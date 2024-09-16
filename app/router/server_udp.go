package router

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"time"

	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/IrineSistiana/mosproxy/internal/udpcmsg"
	"github.com/IrineSistiana/mosproxy/pkg/dnsmsg"
	"github.com/rs/zerolog"
	"golang.org/x/net/ipv6"
)

func (r *Router) startUdpServer(cfg *ServerConfig) (*udpServer, error) {
	socketOpts := cfg.Socket

	if cfg.Udp.MultiRoutes && !udpcmsg.Ok() {
		return nil, errors.New("system does not support multi routes")
	}
	readOob := udpcmsg.Ok() && cfg.Udp.MultiRoutes

	lc := net.ListenConfig{
		Control: controlSocket(socketOpts),
	}

	pc, err := lc.ListenPacket(r.ctx, "udp", cfg.Listen)
	if err != nil {
		return nil, err
	}
	c := pc.(*net.UDPConn)
	if readOob {
		_, err := udpcmsg.SetOpt(c)
		if err != nil {
			c.Close()
			return nil, fmt.Errorf("failed to set socket option, %w", err)
		}
	}

	edns0Size := udpSize
	if cfg.Udp.MaxEdns0Size >= 512 {
		edns0Size = cfg.Udp.MaxEdns0Size
	}

	ctx, cancel := context.WithCancelCause(context.Background())
	s := &udpServer{
		cfg:          cfg,
		r:            r,
		logger:       r.subLoggerForServer("server_udp", cfg.Tag),
		readOob:      readOob,
		maxEdns0Size: edns0Size,

		ctx:    ctx,
		cancel: cancel,
		c:      c,
		send:   make(chan udpSendOp, 128),
	}

	go func() {
		s.logger.Info().
			Stringer("addr", s.c.LocalAddr()).
			Msg("udp server started")
		err := s.startServer()
		if !errors.Is(err, errServerClosed) {
			r.fatal("udp server exited", err)
		}
	}()
	return s, nil
}

type udpServer struct {
	cfg          *ServerConfig
	r            *Router
	logger       *zerolog.Logger
	readOob      bool
	maxEdns0Size int

	ctx    context.Context
	cancel context.CancelCauseFunc
	c      *net.UDPConn

	send chan udpSendOp
}

type udpSendOp struct {
	b      pool.Buffer // released by send loop
	remote netip.AddrPort
	oob    netip.Addr
}

func (s *udpServer) startServer() error {
	wg := new(sync.WaitGroup)
	errc := make(chan error, 1)
	sendErr := func(err error) {
		select {
		case errc <- err:
		default:
		}
	}

	switch runtime.GOOS {
	case "linux":
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendErr(s.startReadLoopLinux())
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendErr(s.startWriteLoopLinux())
		}()
	default:
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendErr(s.startReadLoopOthers())
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendErr(s.startWriteLoopOthers())
		}()
	}

	var err error
	select {
	case err = <-errc:

	case <-s.ctx.Done():
		err = context.Cause(s.ctx)
	}
	s.Close()
	wg.Wait()
	return err
}

func (s *udpServer) startReadLoopLinux() error {
	const batchIoSize = 32
	c := s.c

	// read buffer
	ms := make([]ipv6.Message, batchIoSize)
	for i := range ms {
		ms[i].Buffers = [][]byte{make([]byte, 2048)} // TODO: Configurable?
		if s.readOob {
			ms[i].OOB = make([]byte, 128) // Should be enough
		}
	}

	v6c := ipv6.NewPacketConn(c)
	for {
		n, err := v6c.ReadBatch(ms, 0)
		if err != nil {
			if n <= 0 {
				// Err with zero read. Most likely because c was closed.
				if err := context.Cause(s.ctx); err != nil {
					return err
				}
				return err
			}

			// Temporary err.
			s.logger.Error().
				Err(err).
				Msg("temporary read err")
		}

		for i := range ms[:n] {
			b := ms[i].Buffers[0][:ms[i].N]
			var oob []byte
			if s.readOob {
				oob = ms[i].OOB[:ms[i].NN]
			}
			remoteAddr := netAddr2NetipAddr(ms[i].Addr)

			s.handleMsg(b, oob, remoteAddr)
		}
	}
}

func (s *udpServer) startWriteLoopLinux() error {
	const batchIoSize = 32
	const sendInterval = time.Millisecond
	v6c := ipv6.NewPacketConn(s.c)

	// write buffer
	var wms [batchIoSize]ipv6.Message
	for i := range wms {
		wms[i].Buffers = make([][]byte, 1)
		wms[i].Addr = &net.UDPAddr{IP: make([]byte, 16)}
		wms[i].OOB = make([]byte, 0, 64)
	}

	op2Msg := func(op udpSendOp, m *ipv6.Message) {
		m.Buffers[0] = op.b
		addr := m.Addr.(*net.UDPAddr)
		a6 := op.remote.Addr().As16()
		copy(addr.IP, a6[:])
		addr.Port = int(op.remote.Port())

		if s.readOob {
			m.OOB = udpcmsg.CmsgPktInfo(m.OOB, op.oob)
		}
	}

	resetMsg := func(m *ipv6.Message) {
		pool.ReleaseBuf(m.Buffers[0])
		m.Buffers[0] = nil
		addr := m.Addr.(*net.UDPAddr)
		clear(addr.IP)
		addr.Port = 0
		if m.OOB != nil {
			clear(m.OOB)
			m.OOB = m.OOB[:0]
		}
		m.N = 0
		m.NN = 0
	}

	var waitTimeout *time.Timer
	defer func() {
		if waitTimeout != nil {
			waitTimeout.Stop()
		}
	}()
	for {
		select {
		case <-s.ctx.Done():
			return context.Cause(s.ctx)
		case op := <-s.send:
			i := 0
			op2Msg(op, &wms[0])

			// read more
			if waitTimeout == nil {
				waitTimeout = time.NewTimer(sendInterval)
			} else {
				waitTimeout.Reset(sendInterval)
			}
		readMore:
			for {
				select {
				case op := <-s.send:
					i++
					op2Msg(op, &wms[i])
					if i < len(wms)-1 {
						continue
					}
					break readMore
				case <-waitTimeout.C:
					break readMore
				}
			}
			if waitTimeout != nil {
				waitTimeout.Stop()
			}

			// batch write
			_, err := v6c.WriteBatch(wms[:i+1], 0)
			if err != nil {
				s.logger.Error().Err(err).Msg("failed to write batch msg")
			}
			for j := 0; j < i; j++ {
				resetMsg(&wms[j])
			}
		}
	}
}

func (s *udpServer) startReadLoopOthers() error {
	c := s.c
	b := make([]byte, 2048)
	for {
		n, remoteAddr, err := c.ReadFromUDPAddrPort(b)
		if err != nil {
			if n <= 0 {
				if ctxDone(s.ctx) {
					return errServerClosed
				}
				return err
			}
			// Temporary err.
			s.logger.Error().
				Err(err).
				Msg("temporary read err")
			continue
		}
		s.handleMsg(b[:n], nil, remoteAddr)
	}
}

func (s *udpServer) startWriteLoopOthers() error {
	c := s.c
	for {
		select {
		case <-s.ctx.Done():
			return context.Cause(s.ctx)
		case op := <-s.send:
			_, err := c.WriteToUDPAddrPort(op.b, op.remote)
			pool.ReleaseBuf(op.b)
			if err != nil {
				s.logger.Error().
					Stringer("remote", op.remote).
					Err(err).
					Msg("failed to write msg")
			}
		}
	}
}

func (s *udpServer) handleMsg(b, oob []byte, remoteAddr netip.AddrPort) {
	var oobLocalAddr netip.Addr // only valid if readOob
	if s.readOob && len(oob) > 0 {
		ip, err := udpcmsg.ParseLocalAddr(oob)
		if err != nil {
			s.logger.Error().
				Stringer("remote", remoteAddr).
				Err(err).
				Msg("failed to get remote dst address from socket oob")
			return
		}
		oobLocalAddr = ip
	}

	m, err := dnsmsg.UnpackMsg(b)
	if err != nil {
		s.logger.Warn().
			Stringer("remote", remoteAddr).
			Err(err).
			Msg("invalid query msg")
		return
	}

	q := NewQueryCtx()
	if ok := q.parseQuery(m); !ok {
		// Drop invalid query
		ReleaseQueryCtx(q)
		return
	}
	q.ServerTag = s.cfg.Tag
	q.Protocol = ProtoUDP
	q.RemoteAddr = remoteAddr

	udpSize := s.calUdpSize(m)
	pool.Go(func() {
		defer ReleaseQueryCtx(q)
		defer dnsmsg.ReleaseMsg(m)
		s.r.handleQuery(q)
		resp := serverFinalRespB(m, q.Resp, false, udpSize)
		op := udpSendOp{
			b:      resp,
			remote: remoteAddr,
			oob:    oobLocalAddr,
		}
		select {
		case s.send <- op:
		case <-s.ctx.Done():
		}
	})
}

func (s *udpServer) calUdpSize(m *dnsmsg.Msg) int {
	clientUdpSize := 0
	for _, r := range m.Additionals {
		hdr := r.Hdr()
		if hdr.Type == dnsmsg.TypeOPT {
			clientUdpSize = int(hdr.Class)
		}
	}
	if clientUdpSize > s.maxEdns0Size {
		clientUdpSize = s.maxEdns0Size
	}
	if clientUdpSize < 512 {
		clientUdpSize = 512
	}
	return clientUdpSize
}

// Close all sockets.
func (s *udpServer) Close() error {
	s.cancel(errServerClosed)
	s.c.Close()
	return nil
}
