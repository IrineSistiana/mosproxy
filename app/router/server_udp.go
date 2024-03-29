package router

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/IrineSistiana/mosproxy/internal/udpcmsg"
	"github.com/rs/zerolog"
	"golang.org/x/net/ipv6"
)

func (r *Router) startUdpServer(cfg *ServerConfig) (*udpServer, error) {
	socketOpts := cfg.Socket
	threads := cfg.Udp.Threads
	readOob := udpcmsg.Ok() && cfg.Udp.MultiRoutes
	if threads < 1 || !ctlOk { // Disable multi-thread if os does not support socket ctl
		threads = 1
	}
	if threads > 1 {
		socketOpts.SO_REUSEPORT = true
	}
	lc := net.ListenConfig{
		Control: controlSocket(socketOpts),
	}

	s := &udpServer{
		r:       r,
		logger:  r.subLoggerForServer("server_udp", cfg.Tag),
		readOob: readOob,
	}

	for i := 0; i < threads; i++ {
		pc, err := lc.ListenPacket(r.ctx, "udp", cfg.Listen)
		if err != nil {
			s.Close()
			return nil, err
		}
		c := pc.(*net.UDPConn)
		if readOob {
			_, err := udpcmsg.SetOpt(c)
			if err != nil {
				c.Close()
				s.Close()
				return nil, fmt.Errorf("failed to set socket option, %w", err)
			}
			readOob = true
		}
		s.cs = append(s.cs, &wmUdpConn{c: c})
	}

	s.logger.Info().
		Stringer("addr", s.cs[0].c.LocalAddr()).
		Int("threads", threads).
		Msg("udp server started")
	for i := range s.cs {
		i := i
		go func() {
			err := s.startThread(s.cs[i].c)
			if !errors.Is(err, errServerClosed) {
				r.fatal("udp server exited", err)
			}
		}()
	}
	return s, nil
}

type udpServer struct {
	r       *Router
	cs      []*wmUdpConn
	logger  *zerolog.Logger
	readOob bool

	closing atomic.Bool
}

type wmUdpConn struct {
	c  *net.UDPConn
	wm sync.Mutex
}

func (s *udpServer) startThread(c *net.UDPConn) error {
	switch runtime.GOOS {
	case "linux":
		return s.startThreadLinux(c)
	default:
		return s.startThreadOthers(c)
	}
}

func (s *udpServer) startThreadLinux(c *net.UDPConn) error {
	const batchIoSize = 32
	listenerAddr := c.LocalAddr().(*net.UDPAddr).AddrPort()
	ms := make([]ipv6.Message, batchIoSize)
	for i := range ms {
		ms[i].Buffers = [][]byte{make([]byte, 2048)} // TODO: Configurable?
		ms[i].OOB = make([]byte, 512)
	}

	wms := make([]ipv6.Message, batchIoSize)
	for i := range wms {
		wms[i].Buffers = make([][]byte, 1)
		wms[i].Addr = &net.UDPAddr{IP: make([]byte, 16)}
	}

	v6c := ipv6.NewPacketConn(c)
	for {
		n, err := v6c.ReadBatch(ms, 0)
		if err != nil {
			if n <= 0 {
				// Err with zero read. Most likely because c was closed.
				if s.closing.Load() {
					return errServerClosed
				}
				return err
			}

			// Temporary err.
			s.logger.Error().
				Err(err).
				Msg("temporary read err")
		}

		var respN int
		for i := range ms[:n] {
			b := ms[i].Buffers[0][:ms[i].N]
			oob := ms[i].OOB[:ms[i].NN]
			remoteAddr := netAddr2NetipAddr(ms[i].Addr)

			respB, oobAddr := s.handleMsg(b, oob, remoteAddr, listenerAddr)
			if respB != nil {
				ms := &wms[respN]
				ms.Buffers[0] = respB
				ms.N = len(respB)
				if s.readOob {
					oob := pool.GetBuf(udpcmsg.CmsgSize(oobAddr))
					udpcmsg.CmsgPktInfo(oob, oobAddr)
					ms.OOB = oob
					ms.NN = len(oob)
				}
				addr := ms.Addr.(*net.UDPAddr)
				a6 := remoteAddr.Addr().As16()
				copy(addr.IP, a6[:])
				addr.Port = int(remoteAddr.Port())
				respN++
			}
		}

		if respN > 0 {
			_, err := v6c.WriteBatch(wms[:respN], 0)
			if err != nil {
				s.logger.Error().Err(err).Msg("failed to write batch msg")
			}
			for i := 0; i < respN; i++ {
				ms := &wms[i]
				pool.ReleaseBuf(ms.Buffers[0])
				ms.Buffers[0] = nil
				if ms.OOB != nil {
					pool.ReleaseBuf(ms.OOB)
					ms.OOB = nil
				}
				ms.N = 0
				ms.NN = 0
			}
		}
	}
}

func (s *udpServer) startThreadOthers(c *net.UDPConn) error {
	listenerAddr := c.LocalAddr().(*net.UDPAddr).AddrPort()
	b := make([]byte, 2048)
	oob := make([]byte, 512)
	for {
		n, oobN, _, remoteAddr, err := c.ReadMsgUDPAddrPort(b, oob)
		if err != nil {
			if n <= 0 {
				if s.closing.Load() {
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

		resp, oobAddr := s.handleMsg(b[:n], oob[:oobN], remoteAddr, listenerAddr)
		if resp != nil {
			s.writeResp(resp, remoteAddr, oobAddr)
			pool.ReleaseBuf(resp)
		}
	}
}

// return resp, oobAddr (valid when readOob), if have sync resp.
// Otherwise return nil.
func (s *udpServer) handleMsg(b, oob []byte, remoteAddr, listenerAddr netip.AddrPort) (pool.Buffer, netip.Addr) {
	var oobLocalAddr netip.Addr // only valid if readOob
	var localAddr netip.AddrPort
	if s.readOob {
		ip, err := udpcmsg.ParseLocalAddr(oob)
		if err != nil {
			s.logger.Error().
				Stringer("remote", remoteAddr).
				Err(err).
				Msg("failed to get remote dst address from socket oob")
			return nil, netip.Addr{}
		}
		oobLocalAddr = ip
		localAddr = netip.AddrPortFrom(ip, listenerAddr.Port())
	}

	m, err := dnsmsg.UnpackMsg(b)
	if err != nil {
		s.logger.Warn().
			Stringer("remote", remoteAddr).
			Err(err).
			Msg("invalid query msg")
		return nil, netip.Addr{}
	}
	defer dnsmsg.ReleaseMsg(m)

	if err := s.r.limiterAllowN(remoteAddr.Addr(), costUDPQuery); err != nil {
		resp := mustHaveEmptyRespForQueryB(m, dnsmsg.RCodeRefused, false, 0)
		// TODO: Log or create a metrics entry for refused queries.
		return resp, oobLocalAddr
	}

	respMsg := s.r.handleQueryMsg(
		m,
		QueryMeta{RemoteAddr: remoteAddr, LocalAddr: localAddr},
		s.newUdpRespWriter(remoteAddr, oobLocalAddr, s.udpSize(m)),
	)
	if respMsg != nil {
		defer dnsmsg.ReleaseMsg(respMsg)
		resp := mustHaveRespB(respMsg, false, 0)
		return resp, oobLocalAddr
	}
	return nil, netip.Addr{}
}

type udpRespWriter struct {
	s            *udpServer
	udpSize      int
	remoteAddr   netip.AddrPort
	oobLocalAddr netip.Addr
}

func (w *udpRespWriter) WriteResp(m *dnsmsg.Msg) {
	b := mustHaveRespB(m, false, w.udpSize)
	w.s.writeResp(b, w.remoteAddr, w.oobLocalAddr)
	pool.ReleaseBuf(b)
}

func (s *udpServer) newUdpRespWriter(remoteAddr netip.AddrPort, oobLocalAddr netip.Addr, udpSize int) RespWriter {
	return &udpRespWriter{
		s:            s,
		udpSize:      udpSize,
		remoteAddr:   remoteAddr,
		oobLocalAddr: oobLocalAddr,
	}
}

func (s *udpServer) udpSize(m *dnsmsg.Msg) int {
	clientUdpSize := 0
	for _, r := range m.Additionals {
		hdr := r.Hdr()
		if hdr.Type == dnsmsg.TypeOPT {
			clientUdpSize = int(hdr.Class)
		}
	}
	if clientUdpSize < 512 {
		clientUdpSize = 512
	}
	return clientUdpSize
}

func (s *udpServer) writeResp(b []byte, remote netip.AddrPort, oobAddr netip.Addr) {
	var oob []byte
	if s.readOob {
		oob = pool.GetBuf(udpcmsg.CmsgSize(oobAddr))
		defer pool.ReleaseBuf(oob)
		udpcmsg.CmsgPktInfo(oob, oobAddr)
	}
	c := s.pickAndLockWmConn()
	_, _, err := c.c.WriteMsgUDPAddrPort(b, oob, remote)
	c.wm.Unlock()
	if err != nil {
		s.logger.Warn().
			Stringer("remote", remote).
			Err(err).
			Msg("failed to write response")
	}
}

func (s *udpServer) pickAndLockWmConn() *wmUdpConn {
	if len(s.cs) == 1 {
		c := s.cs[0]
		c.wm.Lock()
		return c
	}

	for i := 0; i < min(len(s.cs), 8); i++ {
		rIdx := rand.IntN(len(s.cs))
		if c := s.cs[rIdx]; c.wm.TryLock() {
			return c
		}
	}
	c := s.cs[rand.IntN(len(s.cs))]
	c.wm.Lock()
	return c
}

// Close all sockets.
func (s *udpServer) Close() error {
	s.closing.Store(true)
	for _, c := range s.cs {
		c.c.Close()
	}
	return nil
}
