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

func (r *router) startUdpServer(cfg *ServerConfig) (*udpServer, error) {
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
	r       *router
	cs      []*wmUdpConn
	logger  *zerolog.Logger
	readOob bool

	closeOnce sync.Once
	closed    atomic.Bool
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
	listenerAddr := c.LocalAddr().(*net.UDPAddr).AddrPort()
	ms := make([]ipv6.Message, 16)
	for i := range ms {
		ms[i].Buffers = [][]byte{make([]byte, 2048)} // TODO: Configurable?
		ms[i].OOB = make([]byte, 512)
	}

	v6c := ipv6.NewPacketConn(c)
	for {
		n, err := v6c.ReadBatch(ms, 0)
		if err != nil {
			if n <= 0 {
				// Err with zero read. Most likely because c was closed.
				if s.closed.Load() {
					return errServerClosed
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
			oob := ms[i].OOB[:ms[i].NN]
			remoteAddr := netAddr2NetipAddr(ms[i].Addr)

			s.handleMsg(b, oob, remoteAddr, listenerAddr)
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
				if s.closed.Load() {
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

		s.handleMsg(b[:n], oob[:oobN], remoteAddr, listenerAddr)
	}
}

func (s *udpServer) handleMsg(b, oob []byte, remoteAddr, listenerAddr netip.AddrPort) {
	var oobLocalAddr netip.Addr // only valid if readOob
	var localAddr netip.AddrPort
	if s.readOob {
		ip, err := udpcmsg.ParseLocalAddr(oob)
		if err != nil {
			s.logger.Error().
				Stringer("remote", remoteAddr).
				Err(err).
				Msg("failed to get remote dst address from socket oob")
			return
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
		return
	}

	if err := s.r.limiterAllowN(remoteAddr.Addr(), costUDPQuery); err != nil {
		resp := mustHaveRespB(m, nil, dnsmsg.RCodeRefused, false, 0)
		s.writeResp(resp, remoteAddr, oobLocalAddr)
		pool.ReleaseBuf(resp)
		// TODO: Log or create a metrics entry for refused queries.
		return
	}

	rc := getRequestContext()
	rc.RemoteAddr = remoteAddr
	rc.LocalAddr = localAddr
	pool.Go(func() {
		defer dnsmsg.ReleaseMsg(m)
		defer releaseRequestContext(rc)
		s.handleReq(m, rc, oobLocalAddr)
	})
}

func (s *udpServer) handleReq(m *dnsmsg.Msg, rc *RequestContext, oobAddr netip.Addr) {
	s.r.handleServerReq(m, rc)

	// Determine the client udp size. Try to find edns0.
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

	b := mustHaveRespB(m, rc.Response.Msg, dnsmsg.RCodeRefused, false, clientUdpSize)
	s.writeResp(b, rc.RemoteAddr, oobAddr)
	pool.ReleaseBuf(b)
}

func (s *udpServer) writeResp(b []byte, remote netip.AddrPort, oobAddr netip.Addr) {
	var oob []byte
	if s.readOob {
		oob = pool.GetBuf(udpcmsg.CmsgSize(oobAddr))
		defer pool.ReleaseBuf(oob)
		oob = udpcmsg.CmsgPktInfo(oob, oobAddr)
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

	for i := 0; i < len(s.cs); i++ {
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
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		for _, c := range s.cs {
			c.c.Close()
		}
	})
	return nil
}
