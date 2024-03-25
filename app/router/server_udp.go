package router

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/IrineSistiana/mosproxy/internal/udpcmsg"
	"github.com/rs/zerolog"
)

func (r *router) startUdpServer(cfg *ServerConfig) (err error) {
	lc := net.ListenConfig{
		Control: controlSocket(cfg.Socket),
	}

	pc, err := lc.ListenPacket(r.ctx, "udp", cfg.Listen)
	if err != nil {
		return err
	}

	c := pc.(*net.UDPConn)
	s := &udpServer{
		r:      r,
		c:      c,
		logger: r.subLoggerForServer("server_udp", cfg.Tag),
	}

	if cfg.Udp.MultiRoutes && udpcmsg.Ok() && c.LocalAddr().(*net.UDPAddr).IP.IsUnspecified() {
		_, err := udpcmsg.SetOpt(c)
		if err != nil {
			pc.Close()
			return fmt.Errorf("failed to set socket option, %w", err)
		}
		s.readOob = true
	}

	s.logger.Info().
		Stringer("addr", c.LocalAddr()).
		Msg("udp server started")
	go func() {
		defer c.Close()
		s.run()
	}()
	return nil
}

type udpServer struct {
	r       *router
	c       *net.UDPConn
	logger  *zerolog.Logger
	readOob bool
}

func (s *udpServer) run() {
	r := s.r
	c := s.c
	listenerAddr := c.LocalAddr().(*net.UDPAddr).AddrPort()

	rb := pool.GetBuf(4096)
	defer pool.ReleaseBuf(rb)

	var oob []byte // nil if s.readOob == false
	if s.readOob {
		oob = pool.GetBuf(512)
		defer pool.ReleaseBuf(oob)
	}

	for {
		localAddr := listenerAddr
		n, oobn, _, remoteAddr, err := c.ReadMsgUDPAddrPort(rb, oob)
		if err != nil {
			if n <= 0 {
				// Err with zero read. Most likely because c was closed.
				r.fatal("udp server exited", err)
				return
			}
			// Temporary err.
			s.logger.Error().
				Stringer("remote", remoteAddr).
				Err(err).
				Msg("temporary read err")
			continue
		}

		var oobLocalAddr netip.Addr // only valid if readOob
		if s.readOob {
			ip, err := udpcmsg.ParseLocalAddr(oob[:oobn])
			if err != nil {
				s.logger.Error().
					Stringer("remote", remoteAddr).
					Err(err).
					Msg("failed to get remote dst address from socket oob")
				continue
			}
			oobLocalAddr = ip
			localAddr = netip.AddrPortFrom(ip, listenerAddr.Port())
		}

		m, err := dnsmsg.UnpackMsg(rb[:n])
		if err != nil {
			s.logger.Warn().
				Stringer("remote", remoteAddr).
				Err(err).
				Msg("invalid query msg")
			continue
		}

		if err := r.limiterAllowN(remoteAddr.Addr(), costUDPQuery); err != nil {
			resp := mustHaveRespB(m, nil, dnsmsg.RCodeRefused, false, 0)
			s.writeResp(resp, remoteAddr, oobLocalAddr)
			pool.ReleaseBuf(resp)
			// TODO: Log or create a metrics entry for refused queries.
			continue
		}

		rc := getRequestContext()
		rc.RemoteAddr = remoteAddr
		rc.LocalAddr = localAddr
		go func() {
			defer dnsmsg.ReleaseMsg(m)
			defer releaseRequestContext(rc)
			s.handleReq(m, rc, oobLocalAddr)
		}()
	}
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
	if _, _, err := s.c.WriteMsgUDPAddrPort(b, oob, remote); err != nil {
		s.logger.Warn().
			Stringer("remote", remote).
			Err(err).
			Msg("failed to write response")
	}
}
