package router

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/pool"
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

	if cfg.Udp.MultiRoutes && c.LocalAddr().(*net.UDPAddr).IP.IsUnspecified() {
		var err error
		s.oobSize, s.dstReader, s.srcWriter, err = initOobHandler(c)
		if err != nil {
			pc.Close()
			return fmt.Errorf("failed to init oob handler, %w", err)
		}
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
	r      *router
	c      *net.UDPConn
	logger *zerolog.Logger

	oobSize   int
	dstReader func(oob []byte) (net.IP, error)
	srcWriter func(ip net.IP) []byte
}

func (s *udpServer) run() {
	r := s.r
	c := s.c
	listenerAddr := c.LocalAddr().(*net.UDPAddr).AddrPort()

	rbp := pool.GetBuf(65535)
	defer pool.ReleaseBuf(rbp)
	rb := rbp

	var oob []byte // maybe nil
	if s.oobSize > 0 {
		oobp := pool.GetBuf(s.oobSize)
		defer pool.ReleaseBuf(oobp)
		oob = oobp
	}

	for {
		n, oobn, _, remoteAddr, err := c.ReadMsgUDPAddrPort(rb, oob)
		if err != nil {
			if n == 0 {
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
		payload := rb[:n]

		var (
			sessionOob   []byte     // maybe nil
			oobLocalAddr netip.Addr // maybe invalid
		)
		localAddr := listenerAddr
		if oobn > 0 {
			ip, err := s.dstReader(oob[:oobn])
			if err != nil {
				s.logger.Error().
					Stringer("remote", remoteAddr).
					Err(err).
					Msg("failed to get remote dst address from socket oob")
				continue
			}
			oobLocalAddr, _ = netip.AddrFromSlice(ip)
			sessionOob = s.srcWriter(ip)
			localAddr = netip.AddrPortFrom(oobLocalAddr, listenerAddr.Port())
		}

		m, err := dnsmsg.UnpackMsg(payload)
		if err != nil {
			s.logger.Error().
				Stringer("remote", remoteAddr).
				Err(err).
				Msg("invalid query msg")
			continue
		}

		rc := getRequestContext()
		rc.RemoteAddr = remoteAddr
		rc.LocalAddr = localAddr
		go func() {
			defer dnsmsg.ReleaseMsg(m)
			defer releaseRequestContext(rc)
			s.handleReq(remoteAddr, sessionOob, m, rc)
		}()
	}
}

func (s *udpServer) handleReq(remoteAddr netip.AddrPort, oob []byte, m *dnsmsg.Msg, rc *RequestContext) {
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

	b, err := packResp(rc.Response.Msg, true, clientUdpSize)
	if err != nil {
		s.logger.Error().
			Err(err).
			Msg(logPackRespErr)
		return
	}
	if _, _, err := s.c.WriteMsgUDPAddrPort(b, oob, remoteAddr); err != nil {
		s.logger.Warn().
			Stringer("remote", remoteAddr).
			Err(err).
			Msg("failed to write response")
	}
}
