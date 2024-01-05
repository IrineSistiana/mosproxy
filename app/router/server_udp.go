package router

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"

	"github.com/IrineSistiana/mosproxy/internal/dnsmsg"
	"github.com/IrineSistiana/mosproxy/internal/pool"
	"github.com/IrineSistiana/mosproxy/internal/pp"
	"go.uber.org/zap"
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
		ppv2:   cfg.ProtocolProxyV2,
		logger: r.logger.Named("server_udp").With(zap.Stringer("server_addr", pc.LocalAddr())),
	}
	if cfg.Udp.MultiRoutes {
		var err error
		s.oobSize, s.dstReader, s.srcWriter, err = initOobHandler(c)
		if err != nil {
			pc.Close()
			return fmt.Errorf("failed to init oob handler, %w", err)
		}
	}

	s.logger.Info("udp server started")
	go func() {
		defer c.Close()
		s.run()
	}()
	return nil
}

type udpServer struct {
	r      *router
	c      *net.UDPConn
	ppv2   bool
	logger *zap.Logger

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
	rb := rbp.B()

	var oob []byte // maybe nil
	if s.oobSize > 0 {
		oobp := pool.GetBuf(s.oobSize)
		defer pool.ReleaseBuf(oobp)
		oob = oobp.B()
	}

	var pp2Reader *bytes.Reader // nil if pp2 disabled
	if s.ppv2 {
		pp2Reader = new(bytes.Reader)
	}

	for {
		var clientDstAddr netip.AddrPort
		var clientSrcAddr netip.AddrPort

		n, oobn, _, soRemoteAddr, err := c.ReadMsgUDPAddrPort(rb, oob)
		if err != nil {
			if n == 0 {
				// Err with zero read. Most likely because c was closed.
				r.fatal("udp server exited", err)
				return
			}
			// Temporary err.
			s.logger.Check(zap.ErrorLevel, "temporary udp read err").Write(
				zap.String("so_remote", soRemoteAddr.String()),
				zap.Error(err),
			)
			continue
		}
		clientSrcAddr = soRemoteAddr
		payload := rb[:n]

		var (
			sessionOob   []byte     // maybe nil
			oobLocalAddr netip.Addr // maybe invalid
		)
		if oobn > 0 {
			ip, err := s.dstReader(oob[:oobn])
			if err != nil {
				s.logger.Error(
					"failed to get remote dst address from socket oob",
					zap.Stringer("so_remote", soRemoteAddr),
					zap.Error(err),
				)
				continue
			}
			oobLocalAddr, _ = netip.AddrFromSlice(ip)
			sessionOob = s.srcWriter(ip)
			clientDstAddr = netip.AddrPortFrom(oobLocalAddr, listenerAddr.Port())
		}

		// Read pp2 header
		if s.ppv2 {
			pp2Reader.Reset(payload)
			ppHdr, n, err := pp.ReadV2(pp2Reader)
			pp2Reader.Reset(nil)
			if err != nil {
				s.logger.Check(zap.ErrorLevel, "failed to read pp2 header").Write(
					zap.Stringer("so_remote", soRemoteAddr),
					zap.Error(err),
				)
				continue
			}
			payload = payload[n:]
			clientSrcAddr = ppHdr.SourceAddr
			clientDstAddr = ppHdr.DestinationAddr
		}

		m, err := dnsmsg.UnpackMsg(payload)
		if err != nil {
			s.logger.Check(zap.WarnLevel, "invalid udp msg").Write(
				zap.String("local", clientDstAddr.String()),
				zap.String("remote", clientSrcAddr.String()),
				zap.Error(err),
			)
			continue
		}

		rc := getRequestContext()
		rc.RemoteAddr = clientSrcAddr
		rc.LocalAddr = clientDstAddr
		pool.Go(func() {
			defer dnsmsg.ReleaseMsg(m)
			defer releaseRequestContext(rc)
			s.handleReq(soRemoteAddr, sessionOob, m, rc)
		})
	}
}

func (s *udpServer) handleReq(remoteC netip.AddrPort, oob []byte, m *dnsmsg.Msg, rc *RequestContext) {
	s.r.handleServerReq(m, rc)

	// Determine the client udp size. Try to find edns0.
	clientUdpSize := 512
	for iter := m.Additionals.Iter(); iter.Next(); {
		r := iter.Value()
		if r.Type == dnsmsg.TypeOPT {
			if r.Class > dnsmsg.Class(clientUdpSize) {
				clientUdpSize = int(r.Class)
			}
		}
	}

	b, err := packResp(rc.Response.Msg, true, clientUdpSize)
	if err != nil {
		s.logger.Error(logPackRespErr, zap.Error(err))
		return
	}
	if _, _, err := s.c.WriteMsgUDPAddrPort(b.B(), oob, remoteC); err != nil {
		s.logger.Check(zap.WarnLevel, "failed to write udp response").Write(
			zap.Stringer("so_local", s.c.LocalAddr()),
			zap.String("so_remote", remoteC.String()),
			zap.Error(err),
		)
	}
}
