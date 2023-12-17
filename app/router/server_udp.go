package router

import (
	"bytes"
	"context"
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
		logger: r.logger.Named("server_udp").With(zap.Stringer("addr", pc.LocalAddr())),
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
	connCtx, cancel := context.WithCancelCause(r.ctx)
	defer cancel(errListenerClosed)

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
		n, oobn, _, remoteAddrC, err := c.ReadMsgUDPAddrPort(rb, oob)
		if err != nil {
			if n == 0 {
				// Err with zero read. Most likely because c was closed.
				r.fatal("udp server exited", err)
				return
			}
			// Temporary err.
			s.logger.Warn(
				"udp read err",
				zap.Stringer("local", listenerAddr),
				zap.Stringer("remote", remoteAddrC),
				zap.Error(err),
			)
			continue
		}

		// Read pp2 header
		var ppHdr pp.HeaderV2 // maybe zero
		var ppHdrL int
		if s.ppv2 {
			pp2Reader.Reset(rb[:n])
			ppHdr, ppHdrL, err = pp.ReadV2(pp2Reader)
			pp2Reader.Reset(nil)
			if err != nil {
				s.logger.Error(
					"failed to read pp2 header",
					zap.Stringer("local", listenerAddr),
					zap.Stringer("remote", remoteAddrC),
					zap.Error(err),
				)
			}
		}

		var (
			sessionOob   []byte     // maybe nil
			oobLocalAddr netip.Addr // maybe invalid
		)
		if oobn > 0 {
			ip, err := s.dstReader(oob[:oobn])
			if err != nil {
				s.logger.Error(
					"failed to get remote dst address from socket oob",
					zap.Stringer("local", listenerAddr),
					zap.Stringer("remote", remoteAddrC),
					zap.Error(err),
				)
				continue
			}
			oobLocalAddr, _ = netip.AddrFromSlice(ip)
			sessionOob = s.srcWriter(ip)
		}

		// Always valid
		var localAddr netip.AddrPort
		var remoteAddr netip.AddrPort
		if ppHdr.DestinationAddr.IsValid() {
			localAddr = ppHdr.DestinationAddr
		} else if oobLocalAddr.IsValid() {
			localAddr = netip.AddrPortFrom(oobLocalAddr, listenerAddr.Port())
		} else {
			localAddr = listenerAddr
		}
		if ppHdr.SourceAddr.IsValid() {
			remoteAddr = ppHdr.SourceAddr
		} else {
			remoteAddr = remoteAddrC
		}

		m, err := dnsmsg.UnpackMsg(rb[ppHdrL:n])
		if err != nil {
			if r.opt.logInvalid {
				s.logger.Check(zap.WarnLevel, "invalid udp msg").Write(
					zap.String("local", localAddr.String()),
					zap.String("remote", remoteAddr.String()),
					zap.Error(err),
				)
			}
			continue
		}

		pool.Go(func() {
			defer dnsmsg.ReleaseMsg(m)
			s.handleReq(remoteAddrC, sessionOob, connCtx, m, remoteAddr, localAddr)
		})
	}
}

func (s *udpServer) handleReq(remoteC netip.AddrPort, oob []byte, ctx context.Context, m *dnsmsg.Msg, remoteAddr, localAddr netip.AddrPort) {
	r := s.r
	c := s.c
	resp := r.handleServerReq(ctx, m, remoteAddr, localAddr)
	defer dnsmsg.ReleaseMsg(resp)

	// Determine the client udp size. Try to find edns0.
	clientUdpSize := 512
	for n := m.Additionals.Head(); n != nil; n = n.Next() {
		r := n.Value()
		if r.Type == dnsmsg.TypeOPT {
			if r.Class > dnsmsg.Class(clientUdpSize) {
				clientUdpSize = int(r.Class)
			}
		}
	}
	buf := pool.GetBuf(clientUdpSize)
	defer pool.ReleaseBuf(buf)
	bs := buf.B()
	n, err := resp.Pack(bs, true, clientUdpSize)
	if err != nil {
		s.logger.Error(logPackRespErr, zap.Error(err))
		return
	}
	if _, _, err := c.WriteMsgUDPAddrPort(bs[:n], oob, remoteC); err != nil {
		s.logger.Check(zap.WarnLevel, "failed to write udp response").Write(
			zap.Stringer("local", c.LocalAddr()),
			zap.Stringer("remote", c.RemoteAddr()),
			zap.Error(err),
		)
	}
}
