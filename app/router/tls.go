package router

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/IrineSistiana/mosproxy/internal/testutils"
)

func makeTlsConfig(cfg *TlsConfig, requireCert bool) (*tls.Config, error) {
	if requireCert && (cfg.Cert == "" || cfg.Key == "") && !cfg.DebugUseTempCert {
		return nil, errors.New("missing required cert or key")
	}

	c := new(tls.Config)
	c.InsecureSkipVerify = cfg.InsecureSkipVerify
	if len(cfg.CA) > 0 {
		pool, err := loadCA(cfg.CA)
		if err != nil {
			return nil, fmt.Errorf("failed to load ca, %w", err)
		}
		c.RootCAs = pool
	}

	if cfg.DebugUseTempCert {
		cert, err := testutils.GenerateCertificate("test.test")
		if err != nil {
			return nil, fmt.Errorf("failed to generate cert, %w", err)
		}
		c.Certificates = []tls.Certificate{cert}
	} else if len(cfg.Key) > 0 && len(cfg.Cert) > 0 {
		cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to load cert, %w", err)
		}
		if len(cert.Certificate) > 0 {
			cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate leaf, %w", err)
			}
		}
		c.Certificates = []tls.Certificate{cert}
	}
	return c, nil
}

func loadCA(f string) (*x509.CertPool, error) {
	caCert, err := os.ReadFile(f)
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	ok := caCertPool.AppendCertsFromPEM(caCert)
	if !ok {
		return nil, fmt.Errorf("file seems not contain a valid cert")
	}
	return caCertPool, nil
}
