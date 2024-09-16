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
	c := new(tls.Config)

	// load cert(s)
	if cfg.DebugUseTempCert {
		cert, err := testutils.GenerateCertificate("test.test")
		if err != nil {
			return nil, fmt.Errorf("failed to generate cert, %w", err)
		}
		c.Certificates = []tls.Certificate{cert}
	} else if len(cfg.Certs) > 0 || len(cfg.Keys) > 0 {
		if len(cfg.Certs) != len(cfg.Keys) {
			return nil, fmt.Errorf("mismatched certificates and keys, got %d cert(s) and %d key(s)", len(cfg.Certs), len(cfg.Keys))
		}

		for i := 0; i < len(cfg.Certs); i++ {
			certFile, keyFile := cfg.Certs[i], cfg.Keys[i]
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return nil, fmt.Errorf("failed to load cert from %s and key %s, %w", certFile, keyFile, err)
			}
			if len(cert.Certificate) > 0 && cert.Leaf == nil { // for go <= 1.22
				cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
				if err != nil {
					return nil, fmt.Errorf("failed to parse certificate leaf, %w", err)
				}
			}
			c.Certificates = append(c.Certificates, cert)
		}
	}

	if requireCert && len(c.Certificates) == 0 {
		return nil, errors.New("empty cert/key pair, tls config needs a valid certificate")
	}

	if len(cfg.CA) > 0 {
		pool, err := loadCA(cfg.CA)
		if err != nil {
			return nil, fmt.Errorf("failed to load ca %s, %w", cfg.CA, err)
		}
		c.RootCAs = pool
	}

	c.InsecureSkipVerify = cfg.InsecureSkipVerify
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
