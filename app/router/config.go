package router

import (
	"bytes"
	"fmt"
	"os"

	"github.com/IrineSistiana/mosproxy/internal/mlog"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Servers   []ServerConfig   `yaml:"servers"`
	Upstreams []UpstreamConfig `yaml:"upstreams"`

	DomainSets []DomainSetConfig `yaml:"domain_sets"`
	Rules      []RuleConfig      `yaml:"rules"`

	Addons AddonsConfig `yaml:"addons"`

	Log     LogConfig     `yaml:"log"`
	Cache   CacheConfig   `yaml:"cache"`
	ECS     ECSConfig     `yaml:"ecs"`
	Metrics MetricsConfig `yaml:"metrics"`
}

type ServerConfig struct {
	Tag         string       `yaml:"tag"`
	Protocol    string       `yaml:"protocol"`
	Listen      string       `yaml:"listen"`
	IdleTimeout int          `yaml:"idle_timeout"`
	Udp         UdpConfig    `yaml:"udp"`
	Tcp         TcpConfig    `yaml:"tcp"`
	Tls         TlsConfig    `yaml:"tls"`
	Http        HttpConfig   `yaml:"http"`
	Quic        QuicConfig   `yaml:"quic"`
	Socket      SocketConfig `yaml:"socket"`
}

type UdpConfig struct {
	MultiRoutes bool `yaml:"multi_routes"`
}

type TcpConfig struct {
	MaxConcurrentQueries int32 `yaml:"max_concurrent_queries"`
}

type TlsConfig struct {
	Cert               string `yaml:"cert"`
	Key                string `yaml:"key"`
	CA                 string `yaml:"ca"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	VerifyClientCert   bool   `yaml:"verify_client_cert"`

	DebugUseTempCert bool `yaml:"debug_use_temp_cert,omitempty"`
}

type HttpConfig struct {
	Path             string `yaml:"path"`
	ClientAddrHeader string `yaml:"client_addr_header"`

	DebugMaxStreams uint32 `yaml:"debug_max_streams,omitempty"`
}

type QuicConfig struct {
	MaxStreams int64 `yaml:"max_streams"`
}

// Only support linux.
type SocketConfig struct {
	SO_REUSEPORT    bool   `yaml:"so_reuseport"` // tcp/udp
	SO_RCVBUF       int    `yaml:"so_rcvbuf"`
	SO_SNDBUF       int    `yaml:"so_sndbuf"`
	SO_MARK         int    `yaml:"so_mark"`
	SO_BINDTODEVICE string `yaml:"so_bindtodevice"`

	_TCP_USER_TIMEOUT uint `yaml:"-"` // tcp
}

type UpstreamConfig struct {
	Tag      string       `yaml:"tag"`
	Addr     string       `yaml:"addr"`
	DialAddr string       `yaml:"dial_addr"`
	Tls      TlsConfig    `yaml:"tls"`
	Socket   SocketConfig `yaml:"socket"`
}

type DomainSetConfig struct {
	Tag   string   `yaml:"tag"`
	Files []string `yaml:"files"`
}

type RuleConfig struct {
	Reverse bool   `yaml:"reverse"`
	Domain  string `yaml:"domain"`
	Reject  uint16 `yaml:"reject"`
	Forward string `yaml:"forward"`
}

type AddonsConfig struct{}

type LogConfig struct {
	Queries bool `yaml:"queries"`
}

type CacheConfig struct {
	MemSize    int    `yaml:"mem_size"`
	Redis      string `yaml:"redis"`
	MaximumTTL int    `yaml:"maximum_ttl"`
	IpMarker   string `yaml:"ip_marker"`
}

type ECSConfig struct {
	Enabled bool `yaml:"enabled"`
}

type MetricsConfig struct {
	Addr string `yaml:"addr"`
}

func genConfigTemplate(o string) {
	logger := mlog.L()
	cfg := &Config{
		Servers:    []ServerConfig{{}},
		Upstreams:  []UpstreamConfig{{}},
		DomainSets: []DomainSetConfig{{}},
		Rules:      []RuleConfig{{}},
	}

	b := new(bytes.Buffer)
	encoder := yaml.NewEncoder(b)
	encoder.SetIndent(2)

	err := encoder.Encode(cfg)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to encode config")
	}
	encoder.Close()

	if len(o) == 0 || o == "stdout" {
		fmt.Printf("%s/n", b.Bytes())
	} else {
		err := os.WriteFile(o, b.Bytes(), 0644)
		if err != nil {
			logger.Fatal().Err(err).Msg("failed to write config file")
		}
	}
}
