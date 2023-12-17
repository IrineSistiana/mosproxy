package upstream

import (
	"net"
	"strings"
)

func getDialAddr(urlAddr, dialAddr string, defaultPort string) string {
	if len(dialAddr) > 0 {
		if strings.HasPrefix(dialAddr, "@") { // unix
			return dialAddr
		}
		host, port := trySplitHostPort(dialAddr)
		if len(port) == 0 { // add default port
			return net.JoinHostPort(host, defaultPort)
		}
		return dialAddr
	}

	host, port := trySplitHostPort(urlAddr)
	if len(port) == 0 {
		return net.JoinHostPort(host, defaultPort)
	}
	return urlAddr
}

func dialNetworkTcpOrUnix(dialAddr string) string {
	if strings.HasPrefix(dialAddr, "@") {
		return "unix"
	}
	return "tcp"
}

func tryRemovePort(s string) string {
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		return s
	}
	return host
}

// trySplitHostPort splits host and port.
// If s has no port, it returns s,""
func trySplitHostPort(s string) (string, string) {
	host, port, err := net.SplitHostPort(s)
	if err == nil {
		return host, port
	}
	return s, ""
}

func tryTrimIpv6Brackets(s string) string {
	if len(s) < 2 {
		return s
	}
	if s[0] == '[' && s[len(s)-1] == ']' {
		return s[1 : len(s)-2]
	}
	return s
}
