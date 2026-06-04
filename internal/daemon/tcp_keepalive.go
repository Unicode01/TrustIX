package daemon

import (
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultControlClientTCPKeepAlive = 2 * time.Minute
	defaultServerTCPKeepAlive        = 2 * time.Minute
)

func controlClientTCPKeepAlive() time.Duration {
	return tcpKeepAliveDurationFromEnv("TRUSTIX_CONTROL_CLIENT_TCP_KEEPALIVE", defaultControlClientTCPKeepAlive)
}

func serverTCPKeepAlive() time.Duration {
	return tcpKeepAliveDurationFromEnv("TRUSTIX_SERVER_TCP_KEEPALIVE", defaultServerTCPKeepAlive)
}

func tcpKeepAliveDurationFromEnv(name string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	switch raw {
	case "":
		return fallback
	case "off", "disable", "disabled", "false", "no":
		return -1
	}
	if seconds, err := strconv.ParseFloat(raw, 64); err == nil {
		return time.Duration(seconds * float64(time.Second))
	}
	if keepAlive, err := time.ParseDuration(raw); err == nil {
		return keepAlive
	}
	return fallback
}
