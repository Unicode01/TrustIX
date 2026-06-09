package daemon

import (
	"net/http"
	"testing"

	"trustix.local/trustix/internal/config"
)

func TestHostAPIReusesWildcardPrimaryListener(t *testing.T) {
	daemon := &Daemon{
		cfg: Config{APIAddr: "0.0.0.0:8787"},
		desired: config.Desired{
			LAN: config.LANConfig{Gateway: "10.0.0.1/24"},
			Management: config.ManagementConfig{
				HostAPI: config.HostManagementAPIConfig{Enabled: true},
			},
		},
		apiServers: []apiServerRuntime{
			{Name: apiServerPrimary, Listen: "0.0.0.0:8787", Server: newManagementHTTPServer(http.NewServeMux())},
		},
	}

	if err := daemon.startHostAPIServerLocked(); err != nil {
		t.Fatalf("startHostAPIServerLocked returned error: %v", err)
	}
	if len(daemon.apiServers) != 2 {
		t.Fatalf("api servers = %d, want 2", len(daemon.apiServers))
	}
	hostRuntime := daemon.apiServers[1]
	if hostRuntime.Name != apiServerHost || hostRuntime.Listen != "10.0.0.1:8787" {
		t.Fatalf("host runtime = %#v, want covered host listener", hostRuntime)
	}
	if hostRuntime.Server != nil {
		t.Fatalf("covered host runtime unexpectedly owns a server")
	}
}

func TestAPIServerListenCovers(t *testing.T) {
	tests := []struct {
		existing  string
		requested string
		want      bool
	}{
		{existing: "0.0.0.0:8787", requested: "10.0.0.1:8787", want: true},
		{existing: ":8787", requested: "10.0.0.1:8787", want: true},
		{existing: "[::]:8787", requested: "[fd00::1]:8787", want: true},
		{existing: "127.0.0.1:8787", requested: "127.0.0.1:8787", want: true},
		{existing: "0.0.0.0:8787", requested: "10.0.0.1:8788", want: false},
		{existing: "127.0.0.1:8787", requested: "10.0.0.1:8787", want: false},
		{existing: "[::]:8787", requested: "10.0.0.1:8787", want: false},
		{existing: "example.com:8787", requested: "10.0.0.1:8787", want: false},
	}
	for _, test := range tests {
		t.Run(test.existing+" covers "+test.requested, func(t *testing.T) {
			if got := apiServerListenCovers(test.existing, test.requested); got != test.want {
				t.Fatalf("apiServerListenCovers(%q, %q) = %t, want %t", test.existing, test.requested, got, test.want)
			}
		})
	}
}
