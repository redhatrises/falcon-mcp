package config

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/crowdstrike/falcon-mcp/internal/version"
)

// Valid-format credentials for tests: Load enforces a 32-char alphanumeric
// client id and a 40-char alphanumeric client secret.
const (
	validID     = "abcdef0123456789abcdef0123456789"
	validSecret = "abcdef0123456789abcdef0123456789abcdef01"
)

func TestLoad(t *testing.T) {
	t.Parallel()
	valid := Config{ClientID: validID, ClientSecret: validSecret}
	tests := []struct {
		name      string
		in        Config
		wantErr   error  // sentinel to errors.Is against; nil means "no error"
		errSubstr string // substring the error message must contain (when wantErr is nil but an error is expected)
		check     func(t *testing.T, c *Config)
	}{
		{
			name:    "missing client id",
			in:      Config{ClientSecret: "secret"},
			wantErr: ErrMissingCredentials,
		},
		{
			name:    "missing client secret",
			in:      Config{ClientID: "id"},
			wantErr: ErrMissingCredentials,
		},
		{
			name:    "malformed client id rejected",
			in:      Config{ClientID: "too-short", ClientSecret: validSecret},
			wantErr: ErrInvalidClientID,
		},
		{
			name:    "malformed client secret rejected",
			in:      Config{ClientID: validID, ClientSecret: "too-short"},
			wantErr: ErrInvalidClientSecret,
		},
		{
			name: "defaults applied",
			in:   valid,
			check: func(t *testing.T, c *Config) {
				if c.Transport != "stdio" {
					t.Errorf("transport = %q, want stdio", c.Transport)
				}
				if c.DetailFetchConcurrency != defaultDetailFetchConcurrency {
					t.Errorf("detailFetchConcurrency = %d, want %d", c.DetailFetchConcurrency, defaultDetailFetchConcurrency)
				}
			},
		},
		{
			name: "non-zero http tuning passes through",
			in: Config{ClientID: validID, ClientSecret: validSecret,
				ResponseHeaderTimeout: 45 * time.Second, IdleTimeout: 90 * time.Second, MaxIdleConnsPerHost: 256},
			check: func(t *testing.T, c *Config) {
				if c.ResponseHeaderTimeout != 45*time.Second {
					t.Errorf("responseHeaderTimeout = %v, want 45s", c.ResponseHeaderTimeout)
				}
				if c.IdleTimeout != 90*time.Second {
					t.Errorf("idleTimeout = %v, want 90s", c.IdleTimeout)
				}
				if c.MaxIdleConnsPerHost != 256 {
					t.Errorf("maxIdleConnsPerHost = %d, want 256", c.MaxIdleConnsPerHost)
				}
			},
		},
		{
			name:    "negative response-header timeout rejected",
			in:      Config{ClientID: validID, ClientSecret: validSecret, ResponseHeaderTimeout: -1},
			wantErr: ErrInvalidHTTPTuning,
		},
		{
			name:    "negative idle timeout rejected",
			in:      Config{ClientID: validID, ClientSecret: validSecret, IdleTimeout: -1},
			wantErr: ErrInvalidHTTPTuning,
		},
		{
			name:    "negative max idle conns per host rejected",
			in:      Config{ClientID: validID, ClientSecret: validSecret, MaxIdleConnsPerHost: -1},
			wantErr: ErrInvalidHTTPTuning,
		},
		{
			name: "non-zero detail fetch concurrency passes through",
			in:   Config{ClientID: validID, ClientSecret: validSecret, DetailFetchConcurrency: 16},
			check: func(t *testing.T, c *Config) {
				if c.DetailFetchConcurrency != 16 {
					t.Errorf("detailFetchConcurrency = %d, want 16", c.DetailFetchConcurrency)
				}
			},
		},
		{
			name: "valid cloud us-1 accepted",
			in:   Config{ClientID: validID, ClientSecret: validSecret, Cloud: "us-1"},
			check: func(t *testing.T, c *Config) {
				if c.Cloud != "us-1" {
					t.Errorf("cloud = %q, want us-1", c.Cloud)
				}
			},
		},
		{
			name: "valid cloud eu-1 accepted",
			in:   Config{ClientID: validID, ClientSecret: validSecret, Cloud: "eu-1"},
		},
		{
			name: "valid cloud us-gov-1 accepted",
			in:   Config{ClientID: validID, ClientSecret: validSecret, Cloud: "us-gov-1"},
		},
		{
			name: "member cid bare 32-hex accepted",
			in:   Config{ClientID: validID, ClientSecret: validSecret, MemberCID: "abcdef0123456789abcdef0123456789"},
			check: func(t *testing.T, c *Config) {
				if c.MemberCID != "abcdef0123456789abcdef0123456789" {
					t.Errorf("memberCID = %q, want bare 32-hex", c.MemberCID)
				}
			},
		},
		{
			name: "member cid with checksum suffix stripped to 32-hex",
			in:   Config{ClientID: validID, ClientSecret: validSecret, MemberCID: "abcdef0123456789abcdef0123456789-9a"},
			check: func(t *testing.T, c *Config) {
				if c.MemberCID != "abcdef0123456789abcdef0123456789" {
					t.Errorf("memberCID = %q, want -XX suffix stripped to bare 32-hex", c.MemberCID)
				}
			},
		},
		{
			name: "member cid surrounding whitespace trimmed",
			in:   Config{ClientID: validID, ClientSecret: validSecret, MemberCID: "  abcdef0123456789abcdef0123456789  "},
			check: func(t *testing.T, c *Config) {
				if c.MemberCID != "abcdef0123456789abcdef0123456789" {
					t.Errorf("memberCID = %q, want trimmed bare 32-hex", c.MemberCID)
				}
			},
		},
		{
			name:    "invalid transport",
			in:      Config{ClientID: validID, ClientSecret: validSecret, Transport: "grpc"},
			wantErr: ErrInvalidTransport,
		},
		{
			name:      "http transport requires addr",
			in:        Config{ClientID: validID, ClientSecret: validSecret, Transport: "streamable-http"},
			errSubstr: "host and port",
		},
		{
			name: "sse transport with loopback addr (no api-key ok)",
			in:   Config{ClientID: validID, ClientSecret: validSecret, Transport: "sse", HTTPAddr: "127.0.0.1:8080"},
			check: func(t *testing.T, c *Config) {
				if c.Transport != "sse" {
					t.Errorf("transport = %q, want sse", c.Transport)
				}
				if c.HTTPAddr != "127.0.0.1:8080" {
					t.Errorf("http addr = %q, want 127.0.0.1:8080", c.HTTPAddr)
				}
			},
		},
		{
			name:      "invalid cloud",
			in:        Config{ClientID: validID, ClientSecret: validSecret, Cloud: "mars"},
			errSubstr: "cloud",
		},
		{
			name:      "invalid member cid",
			in:        Config{ClientID: validID, ClientSecret: validSecret, MemberCID: "xyz"},
			errSubstr: "member",
		},
		{
			name:    "hosted is rejected until implemented",
			in:      Config{ClientID: validID, ClientSecret: validSecret, Hosted: true},
			wantErr: ErrHostedNotImplemented,
		},
		{
			name: "dynamic passes through",
			in:   Config{ClientID: validID, ClientSecret: validSecret, Dynamic: true},
			check: func(t *testing.T, c *Config) {
				if !c.Dynamic {
					t.Errorf("dynamic = false, want true")
				}
			},
		},
		{
			name: "stateless-http with http transport",
			in:   Config{ClientID: validID, ClientSecret: validSecret, Transport: "streamable-http", HTTPAddr: "127.0.0.1:8080", StatelessHTTP: true},
			check: func(t *testing.T, c *Config) {
				if !c.StatelessHTTP {
					t.Errorf("statelessHTTP = false, want true")
				}
			},
		},
		{
			name:    "stateless-http rejected with stdio transport",
			in:      Config{ClientID: validID, ClientSecret: validSecret, StatelessHTTP: true},
			wantErr: ErrStatelessRequiresHTTP,
		},
		{
			name:    "stateless-http rejected with sse transport",
			in:      Config{ClientID: validID, ClientSecret: validSecret, Transport: "sse", HTTPAddr: "127.0.0.1:8080", StatelessHTTP: true},
			wantErr: ErrStatelessRequiresHTTP,
		},
		{
			name:    "api-key rejected with stdio transport",
			in:      Config{ClientID: validID, ClientSecret: validSecret, APIKey: "secret"},
			wantErr: ErrAPIKeyRequiresHTTP,
		},
		{
			name: "api-key accepted with http transport",
			in:   Config{ClientID: validID, ClientSecret: validSecret, Transport: "streamable-http", HTTPAddr: ":8080", APIKey: "secret"},
			check: func(t *testing.T, c *Config) {
				if c.APIKey != "secret" {
					t.Errorf("apiKey = %q, want secret", c.APIKey)
				}
			},
		},
		{
			name: "api-key accepted with sse transport",
			in:   Config{ClientID: validID, ClientSecret: validSecret, Transport: "sse", HTTPAddr: ":8080", APIKey: "secret"},
			check: func(t *testing.T, c *Config) {
				if c.APIKey != "secret" {
					t.Errorf("apiKey = %q, want secret", c.APIKey)
				}
			},
		},
		{
			name: "empty api-key allowed with stdio transport",
			in:   valid,
			check: func(t *testing.T, c *Config) {
				if c.APIKey != "" {
					t.Errorf("apiKey = %q, want empty", c.APIKey)
				}
			},
		},
		{
			name: "empty api-key allowed on loopback http",
			in:   Config{ClientID: validID, ClientSecret: validSecret, Transport: "streamable-http", HTTPAddr: "127.0.0.1:8000"},
			check: func(t *testing.T, c *Config) {
				if c.APIKey != "" {
					t.Errorf("apiKey = %q, want empty", c.APIKey)
				}
			},
		},
		{
			name: "empty api-key allowed on localhost",
			in:   Config{ClientID: validID, ClientSecret: validSecret, Transport: "sse", HTTPAddr: "localhost:8000"},
			check: func(t *testing.T, c *Config) {
				if c.HTTPAddr != "localhost:8000" {
					t.Errorf("http addr = %q, want localhost:8000", c.HTTPAddr)
				}
			},
		},
		{
			name:    "empty api-key rejected on non-loopback http",
			in:      Config{ClientID: validID, ClientSecret: validSecret, Transport: "streamable-http", HTTPAddr: "0.0.0.0:8000"},
			wantErr: ErrUnauthenticatedNonLoopback,
		},
		{
			name:    "empty api-key rejected on empty-host bind-all",
			in:      Config{ClientID: validID, ClientSecret: validSecret, Transport: "sse", HTTPAddr: ":8000"},
			wantErr: ErrUnauthenticatedNonLoopback,
		},
		{
			name:    "empty api-key rejected on routable ip",
			in:      Config{ClientID: validID, ClientSecret: validSecret, Transport: "streamable-http", HTTPAddr: "192.168.1.5:8000"},
			wantErr: ErrUnauthenticatedNonLoopback,
		},
		{
			name: "non-loopback with api-key ok",
			in:   Config{ClientID: validID, ClientSecret: validSecret, Transport: "streamable-http", HTTPAddr: "0.0.0.0:8000", APIKey: "secret"},
			check: func(t *testing.T, c *Config) {
				if c.APIKey != "secret" {
					t.Errorf("apiKey = %q, want secret", c.APIKey)
				}
				if c.HTTPAddr != "0.0.0.0:8000" {
					t.Errorf("http addr = %q, want 0.0.0.0:8000", c.HTTPAddr)
				}
			},
		},
		{
			name: "non-loopback without api-key ok with allow-insecure-http",
			in:   Config{ClientID: validID, ClientSecret: validSecret, Transport: "streamable-http", HTTPAddr: "0.0.0.0:8000", AllowInsecureHTTP: true},
			check: func(t *testing.T, c *Config) {
				if !c.AllowInsecureHTTP {
					t.Errorf("allowInsecureHTTP = false, want true")
				}
				if c.APIKey != "" {
					t.Errorf("apiKey = %q, want empty", c.APIKey)
				}
			},
		},
		{
			name: "modules normalized: trimmed and empties dropped",
			in:   Config{ClientID: validID, ClientSecret: validSecret, Modules: []string{" hosts ", "", "  ", "detections"}},
			check: func(t *testing.T, c *Config) {
				want := []string{"hosts", "detections"}
				if len(c.Modules) != len(want) {
					t.Fatalf("modules = %v, want %v", c.Modules, want)
				}
				for i, m := range want {
					if c.Modules[i] != m {
						t.Errorf("modules[%d] = %q, want %q", i, c.Modules[i], m)
					}
				}
			},
		},
		{
			name: "modules all empty normalized to nil",
			in:   Config{ClientID: validID, ClientSecret: validSecret, Modules: []string{"", "   "}},
			check: func(t *testing.T, c *Config) {
				if c.Modules != nil {
					t.Errorf("modules = %v, want nil", c.Modules)
				}
			},
		},
		{
			name: "user agent absent gets versioned prefix only",
			in:   valid,
			check: func(t *testing.T, c *Config) {
				want := "falcon-mcp/" + version.Version
				if c.UserAgent != want {
					t.Errorf("userAgent = %q, want %q", c.UserAgent, want)
				}
			},
		},
		{
			name: "user agent appended after versioned prefix and trimmed",
			in:   Config{ClientID: validID, ClientSecret: validSecret, UserAgent: "  my-tool/1.2  "},
			check: func(t *testing.T, c *Config) {
				want := "falcon-mcp/" + version.Version + " my-tool/1.2"
				if c.UserAgent != want {
					t.Errorf("userAgent = %q, want %q", c.UserAgent, want)
				}
			},
		},
		{
			name: "host override bare fqdn passes through",
			in:   Config{ClientID: validID, ClientSecret: validSecret, HostOverride: "api.us-2.crowdstrike.com"},
			check: func(t *testing.T, c *Config) {
				if c.HostOverride != "api.us-2.crowdstrike.com" {
					t.Errorf("hostOverride = %q, want bare fqdn", c.HostOverride)
				}
			},
		},
		{
			name: "host override strips scheme and path",
			in:   Config{ClientID: validID, ClientSecret: validSecret, HostOverride: "https://api.us-2.crowdstrike.com/some/path"},
			check: func(t *testing.T, c *Config) {
				if c.HostOverride != "api.us-2.crowdstrike.com" {
					t.Errorf("hostOverride = %q, want api.us-2.crowdstrike.com", c.HostOverride)
				}
			},
		},
		{
			name: "host override strips trailing slash",
			in:   Config{ClientID: validID, ClientSecret: validSecret, HostOverride: "  https://api.us-2.crowdstrike.com/  "},
			check: func(t *testing.T, c *Config) {
				if c.HostOverride != "api.us-2.crowdstrike.com" {
					t.Errorf("hostOverride = %q, want api.us-2.crowdstrike.com", c.HostOverride)
				}
			},
		},
		{
			name: "host override empty stays empty",
			in:   valid,
			check: func(t *testing.T, c *Config) {
				if c.HostOverride != "" {
					t.Errorf("hostOverride = %q, want empty", c.HostOverride)
				}
			},
		},
		{
			name: "proxy empty stays empty",
			in:   valid,
			check: func(t *testing.T, c *Config) {
				if c.Proxy != "" {
					t.Errorf("proxy = %q, want empty", c.Proxy)
				}
			},
		},
		{
			name: "proxy http accepted and trimmed",
			in:   Config{ClientID: validID, ClientSecret: validSecret, Proxy: "  http://proxy.example.com:8080  "},
			check: func(t *testing.T, c *Config) {
				if c.Proxy != "http://proxy.example.com:8080" {
					t.Errorf("proxy = %q, want trimmed http url", c.Proxy)
				}
			},
		},
		{
			name: "proxy https accepted",
			in:   Config{ClientID: validID, ClientSecret: validSecret, Proxy: "https://proxy.example.com:8443"},
			check: func(t *testing.T, c *Config) {
				if c.Proxy != "https://proxy.example.com:8443" {
					t.Errorf("proxy = %q, want https url", c.Proxy)
				}
			},
		},
		{
			name: "proxy socks5 accepted",
			in:   Config{ClientID: validID, ClientSecret: validSecret, Proxy: "socks5://proxy.example.com:1080"},
			check: func(t *testing.T, c *Config) {
				if c.Proxy != "socks5://proxy.example.com:1080" {
					t.Errorf("proxy = %q, want socks5 url", c.Proxy)
				}
			},
		},
		{
			name: "proxy with userinfo accepted",
			in:   Config{ClientID: validID, ClientSecret: validSecret, Proxy: "http://user:pass@proxy.example.com:8080"}, //nolint:gosec // G101: dummy proxy userinfo, not a real credential
			check: func(t *testing.T, c *Config) {
				if c.Proxy != "http://user:pass@proxy.example.com:8080" { //nolint:gosec // G101: dummy proxy userinfo, not a real credential
					t.Errorf("proxy = %q, want url with userinfo", c.Proxy)
				}
			},
		},
		{
			name:    "proxy missing scheme rejected",
			in:      Config{ClientID: validID, ClientSecret: validSecret, Proxy: "proxy.example.com:8080"},
			wantErr: ErrInvalidProxy,
		},
		{
			name:    "proxy unsupported scheme rejected",
			in:      Config{ClientID: validID, ClientSecret: validSecret, Proxy: "ftp://proxy.example.com:8080"},
			wantErr: ErrInvalidProxy,
		},
		{
			name:    "proxy missing host rejected",
			in:      Config{ClientID: validID, ClientSecret: validSecret, Proxy: "http://"},
			wantErr: ErrInvalidProxy,
		},
		{
			name:    "proxy unparseable rejected",
			in:      Config{ClientID: validID, ClientSecret: validSecret, Proxy: "http://[::1"},
			wantErr: ErrInvalidProxy,
		},
		{
			name: "ops addrs empty stay disabled",
			in:   valid,
			check: func(t *testing.T, c *Config) {
				if c.HealthAddr != "" || c.MetricsAddr != "" || c.PprofAddr != "" {
					t.Errorf("ops addrs = %q/%q/%q, want all empty (disabled)", c.HealthAddr, c.MetricsAddr, c.PprofAddr)
				}
			},
		},
		{
			name: "valid ops addrs pass through",
			in:   Config{ClientID: validID, ClientSecret: validSecret, HealthAddr: "127.0.0.1:6061", MetricsAddr: ":6062", PprofAddr: "localhost:6063"},
			check: func(t *testing.T, c *Config) {
				if c.HealthAddr != "127.0.0.1:6061" {
					t.Errorf("healthAddr = %q, want 127.0.0.1:6061", c.HealthAddr)
				}
				if c.MetricsAddr != ":6062" {
					t.Errorf("metricsAddr = %q, want :6062", c.MetricsAddr)
				}
				if c.PprofAddr != "localhost:6063" {
					t.Errorf("pprofAddr = %q, want localhost:6063", c.PprofAddr)
				}
			},
		},
		{
			name:    "malformed health addr rejected",
			in:      Config{ClientID: validID, ClientSecret: validSecret, HealthAddr: "bad:addr:99"},
			wantErr: ErrInvalidDebugAddr,
		},
		{
			name:    "malformed metrics addr rejected",
			in:      Config{ClientID: validID, ClientSecret: validSecret, MetricsAddr: "bad:addr:99"},
			wantErr: ErrInvalidDebugAddr,
		},
		{
			name:    "malformed pprof addr rejected",
			in:      Config{ClientID: validID, ClientSecret: validSecret, PprofAddr: "bad:addr:99"},
			wantErr: ErrInvalidDebugAddr,
		},
		{
			name:      "malformed ops addr names the flag",
			in:        Config{ClientID: validID, ClientSecret: validSecret, PprofAddr: "bad:addr:99"},
			errSubstr: "pprof-addr",
		},
		{
			name:    "out-of-range ops port rejected",
			in:      Config{ClientID: validID, ClientSecret: validSecret, HealthAddr: "127.0.0.1:99999999"},
			wantErr: ErrInvalidDebugAddr,
		},
		{
			name:    "non-numeric ops port rejected",
			in:      Config{ClientID: validID, ClientSecret: validSecret, MetricsAddr: "localhost:http"},
			wantErr: ErrInvalidDebugAddr,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, err := Load(tt.in)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if tt.errSubstr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.errSubstr)
				}
				if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("err = %v, want substring %q", err, tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if tt.check != nil {
				tt.check(t, c)
			}
		})
	}
}

func TestLoadHostedRejected(t *testing.T) {
	_, err := Load(Config{ClientID: validID, ClientSecret: validSecret, Hosted: true})
	if !errors.Is(err, ErrHostedNotImplemented) {
		t.Fatalf("err = %v, want ErrHostedNotImplemented", err)
	}
}
