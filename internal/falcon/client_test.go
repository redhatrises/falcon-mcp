package falconapi

import (
	"context"
	"net/http"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/crowdstrike/falcon-mcp/internal/config"
)

// Test tuning values passed to apiHTTPClient. They are distinct from the
// package defaults so the assertions prove the arguments are threaded onto the
// transport rather than a default coincidentally matching.
const (
	testRespHeaderTimeout   = 45 * time.Second
	testMaxIdleConnsPerHost = 64
)

func TestProxyHTTPClient(t *testing.T) {
	t.Parallel()
	const proxy = "http://proxy.example.com:8080"

	c, err := apiHTTPClient(proxy, testRespHeaderTimeout, testMaxIdleConnsPerHost)
	if err != nil {
		t.Fatalf("apiHTTPClient: %v", err)
	}

	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", c.Transport)
	}
	if tr.Proxy == nil {
		t.Fatal("transport Proxy is nil, want a proxy func")
	}

	// The Proxy func should resolve any outbound request to the configured proxy.
	req, err := http.NewRequest(http.MethodGet, "https://api.crowdstrike.com/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tr.Proxy(req)
	if err != nil {
		t.Fatalf("proxy func: %v", err)
	}
	if got == nil || got.String() != proxy {
		t.Errorf("resolved proxy = %v, want %s", got, proxy)
	}
}

func TestProxyHTTPClientClonesDefaults(t *testing.T) {
	t.Parallel()
	c, err := apiHTTPClient("http://proxy.example.com:8080", testRespHeaderTimeout, testMaxIdleConnsPerHost)
	if err != nil {
		t.Fatalf("apiHTTPClient: %v", err)
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport = %T, want *http.Transport", c.Transport)
	}
	// A clone of http.DefaultTransport keeps its connection-pool defaults rather
	// than a zero-value transport.
	if tr.MaxIdleConns == 0 {
		t.Error("MaxIdleConns = 0, want DefaultTransport's non-zero default (clone lost defaults)")
	}
	if def, ok := http.DefaultTransport.(*http.Transport); ok && tr == def {
		t.Error("transport is the shared DefaultTransport, want an independent clone")
	}
}

// TestAPIHTTPClientSetsTransportTuning verifies both the proxy and non-proxy
// paths apply the supplied response-header timeout and per-host idle-connection
// cap to the transport, so a stalled endpoint cannot pin a pooled connection
// and concurrent callers are not throttled to the stdlib default of 2.
func TestAPIHTTPClientSetsTransportTuning(t *testing.T) {
	t.Parallel()
	for _, proxy := range []string{"", "http://proxy.example.com:8080"} {
		c, err := apiHTTPClient(proxy, testRespHeaderTimeout, testMaxIdleConnsPerHost)
		if err != nil {
			t.Fatalf("apiHTTPClient(%q): %v", proxy, err)
		}
		tr, ok := c.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("Transport = %T, want *http.Transport", c.Transport)
		}
		if tr.ResponseHeaderTimeout != testRespHeaderTimeout {
			t.Errorf("proxy=%q: ResponseHeaderTimeout = %v, want %v", proxy, tr.ResponseHeaderTimeout, testRespHeaderTimeout)
		}
		if tr.MaxIdleConnsPerHost != testMaxIdleConnsPerHost {
			t.Errorf("proxy=%q: MaxIdleConnsPerHost = %d, want %d (default of 2 throttles the single Falcon host)", proxy, tr.MaxIdleConnsPerHost, testMaxIdleConnsPerHost)
		}
	}
}

// TestAPIHTTPClientNoProxyKeepsEnvProxy verifies the non-proxy path retains
// DefaultTransport's ProxyFromEnvironment so HTTPS_PROXY/HTTP_PROXY/NO_PROXY are
// still honored.
func TestAPIHTTPClientNoProxyKeepsEnvProxy(t *testing.T) {
	t.Parallel()
	c, err := apiHTTPClient("", testRespHeaderTimeout, testMaxIdleConnsPerHost)
	if err != nil {
		t.Fatalf("apiHTTPClient: %v", err)
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport = %T, want *http.Transport", c.Transport)
	}
	if tr.Proxy == nil {
		t.Error("Proxy is nil, want ProxyFromEnvironment retained from the clone")
	}
}

func TestProxyHTTPClientInvalid(t *testing.T) {
	t.Parallel()
	// A control character makes url.Parse fail outright.
	if _, err := apiHTTPClient("http://\x7f", testRespHeaderTimeout, testMaxIdleConnsPerHost); err == nil {
		t.Fatal("expected error for unparseable proxy url")
	}
}

// TestNewWithProxy verifies the client constructs when a proxy is configured.
// A concrete Cloud is set so gofalcon skips cloud autodiscovery (a network call
// at construction); the OAuth token exchange is deferred to first use, so this
// exercises the proxy-injection branch fully offline.
func TestNewWithProxy(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{
		ClientID:     "id",
		ClientSecret: "secret",
		Cloud:        "us-2",
		Proxy:        "http://proxy.example.com:8080",
	}
	c, err := New(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("New with proxy: %v", err)
	}
	if c == nil {
		t.Fatal("New returned nil client")
	}
}

func TestNewWithoutProxy(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{
		ClientID:     "id",
		ClientSecret: "secret",
		Cloud:        "us-2",
	}
	c, err := New(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("New without proxy: %v", err)
	}
	if c == nil {
		t.Fatal("New returned nil client")
	}
}

// TestOAuth2ContextKeyResolves documents the mechanism the proxy relies on:
// gofalcon's client-credentials path resolves its base HTTP client from the
// oauth2.HTTPClient context key. If this ever stops holding, proxy injection is
// silently broken, so assert it directly.
func TestOAuth2ContextKeyResolves(t *testing.T) {
	t.Parallel()
	want := &http.Client{}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, want)
	got, ok := ctx.Value(oauth2.HTTPClient).(*http.Client)
	if !ok || got != want {
		t.Fatal("oauth2.HTTPClient context key did not round-trip an *http.Client")
	}
}
