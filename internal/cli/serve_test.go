package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/crowdstrike/falcon-mcp/internal/config"
)

func TestServeHTTPGracefulShutdown(t *testing.T) {
	h := http.NewServeMux()
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		errc <- serveHTTP(ctx, httpServer{addr: "127.0.0.1:0", handler: h, idleTimeout: 120 * time.Second}) // :0 = OS-assigned free port, no collisions
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("serveHTTP returned error on graceful shutdown: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serveHTTP did not return after ctx cancel")
	}
}

func TestServeHTTPInvalidAddr(t *testing.T) {
	h := http.NewServeMux()
	// An unparseable address fails to bind and surfaces through the error channel
	// before ctx is cancelled.
	if err := serveHTTP(t.Context(), httpServer{addr: "bad:addr:99", handler: h, idleTimeout: 120 * time.Second}); err == nil {
		t.Fatal("expected error for invalid listen address")
	}
}

func TestWithAPIKey(t *testing.T) {
	t.Parallel()
	const key = "s3cret"

	// next records whether the wrapped handler was reached and returns 200.
	newNext := func(reached *bool) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			*reached = true
			w.WriteHeader(http.StatusOK)
		})
	}

	tests := []struct {
		name       string
		key        string // key passed to withAPIKey
		header     string // x-api-key sent by the client
		setHeader  bool
		wantStatus int
		wantNext   bool // whether next should be reached
	}{
		{name: "no auth configured passes through", key: "", setHeader: false, wantStatus: http.StatusOK, wantNext: true},
		{name: "missing header rejected", key: key, setHeader: false, wantStatus: http.StatusUnauthorized, wantNext: false},
		{name: "wrong key rejected", key: key, header: "nope", setHeader: true, wantStatus: http.StatusUnauthorized, wantNext: false},
		{name: "empty header rejected", key: key, header: "", setHeader: true, wantStatus: http.StatusUnauthorized, wantNext: false},
		{name: "correct key passes through", key: key, header: key, setHeader: true, wantStatus: http.StatusOK, wantNext: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var reached bool
			h := withAPIKey(tt.key, newNext(&reached))

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.setHeader {
				req.Header.Set("x-api-key", tt.header)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if reached != tt.wantNext {
				t.Errorf("next reached = %v, want %v", reached, tt.wantNext)
			}
			if tt.wantStatus == http.StatusUnauthorized {
				if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
					t.Errorf("Content-Type = %q, want application/json", ct)
				}
				body, _ := io.ReadAll(rec.Body)
				if got := string(body); got != `{"error":"Unauthorized"}` {
					t.Errorf("body = %q, want unauthorized JSON", got)
				}
			}
		})
	}
}

func TestOpsHandlers(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		handler    http.Handler
		path       string
		wantStatus int
		wantInBody string // substring that must appear in the response body
	}{
		{name: "health returns ok", handler: healthHandler(), path: "/healthz", wantStatus: http.StatusOK, wantInBody: "ok"},
		{name: "metrics exposes memstats", handler: metricsHandler(), path: "/metrics", wantStatus: http.StatusOK, wantInBody: "memstats"},
		{name: "pprof index served", handler: pprofHandler(), path: "/debug/pprof/", wantStatus: http.StatusOK, wantInBody: "goroutine"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()
			tt.handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			body, _ := io.ReadAll(rec.Body)
			if !strings.Contains(string(body), tt.wantInBody) {
				t.Errorf("body = %q, want to contain %q", string(body), tt.wantInBody)
			}
		})
	}
}

// TestMetricsHandlerOmitsCmdline verifies the metrics handler emits valid JSON
// that includes memstats but not cmdline: cmdline is the process os.Args and
// would leak credentials passed as flags.
func TestMetricsHandlerOmitsCmdline(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	metricsHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)

	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("response is not valid JSON: %v\nbody: %s", err, body)
	}
	if _, ok := m["cmdline"]; ok {
		t.Error("metrics response contains cmdline; it must be omitted to avoid leaking os.Args")
	}
	if _, ok := m["memstats"]; !ok {
		t.Error("metrics response missing memstats")
	}
}

func TestStartOpsDisabled(t *testing.T) {
	t.Parallel()
	var reached atomic.Bool
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Store(true)
		w.WriteHeader(http.StatusOK)
	})
	if err := startOps(t.Context(), "test", "", h, 120*time.Second); err != nil {
		t.Fatalf("startOps with empty addr: %v", err)
	}
	// Give any (erroneously) launched goroutine a moment to bind and serve.
	time.Sleep(50 * time.Millisecond)
	if reached.Load() {
		t.Error("disabled ops endpoint (addr empty) should not serve any request")
	}
}

// TestStartOpsBindFailureReturnsError verifies a bind failure is returned
// synchronously rather than swallowed in the serve goroutine: an ops endpoint
// that cannot bind must abort startup, not leave a silently-down probe. The
// port is held open by a live listener so startOps's bind collides with it.
func TestStartOpsBindFailureReturnsError(t *testing.T) {
	t.Parallel()
	ln := newLocalListener(t)
	t.Cleanup(func() { _ = ln.Close() })
	addr := ln.Addr().String() // still bound: startOps will collide on it

	err := startOps(t.Context(), "health", addr, healthHandler(), 120*time.Second)
	if err == nil {
		t.Fatal("startOps on an in-use addr should return a bind error")
	}
}

// TestStartOpsServes verifies an enabled addr launches a listener that serves
// the handler. Graceful drain on ctx cancellation is covered by
// TestStartOpsShutdownLogNamesEndpoint.
func TestStartOpsServes(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	addr := startOpsOnFreePort(ctx, t, "health", healthHandler())

	// Poll until the listener is up (goroutine bind is asynchronous).
	var resp *http.Response
	var err error
	for range 50 {
		resp, err = http.Get("http://" + addr + "/healthz") //nolint:noctx // short-lived test client
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

// TestStartOpsShutdownLogNamesEndpoint verifies serveHTTP tags its
// shutdown-complete log line with the endpoint name, so lifecycle lines are
// attributable when several ops listeners run at once. This asserts on log
// labeling, not on a shutdown guarantee: in production the ops goroutines are
// fire-and-forget (see startOps), so the process may exit before an ops
// endpoint's drain finishes. The test keeps its process alive long enough to
// observe the line; that timing is a test artifact, not a promised drain.
func TestStartOpsShutdownLogNamesEndpoint(t *testing.T) {
	var buf syncBuffer
	orig := slog.Default()
	t.Cleanup(func() { slog.SetDefault(orig) })
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))

	ctx, cancel := context.WithCancel(context.Background())
	addr := startOpsOnFreePort(ctx, t, "metrics", healthHandler())

	// Wait for the listener to bind before cancelling so the shutdown path runs.
	for range 50 {
		resp, err := http.Get("http://" + addr + "/healthz") //nolint:noctx // short-lived test client
		if err == nil {
			_ = resp.Body.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()

	// Wait for the shutdown-complete line to appear, then isolate it: the
	// startup line also carries endpoint=metrics, so asserting on the whole
	// buffer would pass even if the shutdown line dropped the name.
	var shutLine string
	for range 50 {
		for line := range strings.SplitSeq(buf.String(), "\n") {
			if strings.Contains(line, "shutdown complete") {
				shutLine = line
			}
		}
		if shutLine != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if shutLine == "" {
		t.Fatalf("no shutdown-complete log line captured; got: %q", buf.String())
	}
	if !strings.Contains(shutLine, "endpoint=metrics") {
		t.Errorf("shutdown log missing endpoint name; got: %q", shutLine)
	}
}

// syncBuffer is a goroutine-safe io.Writer for capturing slog output: serveHTTP
// logs from a background goroutine while the test reads, so the writes and reads
// must be mutex-guarded.
type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// newLocalListener grabs an OS-assigned free port on loopback so the test uses a
// real, unique addr without racing on a hardcoded port.
func newLocalListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return ln
}

// startOpsOnFreePort discovers a free loopback port and starts an ops endpoint
// on it, returning the bound addr. Discovery closes the probe listener before
// startOps re-binds, so another process can steal the port in the gap; a few
// retries on that collision keep the test hermetic under parallel load.
func startOpsOnFreePort(ctx context.Context, t *testing.T, name string, h http.Handler) string {
	t.Helper()
	for attempt := range 5 {
		ln := newLocalListener(t)
		addr := ln.Addr().String()
		_ = ln.Close() // free the port; startOps re-binds it
		err := startOps(ctx, name, addr, h, 120*time.Second)
		if err == nil {
			return addr
		}
		if errors.Is(err, syscall.EADDRINUSE) && attempt < 4 {
			continue // port stolen in the close/rebind gap; pick another
		}
		t.Fatalf("startOps: %v", err)
	}
	panic("unreachable")
}

func TestIsLoopbackAddr(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		addr string
		want bool
	}{
		{name: "ipv4 loopback", addr: "127.0.0.1:6060", want: true},
		{name: "ipv4 loopback range", addr: "127.0.0.5:6060", want: true},
		{name: "ipv6 loopback", addr: "[::1]:6060", want: true},
		{name: "localhost resolves loopback", addr: "localhost:6060", want: true},
		{name: "all interfaces ipv4", addr: "0.0.0.0:6060", want: false},
		{name: "all interfaces ipv6", addr: "[::]:6060", want: false},
		{name: "empty host binds all", addr: ":6060", want: false},
		{name: "routable ip", addr: "192.168.1.5:6060", want: false},
		{name: "malformed addr", addr: "bad:addr:99", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := config.IsLoopbackAddr(tt.addr); got != tt.want {
				t.Errorf("IsLoopbackAddr(%q) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

// TestCheckSensitiveOpsBinds verifies metrics/pprof fail closed on non-loopback
// binds unless AllowInsecureOpsBind is set, while health is never gated and
// empty/loopback sensitive addrs always pass.
func TestCheckSensitiveOpsBinds(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		cfg     *config.Config
		wantErr bool
	}{
		{
			name: "metrics loopback ok",
			cfg:  &config.Config{MetricsAddr: "127.0.0.1:6061"},
		},
		{
			name: "pprof loopback ok",
			cfg:  &config.Config{PprofAddr: "127.0.0.1:6062"},
		},
		{
			name:    "metrics non-loopback rejected",
			cfg:     &config.Config{MetricsAddr: "0.0.0.0:6061"},
			wantErr: true,
		},
		{
			name:    "pprof non-loopback rejected",
			cfg:     &config.Config{PprofAddr: "0.0.0.0:6062"},
			wantErr: true,
		},
		{
			name:    "empty host metrics rejected",
			cfg:     &config.Config{MetricsAddr: ":6061"},
			wantErr: true,
		},
		{
			name: "health non-loopback not gated",
			cfg:  &config.Config{HealthAddr: "0.0.0.0:6060"},
		},
		{
			name: "empty metrics/pprof ok",
			cfg:  &config.Config{},
		},
		{
			name: "override allows non-loopback metrics",
			cfg: &config.Config{
				MetricsAddr:          "0.0.0.0:6061",
				AllowInsecureOpsBind: true,
			},
		},
		{
			name: "override allows non-loopback pprof",
			cfg: &config.Config{
				PprofAddr:            "0.0.0.0:6062",
				AllowInsecureOpsBind: true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := checkSensitiveOpsBinds(tt.cfg)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestCheckSensitiveOpsBindsOverrideWarns(t *testing.T) {
	var buf syncBuffer
	orig := slog.Default()
	t.Cleanup(func() { slog.SetDefault(orig) })
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))

	err := checkSensitiveOpsBinds(&config.Config{
		PprofAddr:            "0.0.0.0:6063",
		AllowInsecureOpsBind: true,
	})
	if err != nil {
		t.Fatalf("override should allow non-loopback bind: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, "allow-insecure-ops-bind") {
		t.Errorf("expected warning about insecure override; got: %q", got)
	}
	if !strings.Contains(got, "endpoint=pprof") {
		t.Errorf("expected warning to name pprof endpoint; got: %q", got)
	}
}

func TestStripTrailingSlashPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in, want string
	}{
		{in: "/", want: "/"},
		{in: "/mcp", want: "/mcp"},
		{in: "/mcp/", want: "/mcp"},
		{in: "/mcp///", want: "/mcp"},
		{in: "///", want: "/"},
		{in: "", want: ""},
		{in: "/a/b/", want: "/a/b"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			if got := stripTrailingSlashPath(tt.in); got != tt.want {
				t.Errorf("stripTrailingSlashPath(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestNormalizeJSONRPCContentType(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		in         string
		want       string
		wantChange bool
	}{
		{name: "json-rpc plain", in: "application/json-rpc", want: "application/json", wantChange: true},
		{name: "json-rpc with charset", in: "application/json-rpc; charset=utf-8", want: "application/json; charset=utf-8", wantChange: true},
		{name: "json-rpc case insensitive", in: "Application/JSON-RPC; charset=UTF-8", want: "application/json; charset=UTF-8", wantChange: true},
		{name: "plain json untouched", in: "application/json", want: "application/json", wantChange: false},
		{name: "json with charset untouched", in: "application/json; charset=utf-8", want: "application/json; charset=utf-8", wantChange: false},
		{name: "empty untouched", in: "", want: "", wantChange: false},
		{name: "unrelated media type", in: "text/plain", want: "text/plain", wantChange: false},
		// Prefix must not rewrite application/json-rpc-extra as a different type without the boundary —
		// the Python middleware uses startswith, so "application/json-rpcfoo" would rewrite; match that.
		{name: "startswith prefix match", in: "application/json-rpcfoo", want: "application/jsonfoo", wantChange: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, changed := normalizeJSONRPCContentType(tt.in)
			if got != tt.want || changed != tt.wantChange {
				t.Errorf("normalizeJSONRPCContentType(%q) = (%q, %v), want (%q, %v)",
					tt.in, got, changed, tt.want, tt.wantChange)
			}
		})
	}
}

// TestStripTrailingSlashMiddleware verifies the handler rewrites the path
// before the inner handler sees it, and leaves root "/" alone.

func TestStripTrailingSlashMiddleware(t *testing.T) {
	t.Parallel()
	var sawPath string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	})
	h := stripTrailingSlash(inner)

	req := httptest.NewRequest(http.MethodPost, "/mcp/?q=1", nil)
	// httptest normalizes trailing-slash URLs; set Path explicitly after construction.
	req.URL.Path = "/mcp/"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if sawPath != "/mcp" {
		t.Errorf("inner path = %q, want /mcp", sawPath)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	// Root must not be stripped to empty.
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if sawPath != "/" {
		t.Errorf("root path = %q, want /", sawPath)
	}
}

// TestNormalizeContentTypeMiddleware verifies application/json-rpc is rewritten
// on the request the inner handler observes.

func TestNormalizeContentTypeMiddleware(t *testing.T) {
	t.Parallel()
	var sawCT string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawCT = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	})
	h := normalizeContentType(inner)

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json-rpc; charset=utf-8")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if sawCT != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q, want application/json; charset=utf-8", sawCT)
	}

	req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if sawCT != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", sawCT)
	}
}

// TestWithHTTPMiddlewareOrder checks Content-Type normalization and path strip
// both apply when composed, matching Python request order.

func TestWithHTTPMiddlewareOrder(t *testing.T) {
	t.Parallel()
	var sawPath, sawCT string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawPath = r.URL.Path
		sawCT = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	})
	h := withHTTPMiddleware(inner)

	req := httptest.NewRequest(http.MethodPost, "/mcp/", strings.NewReader(`{}`))
	req.URL.Path = "/mcp/"
	req.Header.Set("Content-Type", "application/json-rpc")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if sawPath != "/mcp" {
		t.Errorf("path = %q, want /mcp", sawPath)
	}
	if sawCT != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", sawCT)
	}
}
