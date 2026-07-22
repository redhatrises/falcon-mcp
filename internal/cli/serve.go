package cli

import (
	"context"
	"crypto/subtle"
	"errors"
	"expvar"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/config"
	falconapi "github.com/crowdstrike/falcon-mcp/internal/falcon"
	"github.com/crowdstrike/falcon-mcp/internal/mcpserver"
)

// jsonRPCMediaType is an alternate Content-Type some MCP clients send on POST
// bodies. The Go MCP SDK only accepts application/json; middleware rewrites this
// to application/json while preserving parameters (e.g. charset).
const jsonRPCMediaType = "application/json-rpc"

// serve builds the Falcon client and MCP server, then serves over the
// configured transport (stdio, streamable-http, or sse) until ctx is cancelled.
// It derives a context cancelled on os.Interrupt so the transports drain
// gracefully on Ctrl+C. The server is closed when serve returns.
func serve(ctx context.Context, cfg *config.Config) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()

	api, err := falconapi.New(ctx, cfg)
	if err != nil {
		return err
	}
	srv, err := mcpserver.New(cfg, api)
	if err != nil {
		return err
	}
	defer func() { _ = srv.Close() }()

	// Ops endpoints are independent of the MCP transport: each is opt-in via its
	// own addr and works even under stdio. Each is bound synchronously so a bind
	// failure aborts startup instead of leaving a probe endpoint silently down.
	// They share ctx, so Ctrl+C signals their shutdown alongside the MCP server.
	// serve does not wait for their drain to finish: they are best-effort
	// debug/probe endpoints, so the process may exit before a slow pprof capture
	// completes.
	for _, ops := range []struct {
		name, addr string
		handler    http.Handler
		sensitive  bool
	}{
		{"health", cfg.HealthAddr, healthHandler(), false},
		{"metrics", cfg.MetricsAddr, metricsHandler(), true},
		{"pprof", cfg.PprofAddr, pprofHandler(), true},
	} {
		if ops.sensitive && ops.addr != "" && !isLoopbackAddr(ops.addr) {
			slog.Warn("ops endpoint bound to a non-loopback address; it is unauthenticated and intended for debugging only — restrict access with firewall rules",
				"endpoint", ops.name, "addr", ops.addr)
		}
		if err := startOps(ctx, ops.name, ops.addr, ops.handler, cfg.IdleTimeout); err != nil {
			return err
		}
	}

	switch cfg.Transport {
	case "stdio":
		slog.Info("falcon-mcp starting", "transport", "stdio")
		// Ctrl+C cancels ctx: a clean shutdown, not an error. Swallow
		// context.Canceled so it isn't surfaced as a run failure, mirroring
		// serveHTTP's clean-shutdown semantics.
		if err := srv.Run(ctx, &mcp.StdioTransport{}); err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
		slog.Info("falcon-mcp shutdown complete", "transport", "stdio")
		return nil
	case "streamable-http":
		opts := &mcp.StreamableHTTPOptions{Stateless: cfg.StatelessHTTP}
		h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv.MCP() }, opts)
		slog.Info("falcon-mcp starting", "transport", "streamable-http", "addr", cfg.HTTPAddr, "stateless", cfg.StatelessHTTP, "auth", cfg.APIKey != "")
		return serveHTTP(ctx, httpServer{
			endpoint:    "streamable-http",
			addr:        cfg.HTTPAddr,
			handler:     withAPIKey(cfg.APIKey, withHTTPMiddleware(h)),
			idleTimeout: cfg.IdleTimeout,
		})
	case "sse":
		h := mcp.NewSSEHandler(func(*http.Request) *mcp.Server { return srv.MCP() }, nil)
		slog.Info("falcon-mcp starting", "transport", "sse", "addr", cfg.HTTPAddr, "auth", cfg.APIKey != "")
		return serveHTTP(ctx, httpServer{
			endpoint:    "sse",
			addr:        cfg.HTTPAddr,
			handler:     withAPIKey(cfg.APIKey, withHTTPMiddleware(h)),
			idleTimeout: cfg.IdleTimeout,
		})
	default:
		// Defense-in-depth: config.Load already validated the transport.
		return fmt.Errorf("unsupported transport %q", cfg.Transport)
	}
}

// startOps binds addr and serves h on it in a goroutine tied to ctx when addr
// is non-empty; an empty addr disables the endpoint and starts no listener. The
// bind happens synchronously so a bind failure (port in use, permission denied)
// is returned to the caller and aborts startup rather than being lost in a
// background goroutine — an ops listener that never comes up must not look
// healthy. A serve failure after a successful bind is only logged. name labels
// the endpoint in logs.
func startOps(ctx context.Context, name, addr string, h http.Handler, idle time.Duration) error {
	if addr == "" {
		return nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("bind %s endpoint %q: %w", name, addr, err)
	}
	slog.Info(fmt.Sprintf("falcon-mcp %s endpoint", name), "endpoint", name, "addr", addr)
	go func() {
		if err := serveHTTP(ctx, httpServer{
			endpoint:    name,
			addr:        addr,
			handler:     h,
			idleTimeout: idle,
			listener:    ln,
		}); err != nil {
			slog.Error("ops endpoint exited", "endpoint", name, "err", err)
		}
	}()
	return nil
}

// isLoopbackAddr reports whether addr binds only to the loopback interface, so
// callers can warn when a sensitive endpoint is exposed off-host. A host that is
// an IP is checked directly; a hostname is resolved and treated as loopback only
// when every resolved address is loopback. An empty host (e.g. ":6060") binds
// all interfaces and is not loopback. A malformed addr is reported as
// non-loopback so the caller errs toward warning.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if !ip.IsLoopback() {
			return false
		}
	}
	return true
}

// healthHandler serves a fixed 200 "ok" liveness response on /healthz. It is a
// pure liveness probe: it reports that the process is up and serving, not that
// any dependency is reachable.
func healthHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}

// metricsHandler serves the stdlib expvar metrics on /metrics. expvar is used
// directly to avoid a metrics dependency. It deliberately does not use
// expvar.Handler: that handler publishes "cmdline" (the process os.Args), which
// would expose credentials passed as flags rather than env vars. This handler
// emits the same JSON object but skips "cmdline".
func metricsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		fmt.Fprintf(w, "{\n")
		first := true
		expvar.Do(func(kv expvar.KeyValue) {
			if kv.Key == "cmdline" {
				return
			}
			if !first {
				fmt.Fprintf(w, ",\n")
			}
			first = false
			fmt.Fprintf(w, "%q: %s", kv.Key, kv.Value)
		})
		fmt.Fprintf(w, "\n}\n")
	})
	return mux
}

// pprofHandler serves the net/http/pprof profiling endpoints under
// /debug/pprof/ on its own mux. The handlers are registered by name rather than
// via the package's blank-import side effect on http.DefaultServeMux, so
// profiling is exposed only on the addr the operator opts into.
func pprofHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return mux
}

// withHTTPMiddleware applies the HTTP transport compatibility middlewares that
// mirror the Python falcon-mcp ASGI stack (strip trailing slashes, normalize
// application/json-rpc Content-Type). Request order matches Python: auth wraps
// this stack, then Content-Type normalization, then trailing-slash strip, then
// the MCP handler.
func withHTTPMiddleware(next http.Handler) http.Handler {
	next = stripTrailingSlash(next)
	next = normalizeContentType(next)
	return next
}

// stripTrailingSlashPath removes trailing slashes from path, leaving "/" alone.
// Multiple trailing slashes are all stripped (e.g. "/mcp///" -> "/mcp").
func stripTrailingSlashPath(path string) string {
	if path == "/" || !strings.HasSuffix(path, "/") {
		return path
	}
	stripped := strings.TrimRight(path, "/")
	if stripped == "" {
		return "/"
	}
	return stripped
}

// stripTrailingSlash rewrites r.URL.Path (and RawPath when set) so handlers
// that match exact paths do not 404/redirect when clients append a trailing
// slash. Mirrors falcon_mcp.common.auth.strip_trailing_slash_middleware.
func stripTrailingSlash(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if stripped := stripTrailingSlashPath(r.URL.Path); stripped != r.URL.Path {
			r.URL.Path = stripped
			if r.URL.RawPath != "" {
				r.URL.RawPath = stripTrailingSlashPath(r.URL.RawPath)
			}
		}
		next.ServeHTTP(w, r)
	})
}

// normalizeJSONRPCContentType rewrites application/json-rpc to application/json,
// preserving parameters (e.g. "; charset=utf-8"). Matching is case-insensitive
// on the media type. Returns the (possibly rewritten) value and whether a
// rewrite occurred. Mirrors falcon_mcp.common.auth.normalize_content_type_middleware.
func normalizeJSONRPCContentType(ct string) (string, bool) {
	if !strings.HasPrefix(strings.ToLower(ct), jsonRPCMediaType) {
		return ct, false
	}
	// Media-type length is case-invariant; keep any parameters from the original.
	rest := ct[len(jsonRPCMediaType):]
	return "application/json" + rest, true
}

// normalizeContentType rewrites request Content-Type application/json-rpc to
// application/json so the go-sdk's strict media-type check accepts clients that
// send the JSON-RPC media type. Mirrors the Python ASGI middleware.
func normalizeContentType(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rewritten, ok := normalizeJSONRPCContentType(r.Header.Get("Content-Type")); ok {
			r.Header.Set("Content-Type", rewritten)
		}
		next.ServeHTTP(w, r)
	})
}

// withAPIKey guards next with a static-secret check when key is non-empty; an
// empty key returns next unchanged, leaving the endpoint open (auth disabled).
// A request must carry a matching x-api-key header or it gets 401 with a JSON
// body. The compare is constant-time to avoid leaking the key through response
// timing. Header, body, and env/flag naming match the upstream Python falcon-mcp
// so existing clients and configs are wire-compatible.
func withAPIKey(key string, next http.Handler) http.Handler {
	if key == "" {
		return next
	}
	want := []byte(key)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provided := []byte(r.Header.Get("x-api-key"))
		if subtle.ConstantTimeCompare(provided, want) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"Unauthorized"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// httpServer describes one graceful HTTP listener. endpoint labels it in logs
// (e.g. "streamable-http", "metrics") so lifecycle lines are attributable when
// several listeners run at once. When listener is non-nil, serveHTTP serves on
// it (the caller has already bound the port and observed any bind error);
// otherwise serveHTTP binds addr itself.
type httpServer struct {
	endpoint    string
	addr        string
	handler     http.Handler
	idleTimeout time.Duration
	listener    net.Listener
}

// serveHTTP runs s until ctx is cancelled, then drains in-flight requests via a
// graceful shutdown. idleTimeout bounds how long an idle keep-alive connection
// is held open before reaping. It returns nil on clean shutdown and a wrapped
// error if the listener fails to bind or the drain fails.
func serveHTTP(ctx context.Context, s httpServer) error {
	srv := &http.Server{
		Addr:              s.addr,
		Handler:           s.handler,
		ReadHeaderTimeout: 10 * time.Second, // bound header read to mitigate Slowloris
		IdleTimeout:       s.idleTimeout,    // reap idle keep-alive connections so they don't accumulate and exhaust file descriptors under many clients
	}

	errc := make(chan error, 1)
	go func() {
		serve := srv.ListenAndServe
		if s.listener != nil {
			serve = func() error { return srv.Serve(s.listener) }
		}
		if err := serve(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
			return
		}
		errc <- nil
	}()

	select {
	case err := <-errc: // failed to bind, or exited early
		return err
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutCtx); err != nil {
			return fmt.Errorf("http shutdown: %w", err)
		}
		slog.Info("falcon-mcp shutdown complete", "endpoint", s.endpoint, "addr", s.addr)
		return nil
	}
}
