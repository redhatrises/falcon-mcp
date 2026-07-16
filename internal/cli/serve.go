package cli

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/config"
	falconapi "github.com/crowdstrike/falcon-mcp/internal/falcon"
	"github.com/crowdstrike/falcon-mcp/internal/mcpserver"
)

// serve builds the Falcon client and MCP server, then serves over the
// configured transport (stdio, streamable-http, or sse) until ctx is cancelled.
// The server is closed when serve returns.
func serve(ctx context.Context, cfg *config.Config) error {
	api, err := falconapi.New(ctx, cfg)
	if err != nil {
		return err
	}
	srv, err := mcpserver.New(cfg, api)
	if err != nil {
		return err
	}
	defer func() { _ = srv.Close() }()

	switch cfg.Transport {
	case "stdio":
		slog.Info("falcon-mcp starting", "transport", "stdio")
		// Ctrl+C cancels ctx: a clean shutdown, not an error. Swallow
		// context.Canceled so it isn't surfaced as a run failure, mirroring
		// serveHTTP's clean-shutdown semantics.
		if err := srv.Run(ctx, &mcp.StdioTransport{}); err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
		slog.Info("falcon-mcp shutdown complete")
		return nil
	case "streamable-http":
		opts := &mcp.StreamableHTTPOptions{Stateless: cfg.StatelessHTTP}
		h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv.MCP() }, opts)
		slog.Info("falcon-mcp starting", "transport", "streamable-http", "addr", cfg.HTTPAddr, "stateless", cfg.StatelessHTTP, "auth", cfg.APIKey != "")
		return serveHTTP(ctx, cfg.HTTPAddr, withAPIKey(cfg.APIKey, h), cfg.IdleTimeout)
	case "sse":
		h := mcp.NewSSEHandler(func(*http.Request) *mcp.Server { return srv.MCP() }, nil)
		slog.Info("falcon-mcp starting", "transport", "sse", "addr", cfg.HTTPAddr, "auth", cfg.APIKey != "")
		return serveHTTP(ctx, cfg.HTTPAddr, withAPIKey(cfg.APIKey, h), cfg.IdleTimeout)
	default:
		// Defense-in-depth: config.Load already validated the transport.
		return fmt.Errorf("unsupported transport %q", cfg.Transport)
	}
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

// serveHTTP runs h on addr until ctx is cancelled, then drains in-flight
// requests via a graceful shutdown. idleTimeout bounds how long an idle
// keep-alive connection is held open before reaping. It returns nil on clean
// shutdown and a wrapped error if the listener fails to bind or the drain fails.
func serveHTTP(ctx context.Context, addr string, h http.Handler, idleTimeout time.Duration) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second, // bound header read to mitigate Slowloris
		IdleTimeout:       idleTimeout,      // reap idle keep-alive connections so they don't accumulate and exhaust file descriptors under many clients
	}

	errc := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
			return
		}
		errc <- nil
	}()

	select {
	case err := <-errc: // failed to bind, or exited early
		return err
	case <-ctx.Done():
		slog.Info("falcon-mcp shutting down", "addr", addr)
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutCtx); err != nil {
			return fmt.Errorf("http shutdown: %w", err)
		}
		slog.Info("falcon-mcp shutdown complete")
		return nil
	}
}
