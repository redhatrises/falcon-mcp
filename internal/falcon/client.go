// Package falconapi builds the shared gofalcon API client from validated
// configuration. It isolates region/MSSP wiring so the rest of the server can
// depend on the concrete *client.CrowdStrikeAPISpecification.
package falconapi

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/crowdstrike/falcon-mcp/internal/config"
)

// New constructs a gofalcon client from cfg. The context is used only for the
// OAuth2 token exchange during construction (per gofalcon's ApiConfig
// contract); per-call cancellation is supplied separately on each API call.
//
// The context always carries an *http.Client under the oauth2.HTTPClient key.
// gofalcon resolves its base transport from that key (via clientcredentials ->
// oauth2.NewClient), so both the token exchange and all API calls use it. This
// is the correct injection point: ApiConfig.TransportDecorator wraps gofalcon's
// outermost round-tripper (above the OAuth transport), so using it would strip
// the Authorization layer and break auth. The injected client clones
// http.DefaultTransport, preserving its connection-pool defaults and (when
// cfg.Proxy is empty) its ProxyFromEnvironment behavior, so HTTPS_PROXY/
// HTTP_PROXY/NO_PROXY are still honored; it adds a response-header timeout and,
// when cfg.Proxy is set, overrides the proxy.
func New(ctx context.Context, cfg *config.Config) (*client.CrowdStrikeAPISpecification, error) {
	httpClient, err := apiHTTPClient(cfg.Proxy, cfg.ResponseHeaderTimeout, cfg.MaxIdleConnsPerHost)
	if err != nil {
		return nil, err
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	c, err := falcon.NewClient(&falcon.ApiConfig{
		ClientId:          cfg.ClientID,
		ClientSecret:      cfg.ClientSecret,
		MemberCID:         cfg.MemberCID,
		Cloud:             falcon.Cloud(cfg.Cloud),
		HostOverride:      cfg.HostOverride,
		UserAgentOverride: cfg.UserAgent,
		Context:           ctx,
	})
	if err != nil {
		return nil, err
	}
	// Log the client shape at construction, never the secret. MemberCID
	// is reported only by presence; the proxy URL is reported only by presence
	// because it can embed credentials in userinfo.
	slog.Default().Debug("falcon client constructed",
		"cloud", cfg.Cloud,
		"host_override", cfg.HostOverride,
		"member_cid_set", cfg.MemberCID != "",
		"user_agent", cfg.UserAgent,
		"proxy_set", cfg.Proxy != "",
	)
	return c, nil
}

// apiHTTPClient builds the *http.Client gofalcon uses for the token exchange and
// all API calls. It clones http.DefaultTransport to keep its connection-pool
// defaults, then sets the response-header timeout and per-host idle-connection
// cap. When proxy is non-empty it overrides the proxy; when empty the clone
// retains DefaultTransport's ProxyFromEnvironment, so HTTPS_PROXY/HTTP_PROXY/
// NO_PROXY are still honored. proxy is validated by config.Load; it is re-parsed
// here rather than threaded through as a *url.URL to keep config.Config free of
// net/url types. respHeaderTimeout and maxIdleConnsPerHost are already
// defaulted and validated by config.Load.
func apiHTTPClient(proxy string, respHeaderTimeout time.Duration, maxIdleConnsPerHost int) (*http.Client, error) {
	dt, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("http.DefaultTransport is not an *http.Transport")
	}
	tr := dt.Clone()
	tr.ResponseHeaderTimeout = respHeaderTimeout
	tr.MaxIdleConnsPerHost = maxIdleConnsPerHost
	if proxy != "" {
		u, err := url.Parse(proxy)
		if err != nil {
			return nil, fmt.Errorf("parse proxy url %q: %w", proxy, err)
		}
		tr.Proxy = http.ProxyURL(u)
	}
	return &http.Client{Transport: tr}, nil
}

// CheckConnectivity reports whether cfg's credentials can obtain an OAuth2
// token from the Falcon API. It runs the same client-credentials exchange
// gofalcon uses for every API call (golang.org/x/oauth2/clientcredentials),
// so a success here means real requests will authenticate.
//
// It builds a fresh token source rather than touching any shared client, so a
// connectivity check never disturbs cached token state. On any error — bad
// credentials, non-2xx response, or an unreachable host — it logs a warning and
// returns false rather than propagating.
func CheckConnectivity(ctx context.Context, cfg *config.Config) bool {
	return checkConnectivity(ctx, cfg, nil)
}

// checkConnectivity is the testable implementation. When httpClient is nil a
// client is built from cfg (proxy, timeouts). Tests pass an httptest client so
// the token-exchange branches are covered offline.
func checkConnectivity(ctx context.Context, cfg *config.Config, httpClient *http.Client) bool {
	if cfg == nil {
		return false
	}

	host := cfg.HostOverride
	if host == "" {
		host = falcon.Cloud(cfg.Cloud).Host()
	}

	conf := clientcredentials.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		TokenURL:     "https://" + host + "/oauth2/token",
	}
	if cfg.MemberCID != "" {
		conf.EndpointParams = url.Values{"member_cid": {cfg.MemberCID}}
	}

	if httpClient == nil {
		var err error
		httpClient, err = apiHTTPClient(cfg.Proxy, cfg.ResponseHeaderTimeout, cfg.MaxIdleConnsPerHost)
		if err != nil {
			slog.Warn("connectivity check failed", "err", err)
			return false
		}
	}
	// gofalcon resolves its token-exchange HTTP client from this context key
	// (via oauth2.NewClient); reuse it so the probe honors proxy and timeout
	// settings exactly as production calls do.
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	if _, err := conf.Token(ctx); err != nil {
		slog.Warn("connectivity check failed", "err", err)
		return false
	}
	return true
}
