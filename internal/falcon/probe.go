package falconapi

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon"

	"github.com/crowdstrike/falcon-mcp/internal/config"
)

// ProbeConnectivity performs a non-stateful OAuth2 client-credentials token
// request against the Falcon API. It matches Python falcon_check_connectivity
// semantics: _login_handler(stateful=False) and connected == (status_code == 201).
//
// The probe does not mutate any shared gofalcon client token state. On network
// or HTTP errors it logs a warning and returns false rather than propagating.
func ProbeConnectivity(ctx context.Context, cfg *config.Config) bool {
	return probeConnectivity(ctx, cfg, nil)
}

// probeConnectivity is the testable implementation. When httpClient is nil a
// client is built from cfg (proxy, timeouts). Tests pass an httptest client so
// status-code branches are covered offline.
func probeConnectivity(ctx context.Context, cfg *config.Config, httpClient *http.Client) bool {
	if cfg == nil {
		return false
	}

	host := cfg.HostOverride
	if host == "" {
		host = falcon.Cloud(cfg.Cloud).Host()
	}
	tokenURL := "https://" + host + "/oauth2/token"

	form := url.Values{}
	form.Set("client_id", cfg.ClientID)
	form.Set("client_secret", cfg.ClientSecret)
	if cfg.MemberCID != "" {
		form.Set("member_cid", cfg.MemberCID)
	}

	if httpClient == nil {
		var err error
		httpClient, err = apiHTTPClient(cfg.Proxy, cfg.ResponseHeaderTimeout, cfg.MaxIdleConnsPerHost)
		if err != nil {
			slog.Warn("connectivity probe failed", "err", err)
			return false
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		slog.Warn("connectivity probe failed", "err", err)
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		slog.Warn("connectivity probe failed", "err", err)
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	// Drain body so the connection can be reused; ignore content.
	_, _ = io.Copy(io.Discard, resp.Body)

	// Falcon's OAuth2 token endpoint returns 201 Created on success (same check
	// as Python: result.get("status_code") == 201).
	return resp.StatusCode == http.StatusCreated
}
