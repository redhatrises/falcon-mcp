// Package falconapi builds the shared gofalcon API client from validated
// configuration. It isolates region/MSSP wiring so the rest of the server can
// depend on the concrete *client.CrowdStrikeAPISpecification.
package falconapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/crowdstrike/falcon-mcp/internal/config"
)

// ErrAuthenticationFailed classifies a failed OAuth2 token exchange during
// client construction. Callers can branch with errors.Is. The error text never
// includes the client secret or access token.
var ErrAuthenticationFailed = errors.New("falconapi: failed to authenticate with the Falcon API")

// authenticateCredentials exchanges client credentials for an OAuth2 token so
// bad credentials fail before the server starts serving. It mirrors Python
// FalconClient.authenticate() fail-fast behavior. The obtained token is
// discarded; gofalcon fetches its own via the clientcredentials TokenSource on
// first API use. The var is overridable in tests so construction can stay offline.
var authenticateCredentials = doAuthenticateCredentials

// New constructs a gofalcon client from cfg and eagerly validates the OAuth2
// credentials with a token exchange. Bad credentials fail here rather than on
// the first tool call, matching the Python port's init-time authenticate().
//
// The context is used for the OAuth2 token exchange during construction (per
// gofalcon's ApiConfig contract and our fail-fast probe); per-call cancellation
// is supplied separately on each API call.
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

	// Keep ApiConfig as a named value so Autodiscover can mutate Cloud in place
	// and Host() reflects the resolved region for the fail-fast token exchange.
	ac := &falcon.ApiConfig{
		ClientId:          cfg.ClientID,
		ClientSecret:      cfg.ClientSecret,
		MemberCID:         cfg.MemberCID,
		Cloud:             falcon.Cloud(cfg.Cloud),
		HostOverride:      cfg.HostOverride,
		UserAgentOverride: cfg.UserAgent,
		Context:           ctx,
	}
	c, err := falcon.NewClient(ac)
	if err != nil {
		// Autodiscover (when cloud is unset/autodiscover and HostOverride is
		// empty) already performs a credentialed token call; surface that as an
		// authentication failure so operators get a consistent class of error.
		return nil, fmt.Errorf("%w: %v", ErrAuthenticationFailed, err)
	}
	if err := authenticateCredentials(ctx, httpClient, ac); err != nil {
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

// doAuthenticateCredentials performs a client-credentials token exchange against
// the same host and parameters gofalcon uses (https://{Host}/oauth2/token, plus
// member_cid when set). A non-empty access token is required for success. The
// token is not retained; this call exists solely to fail fast on bad credentials.
func doAuthenticateCredentials(ctx context.Context, httpClient *http.Client, ac *falcon.ApiConfig) error {
	cfg := clientcredentials.Config{
		ClientID:     ac.ClientId,
		ClientSecret: ac.ClientSecret,
		// Match gofalcon clientCredentialsHTTPClient TokenURL construction.
		TokenURL: "https://" + ac.Host() + "/oauth2/token",
	}
	if ac.MemberCID != "" {
		cfg.EndpointParams = url.Values{
			"member_cid": []string{ac.MemberCID},
		}
	}
	// Thread the same HTTP client (proxy, timeouts, connection pool) that
	// gofalcon will use, via the oauth2.HTTPClient context key.
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	tok, err := cfg.Token(ctx)
	if err != nil {
		return formatAuthError(err, ac)
	}
	if tok == nil || tok.AccessToken == "" {
		return fmt.Errorf("%w: token endpoint returned an empty access token. Hint: Check network connectivity to %s and verify FALCON_BASE_URL/--cloud is correct for your CrowdStrike region",
			ErrAuthenticationFailed, ac.Host())
	}
	return nil
}

// formatAuthError builds an ErrAuthenticationFailed that carries HTTP status
// (when available), OAuth error fields, and an operator-oriented hint. It never
// includes the client secret or access token. Hints mirror the Python client's
// auth_failure_message().
func formatAuthError(err error, ac *falcon.ApiConfig) error {
	var re *oauth2.RetrieveError
	status := 0
	var detail []string
	if errors.As(err, &re) {
		if re.Response != nil {
			status = re.Response.StatusCode
		}
		if re.ErrorCode != "" {
			detail = append(detail, re.ErrorCode)
		}
		if re.ErrorDescription != "" {
			detail = append(detail, re.ErrorDescription)
		}
		// Prefer structured OAuth fields; otherwise parse Falcon's
		// {"errors":[{"message":"..."}]} envelope, then a short body snippet.
		// Body is never the secret (client_secret is POST form / basic auth).
		if len(detail) == 0 && len(re.Body) > 0 {
			if msg := falconTokenErrorMessage(re.Body); msg != "" {
				detail = append(detail, msg)
			} else {
				body := strings.TrimSpace(string(re.Body))
				if len(body) > 200 {
					body = body[:200] + "..."
				}
				detail = append(detail, body)
			}
		}
	} else {
		// Network / DNS / context cancellation — keep the error text but never
		// assume it embeds secrets (client_secret is not in the URL).
		detail = append(detail, err.Error())
	}

	switch {
	case status == http.StatusUnauthorized || status == http.StatusBadRequest:
		// Falcon often returns 400 (not 401) for unknown client_id/secret pairs.
		detail = append(detail, "Hint: Verify FALCON_CLIENT_ID and FALCON_CLIENT_SECRET are correct and the API key has not been revoked")
	case status == http.StatusForbidden && ac.MemberCID != "":
		// MemberCID is an account selector, not a secret; Python surfaces it too.
		detail = append(detail, fmt.Sprintf("Hint: A member_cid is configured (%s). Verify this is a valid child CID managed by your parent tenant, not the parent CID itself", ac.MemberCID))
	case status == http.StatusForbidden:
		detail = append(detail, "Hint: Verify the API client has the required scopes and has not been disabled")
	default:
		detail = append(detail, fmt.Sprintf("Hint: Check network connectivity to %s and verify FALCON_BASE_URL/--cloud is correct for your CrowdStrike region", ac.Host()))
	}

	msg := strings.Join(detail, ". ")
	if status > 0 {
		return fmt.Errorf("%w (HTTP %d): %s", ErrAuthenticationFailed, status, msg)
	}
	return fmt.Errorf("%w: %s", ErrAuthenticationFailed, msg)
}

// falconTokenErrorMessage extracts the first errors[].message from a Falcon
// OAuth error body. CrowdStrike's token endpoint often returns this MSA-style
// envelope instead of RFC 6749 error/error_description fields.
func falconTokenErrorMessage(body []byte) string {
	var payload struct {
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return ""
	}
	for _, e := range payload.Errors {
		if m := strings.TrimSpace(e.Message); m != "" {
			return m
		}
	}
	return ""
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
