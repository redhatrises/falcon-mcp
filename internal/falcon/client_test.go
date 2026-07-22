package falconapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/crowdstrike/gofalcon/falcon"
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

// stubAuth installs fn as authenticateCredentials for the duration of the test.
// Not safe with t.Parallel on callers that share the package-level var.
func stubAuth(t *testing.T, fn func(context.Context, *http.Client, *falcon.ApiConfig) error) {
	t.Helper()
	orig := authenticateCredentials
	authenticateCredentials = fn
	t.Cleanup(func() { authenticateCredentials = orig })
}

// TestNewWithProxy verifies the client constructs when a proxy is configured.
// A concrete Cloud is set so gofalcon skips cloud autodiscovery (a network call
// at construction). Eager OAuth is stubbed so the test stays offline while still
// covering the proxy-injection branch of New.
func TestNewWithProxy(t *testing.T) {
	stubAuth(t, func(context.Context, *http.Client, *falcon.ApiConfig) error { return nil })
	cfg := &config.Config{
		ClientID:     "id",
		ClientSecret: "secret",
		Cloud:        "us-2",
		Proxy:        "http://proxy.example.com:8080",
	}
	c, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New with proxy: %v", err)
	}
	if c == nil {
		t.Fatal("New returned nil client")
	}
}

func TestNewWithoutProxy(t *testing.T) {
	stubAuth(t, func(context.Context, *http.Client, *falcon.ApiConfig) error { return nil })
	cfg := &config.Config{
		ClientID:     "id",
		ClientSecret: "secret",
		Cloud:        "us-2",
	}
	c, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New without proxy: %v", err)
	}
	if c == nil {
		t.Fatal("New returned nil client")
	}
}

// TestNewPropagatesAuthFailure verifies that a failed eager token exchange
// aborts New with ErrAuthenticationFailed so serve start fails fast.
func TestNewPropagatesAuthFailure(t *testing.T) {
	const secret = "supersecretclientsecretvalue0000000001"
	stubAuth(t, func(context.Context, *http.Client, *falcon.ApiConfig) error {
		return fmtAuth401()
	})
	cfg := &config.Config{
		ClientID:     "id",
		ClientSecret: secret,
		Cloud:        "us-2",
	}
	_, err := New(context.Background(), cfg)
	if err == nil {
		t.Fatal("New: expected authentication error, got nil")
	}
	if !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("New error = %v, want errors.Is(..., ErrAuthenticationFailed)", err)
	}
	// OAuth error_description may mention the word "client_secret"; the actual
	// credential value must never appear.
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("auth error must not include the client secret value: %v", err)
	}
}

func fmtAuth401() error {
	return formatAuthError(&oauth2.RetrieveError{
		Response:         &http.Response{StatusCode: http.StatusUnauthorized},
		ErrorCode:        "invalid_client",
		ErrorDescription: "Unknown client or invalid client_secret",
	}, &falcon.ApiConfig{HostOverride: "api.us-2.crowdstrike.com"})
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

// roundTripFunc is an http.RoundTripper adapter for tests.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func tokenJSONResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
}

// TestDoAuthenticateCredentialsSuccess exercises a successful client-credentials
// exchange via a fake transport. CrowdStrike returns 201 Created for tokens.
func TestDoAuthenticateCredentialsSuccess(t *testing.T) {
	t.Parallel()
	var sawToken bool
	httpClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/oauth2/token" {
			t.Fatalf("path = %q, want /oauth2/token", req.URL.Path)
		}
		if req.URL.Host != "api.us-2.crowdstrike.com" {
			t.Fatalf("host = %q, want api.us-2.crowdstrike.com", req.URL.Host)
		}
		if req.Method != http.MethodPost {
			t.Fatalf("method = %q, want POST", req.Method)
		}
		sawToken = true
		// 201 is what Falcon returns; oauth2 accepts any 2xx.
		return tokenJSONResponse(http.StatusCreated, `{"access_token":"tok","token_type":"bearer","expires_in":3600}`), nil
	})}
	ac := &falcon.ApiConfig{
		ClientId:     "id",
		ClientSecret: "secret",
		Cloud:        falcon.Cloud("us-2"),
	}
	if err := doAuthenticateCredentials(context.Background(), httpClient, ac); err != nil {
		t.Fatalf("doAuthenticateCredentials: %v", err)
	}
	if !sawToken {
		t.Fatal("expected token request")
	}
}

// TestDoAuthenticateCredentialsMemberCID verifies member_cid is posted as a
// form parameter so Flight Control credentials are validated the same way
// gofalcon will use them on first API call.
func TestDoAuthenticateCredentialsMemberCID(t *testing.T) {
	t.Parallel()
	const member = "0123456789abcdef0123456789abcdef"
	httpClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if err := req.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		if got := req.Form.Get("member_cid"); got != member {
			t.Fatalf("member_cid = %q, want %q", got, member)
		}
		return tokenJSONResponse(http.StatusCreated, `{"access_token":"tok","token_type":"bearer","expires_in":3600}`), nil
	})}
	ac := &falcon.ApiConfig{
		ClientId:     "id",
		ClientSecret: "secret",
		MemberCID:    member,
		Cloud:        falcon.Cloud("us-2"),
	}
	if err := doAuthenticateCredentials(context.Background(), httpClient, ac); err != nil {
		t.Fatalf("doAuthenticateCredentials: %v", err)
	}
}

// TestDoAuthenticateCredentialsUnauthorized verifies a 401 from the token
// endpoint becomes ErrAuthenticationFailed with a credential-check hint and no
// secret leakage.
func TestDoAuthenticateCredentialsUnauthorized(t *testing.T) {
	t.Parallel()
	const secret = "supersecretclientsecretvalue0000000001"
	httpClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return tokenJSONResponse(http.StatusUnauthorized, `{"error":"invalid_client","error_description":"Unknown client or invalid client_secret"}`), nil
	})}
	ac := &falcon.ApiConfig{
		ClientId:     "id",
		ClientSecret: secret,
		Cloud:        falcon.Cloud("us-2"),
	}
	err := doAuthenticateCredentials(context.Background(), httpClient, ac)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("error = %v, want errors.Is(..., ErrAuthenticationFailed)", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "HTTP 401") {
		t.Errorf("error should include HTTP 401: %s", msg)
	}
	if !strings.Contains(msg, "invalid_client") {
		t.Errorf("error should include OAuth error code: %s", msg)
	}
	if !strings.Contains(msg, "FALCON_CLIENT_ID") {
		t.Errorf("error should include credential-check hint: %s", msg)
	}
	if strings.Contains(msg, secret) {
		t.Errorf("error must not include client secret: %s", msg)
	}
}

// TestDoAuthenticateCredentialsForbiddenMemberCID verifies the 403 + member_cid
// hint path mirrors the Python auth_failure_message().
func TestDoAuthenticateCredentialsForbiddenMemberCID(t *testing.T) {
	t.Parallel()
	const member = "0123456789abcdef0123456789abcdef"
	httpClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return tokenJSONResponse(http.StatusForbidden, `{"error":"access_denied","error_description":"access denied, authorization failed"}`), nil
	})}
	ac := &falcon.ApiConfig{
		ClientId:     "id",
		ClientSecret: "secret",
		MemberCID:    member,
		Cloud:        falcon.Cloud("us-2"),
	}
	err := doAuthenticateCredentials(context.Background(), httpClient, ac)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("error = %v, want errors.Is(..., ErrAuthenticationFailed)", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "HTTP 403") {
		t.Errorf("error should include HTTP 403: %s", msg)
	}
	if !strings.Contains(msg, member) {
		t.Errorf("error should mention configured member_cid: %s", msg)
	}
	if !strings.Contains(msg, "child CID") {
		t.Errorf("error should include member_cid hint: %s", msg)
	}
}

// TestDoAuthenticateCredentialsEmptyToken treats a 2xx with no access_token as
// failure so a misbehaving endpoint cannot look like a successful start.
func TestDoAuthenticateCredentialsEmptyToken(t *testing.T) {
	t.Parallel()
	httpClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return tokenJSONResponse(http.StatusOK, `{"token_type":"bearer","expires_in":3600}`), nil
	})}
	ac := &falcon.ApiConfig{
		ClientId:     "id",
		ClientSecret: "secret",
		Cloud:        falcon.Cloud("us-2"),
	}
	err := doAuthenticateCredentials(context.Background(), httpClient, ac)
	if err == nil {
		t.Fatal("expected error for empty access_token")
	}
	if !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("error = %v, want errors.Is(..., ErrAuthenticationFailed)", err)
	}
}

// TestFormatAuthErrorNetworkHint verifies non-RetrieveError failures get the
// connectivity hint with the resolved host (no secret leakage).
func TestFormatAuthErrorNetworkHint(t *testing.T) {
	t.Parallel()
	ac := &falcon.ApiConfig{HostOverride: "api.example.invalid"}
	err := formatAuthError(errors.New("dial tcp: no such host"), ac)
	if !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("error = %v, want errors.Is(..., ErrAuthenticationFailed)", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "api.example.invalid") {
		t.Errorf("error should mention host: %s", msg)
	}
	if !strings.Contains(msg, "network connectivity") {
		t.Errorf("error should include connectivity hint: %s", msg)
	}
}

// TestDoAuthenticateCredentialsFalcon400Envelope verifies Falcon's MSA-style
// token error body (HTTP 400 + errors[].message, no RFC 6749 error field) is
// surfaced cleanly with a credential-check hint rather than a raw JSON dump.
func TestDoAuthenticateCredentialsFalcon400Envelope(t *testing.T) {
	t.Parallel()
	body := `{
  "meta": {"query_time": 0.001, "powered_by": "csam", "trace_id": "abc"},
  "errors": [{"code": 400, "message": "Failed to generate access token for clientID=id"}]
}`
	httpClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return tokenJSONResponse(http.StatusBadRequest, body), nil
	})}
	ac := &falcon.ApiConfig{
		ClientId:     "id",
		ClientSecret: "secret",
		Cloud:        falcon.Cloud("us-2"),
	}
	err := doAuthenticateCredentials(context.Background(), httpClient, ac)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("error = %v, want errors.Is(..., ErrAuthenticationFailed)", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "HTTP 400") {
		t.Errorf("error should include HTTP 400: %s", msg)
	}
	if !strings.Contains(msg, "Failed to generate access token") {
		t.Errorf("error should include Falcon errors[].message: %s", msg)
	}
	if strings.Contains(msg, "trace_id") || strings.Contains(msg, "powered_by") {
		t.Errorf("error should not dump full Falcon meta envelope: %s", msg)
	}
	if !strings.Contains(msg, "FALCON_CLIENT_ID") {
		t.Errorf("error should include credential-check hint for 400: %s", msg)
	}
}

// TestDoAuthenticateCredentialsUsesHostOverride ensures TokenURL targets the
// HostOverride FQDN (the FALCON_BASE_URL path) rather than the cloud default.
func TestDoAuthenticateCredentialsUsesHostOverride(t *testing.T) {
	t.Parallel()
	httpClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != "api.custom.example.com" {
			t.Fatalf("host = %q, want api.custom.example.com", req.URL.Host)
		}
		return tokenJSONResponse(http.StatusCreated, `{"access_token":"tok","token_type":"bearer","expires_in":3600}`), nil
	})}
	ac := &falcon.ApiConfig{
		ClientId:     "id",
		ClientSecret: "secret",
		Cloud:        falcon.Cloud("us-2"),
		HostOverride: "api.custom.example.com",
	}
	if err := doAuthenticateCredentials(context.Background(), httpClient, ac); err != nil {
		t.Fatalf("doAuthenticateCredentials: %v", err)
	}
}
