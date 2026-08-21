// Package config parses and validates falcon-mcp server configuration. It
// validates resolved input values and returns a normalized Config; it never
// reads the environment or stores config in a package-level global. Env/flag/
// file resolution lives in the internal/cli package.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/crowdstrike/falcon-mcp/internal/version"
)

// defaultDetailFetchConcurrency bounds concurrent detail-fetch requests. The
// workload is network/API-bound (Falcon rate limits), not CPU-bound, so this is
// a small fixed default rather than a function of runtime.NumCPU().
const defaultDetailFetchConcurrency = 4

// Sentinel errors returned by Load. Use errors.Is for control flow.
var (
	// ErrMissingCredentials is returned when client id/secret are absent.
	ErrMissingCredentials = errors.New("config: client id and client secret are required")
	// ErrInvalidClientID is returned when the client id is present but not the
	// expected 32-character alphanumeric format.
	ErrInvalidClientID = errors.New("config: invalid client id format")
	// ErrInvalidClientSecret is returned when the client secret is present but
	// not the expected 40-character alphanumeric format.
	ErrInvalidClientSecret = errors.New("config: invalid client secret format")
	// ErrInvalidTransport is returned when the transport is not one of the
	// supported values.
	ErrInvalidTransport = errors.New("config: transport must be stdio, streamable-http, or sse")
	// ErrAddrRequired is returned when a network transport is selected without a
	// host and port.
	ErrAddrRequired = errors.New("config: host and port are required for a network transport")
	// ErrInvalidCloud is returned when the cloud region is present but not a
	// recognized value.
	ErrInvalidCloud = errors.New("config: invalid cloud region")
	// ErrInvalidMemberCID is returned when the member CID is present but malformed.
	ErrInvalidMemberCID = errors.New("config: invalid member cid")
	// ErrStatelessRequiresHTTP is returned when stateless-http is set but the
	// transport is not streamable-http. Stateless mode is a streamable-HTTP-only
	// feature.
	ErrStatelessRequiresHTTP = errors.New("config: stateless-http requires the streamable-http transport")
	// ErrAPIKeyRequiresHTTP is returned when api-key is set but the transport is
	// not streamable-http or sse. A static endpoint secret only guards a network
	// transport; it is meaningless for stdio.
	ErrAPIKeyRequiresHTTP = errors.New("config: api-key requires the streamable-http or sse transport")
	// ErrInvalidProxy is returned when a non-empty proxy value is not a usable
	// proxy URL (unparseable, missing scheme/host, or an unsupported scheme).
	ErrInvalidProxy = errors.New("config: invalid proxy url")
	// ErrInvalidHTTPTuning is returned when a connection-tuning value
	// (response-header timeout, idle timeout, or max idle connections per host)
	// is negative. Zero is accepted and replaced by the built-in default.
	ErrInvalidHTTPTuning = errors.New("config: invalid http tuning value")
	// ErrInvalidDebugAddr is returned when an ops endpoint address (health,
	// metrics, or pprof) is non-empty but not a valid host:port. The wrapped
	// message names which flag failed.
	ErrInvalidDebugAddr = errors.New("config: invalid ops endpoint address")
)

// Validation patterns, compiled once at package scope.
var (
	clientIDRE     = regexp.MustCompile(`^[a-zA-Z0-9]{32}$`)
	clientSecretRE = regexp.MustCompile(`^[a-zA-Z0-9]{40}$`)
	cloudRE        = regexp.MustCompile(`^(autodiscover|us-?1|us-?2|us-?3|eu-?1|us-?gov-?1|us-?gov-?2|gov-?1|gov-?2)$`)
	memberCIDRE    = regexp.MustCompile(`^[0-9a-fA-F]{32}(-[0-9a-fA-F]{2})?$`)
)

// Config is the server configuration. The cli package populates it from flags,
// env, and config files, then passes it to Load for validation and default
// normalization. Treat it as immutable after Load returns.
type Config struct {
	ClientID     string
	ClientSecret string
	Cloud        string
	HostOverride string
	MemberCID    string
	// Proxy is an optional outbound HTTP/HTTPS proxy URL for Falcon API calls.
	// When set it forces both the OAuth token exchange and all API traffic
	// through the proxy. When empty, the default transport is used, which honors
	// the HTTPS_PROXY/HTTP_PROXY/NO_PROXY environment variables.
	Proxy     string
	Transport string
	HTTPAddr  string
	// HealthAddr is the listen address for the /healthz liveness endpoint. Empty
	// disables it. It is independent of HTTPAddr and works under any transport,
	// including stdio.
	HealthAddr string
	// MetricsAddr is the listen address for the /metrics endpoint, which serves
	// process, tool-call, and Falcon API metrics in Prometheus text exposition
	// format. Empty disables it. It is independent of HTTPAddr and works under any
	// transport, including stdio.
	MetricsAddr string
	// PprofAddr is the listen address for the /debug/pprof profiling endpoints.
	// Empty disables it. It is independent of HTTPAddr and works under any
	// transport, including stdio; bind it to a local-only address.
	PprofAddr string
	Hosted    bool
	// UserAgent is an optional caller-supplied string appended to the API
	// User-Agent header. Load composes the final value; see composeUserAgent.
	UserAgent string
	// Dynamic exposes only the three meta-tools (falcon_search_tools,
	// falcon_execute_tool, falcon_list_enabled_modules) instead of every
	// module's tools, so clients discover tools on demand and pay each tool's
	// schema cost only when they call it. Off by default.
	Dynamic bool
	// StatelessHTTP runs the http transport in stateless mode: no
	// Mcp-Session-Id tracking, a fresh temporary session per request. Intended
	// for horizontally-scaled deployments. Only meaningful with transport
	// "streamable-http".
	StatelessHTTP          bool
	DetailFetchConcurrency int
	// APIKey is an optional static shared secret. When non-empty, the http and
	// sse transports require it in the x-api-key request header; empty disables
	// endpoint auth. It authenticates clients to this server and is unrelated to
	// the Falcon OAuth credentials (ClientID/ClientSecret), which authenticate
	// this server to CrowdStrike.
	APIKey string
	// Modules is an allowlist of module names to enable; empty enables all.
	// config normalizes this list but does not validate names against the real
	// module set — that authority belongs to the mcpserver package.
	Modules []string
	// KeepAlive is the interval at which the server pings idle sessions to detect
	// dead peers and hold long-lived connections open. Zero (the default)
	// disables keepalive. It is only meaningful for the http and sse transports;
	// stdio ignores it.
	KeepAlive time.Duration
	// ResponseHeaderTimeout bounds how long the Falcon API client waits for an
	// upstream's response headers after writing a request. Zero selects
	// defaultResponseHeaderTimeout; a negative value is rejected by Load.
	ResponseHeaderTimeout time.Duration
	// IdleTimeout bounds how long an idle keep-alive connection is kept open by
	// the http/sse server before being reaped. Zero selects defaultIdleTimeout;
	// a negative value is rejected by Load. Ignored by the stdio transport.
	IdleTimeout time.Duration
	// MaxIdleConnsPerHost caps idle Falcon API connections retained per host.
	// Zero selects defaultMaxIdleConnsPerHost; a negative value is rejected by
	// Load.
	MaxIdleConnsPerHost int
}

// Load validates cfg, applies defaults, and returns the normalized Config. It
// fails fast when required credentials are missing or a field is malformed.
func Load(cfg Config) (*Config, error) {
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, ErrMissingCredentials
	}
	if !clientIDRE.MatchString(cfg.ClientID) {
		return nil, fmt.Errorf("%w: expected 32 alphanumeric characters", ErrInvalidClientID)
	}
	if !clientSecretRE.MatchString(cfg.ClientSecret) {
		return nil, fmt.Errorf("%w: expected 40 alphanumeric characters", ErrInvalidClientSecret)
	}

	if cfg.Transport == "" {
		cfg.Transport = "stdio"
	}
	switch cfg.Transport {
	case "stdio", "streamable-http", "sse":
	default:
		return nil, ErrInvalidTransport
	}
	if cfg.Transport != "stdio" && cfg.HTTPAddr == "" {
		return nil, fmt.Errorf("%w, got %q", ErrAddrRequired, cfg.Transport)
	}
	if cfg.StatelessHTTP && cfg.Transport != "streamable-http" {
		return nil, fmt.Errorf("%w, got %q", ErrStatelessRequiresHTTP, cfg.Transport)
	}
	if cfg.APIKey != "" && cfg.Transport == "stdio" {
		return nil, fmt.Errorf("%w, got %q", ErrAPIKeyRequiresHTTP, cfg.Transport)
	}

	if err := matchOrEmpty(cloudRE, ErrInvalidCloud, cfg.Cloud); err != nil {
		return nil, err
	}
	cfg.MemberCID = strings.TrimSpace(cfg.MemberCID)
	if err := matchOrEmpty(memberCIDRE, ErrInvalidMemberCID, cfg.MemberCID); err != nil {
		return nil, err
	}
	cfg.MemberCID = normalizeMemberCID(cfg.MemberCID)

	cfg.Proxy = strings.TrimSpace(cfg.Proxy)
	if err := validateProxy(cfg.Proxy); err != nil {
		return nil, err
	}

	if cfg.DetailFetchConcurrency == 0 {
		cfg.DetailFetchConcurrency = defaultDetailFetchConcurrency
	}

	if err := validateHTTPTuning(&cfg); err != nil {
		return nil, err
	}

	if err := validateOpsAddrs(&cfg); err != nil {
		return nil, err
	}

	cfg.Modules = normalizeModules(cfg.Modules)

	cfg.HostOverride = normalizeHostOverride(cfg.HostOverride)

	cfg.UserAgent = composeUserAgent(cfg.UserAgent)

	return &cfg, nil
}

// validateHTTPTuning rejects a negative connection-tuning value (fail fast).
// Defaults are supplied by the cli flag definitions, so Load does not
// substitute them here; it only guards against a value that has no valid
// meaning and, if passed through, would silently disable the very protection
// the value exists to provide.
func validateHTTPTuning(cfg *Config) error {
	if cfg.ResponseHeaderTimeout < 0 {
		return fmt.Errorf("%w: response-header timeout %v must not be negative", ErrInvalidHTTPTuning, cfg.ResponseHeaderTimeout)
	}
	if cfg.IdleTimeout < 0 {
		return fmt.Errorf("%w: idle timeout %v must not be negative", ErrInvalidHTTPTuning, cfg.IdleTimeout)
	}
	if cfg.MaxIdleConnsPerHost < 0 {
		return fmt.Errorf("%w: max idle connections per host %d must not be negative", ErrInvalidHTTPTuning, cfg.MaxIdleConnsPerHost)
	}
	return nil
}

// validateOpsAddrs rejects an ops endpoint address that is not a bindable
// host:port (fail fast). Each address is optional; an empty value disables that
// endpoint. A non-empty value must split into host:port and carry a numeric
// port in the 0-65535 range, so a value that passes here cannot fail to bind
// merely because it was malformed. The error names the flag that failed.
func validateOpsAddrs(cfg *Config) error {
	for _, a := range []struct{ flag, addr string }{
		{"health-addr", cfg.HealthAddr},
		{"metrics-addr", cfg.MetricsAddr},
		{"pprof-addr", cfg.PprofAddr},
	} {
		if a.addr == "" {
			continue
		}
		_, port, err := net.SplitHostPort(a.addr)
		if err != nil {
			return fmt.Errorf("%w: %s %q: %w", ErrInvalidDebugAddr, a.flag, a.addr, err)
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 0 || n > 65535 {
			return fmt.Errorf("%w: %s %q: port must be a number in 0-65535", ErrInvalidDebugAddr, a.flag, a.addr)
		}
	}
	return nil
}

// normalizeHostOverride reduces a base-URL value to the bare FQDN that gofalcon's
// ApiConfig.HostOverride expects. gofalcon builds "https://" + Host() + "/oauth2/token"
// and uses Host() as the transport host, so a scheme or path in the value would
// break it. The env var is named FALCON_BASE_URL, which invites a full URL like
// "https://api.us-2.crowdstrike.com/", so we strip any scheme and path and keep
// only the host. An input that is already a bare host passes through unchanged.
func normalizeHostOverride(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	// url.Parse only populates Host when a scheme is present; add one for a bare
	// "host/path" input so the path is stripped consistently.
	toParse := host
	if !strings.Contains(host, "://") {
		toParse = "https://" + host
	}
	if u, err := url.Parse(toParse); err == nil && u.Host != "" {
		return u.Host
	}
	return host
}

// validateProxy checks a non-empty proxy value. It must parse as an absolute URL
// with a host and one of the supported schemes (http, https, socks5). An empty
// value is valid: it selects the default transport, which honors the
// HTTPS_PROXY/NO_PROXY environment variables. The value is not stored parsed;
// falconapi re-parses it when building the client.
func validateProxy(proxy string) error {
	if proxy == "" {
		return nil
	}
	u, err := url.Parse(proxy)
	if err != nil {
		return fmt.Errorf("%w %q: %w", ErrInvalidProxy, proxy, err)
	}
	switch u.Scheme {
	case "http", "https", "socks5":
	default:
		return fmt.Errorf("%w %q: scheme must be http, https, or socks5", ErrInvalidProxy, proxy)
	}
	if u.Host == "" {
		return fmt.Errorf("%w %q: missing host", ErrInvalidProxy, proxy)
	}
	return nil
}

// composeUserAgent builds the User-Agent value sent to the Falcon API. It always
// leads with falcon-mcp/<version> and appends the caller-supplied string when
// present.
func composeUserAgent(user string) string {
	if user = strings.TrimSpace(user); user != "" {
		return fmt.Sprintf("falcon-mcp/%s %s", version.Version, user)
	}
	return fmt.Sprintf("falcon-mcp/%s", version.Version)
}

// normalizeModules trims each module name and drops empty entries, returning nil
// when nothing remains. It does not validate names against the real module set:
// config must not import mcpserver, which is the sole authority on valid names.
func normalizeModules(names []string) []string {
	var out []string
	for _, n := range names {
		if n = strings.TrimSpace(n); n != "" {
			out = append(out, n)
		}
	}
	return out
}

// normalizeMemberCID reduces a validated member CID to its bare 32-character
// form. The value may be supplied with a trailing "-XX" checksum suffix, which
// gofalcon's ApiConfig.MemberCID does not expect, so the suffix is dropped. An
// empty value passes through unchanged. The caller must validate against
// memberCIDRE first; this assumes a well-formed input.
func normalizeMemberCID(cid string) string {
	if len(cid) >= 32 {
		return cid[:32]
	}
	return cid
}

// matchOrEmpty reports nil when s is empty or matches re, else sentinel wrapped
// with the offending value.
func matchOrEmpty(re *regexp.Regexp, sentinel error, s string) error {
	if s == "" || re.MatchString(s) {
		return nil
	}
	return fmt.Errorf("%w %q", sentinel, s)
}
