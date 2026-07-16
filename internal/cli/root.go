// Package cli owns the falcon-mcp command-line interface. It is the sole owner
// of cobra and a local viper instance: it resolves configuration values
// (precedence flag > env > config file > default), applies INI/falcon_-prefix
// normalization, and produces a plain config.Input. It imports config but
// config never imports cli — viper/cobra do not leak into the domain package.
package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-viper/encoding/ini"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/crowdstrike/falcon-mcp/internal/config"
	"github.com/crowdstrike/falcon-mcp/internal/version"
)

var (
	progName   = "falcon-mcp"
	cliVersion = fmt.Sprintf("%s %s <commit: %s>", progName, version.Version, version.Commit)
)

// ErrInvalidLogFormat is returned when --log-format is not "text" or "json".
var ErrInvalidLogFormat = errors.New("cli: invalid log format")

// Execute is the process entry point for falcon-mcp. It derives a context
// cancelled on os.Interrupt (so the http/sse transports drain gracefully on
// Ctrl+C), builds the root command, and runs it. preRunE installs the logger,
// at debug level when --debug is set and INFO otherwise.
func Execute() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	return newRootCmd().ExecuteContext(ctx)
}

// newLogger returns the process's logger emitting to stderr at level. format
// selects the handler: "json" emits JSON, anything else emits text.
func newLogger(level slog.Level, format string) *slog.Logger {
	opts := &slog.HandlerOptions{Level: level}
	if format == "json" {
		return slog.New(slog.NewJSONHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}

// newRootCmd builds the falcon-mcp root command. preRunE resolves the config
// once; runE serves it. cfg is the only state shared between the two phases —
// a single local held here and passed to each phase keeps it off package
// globals without a wrapper type or double indirection.
func newRootCmd() *cobra.Command {
	var cfg *config.Config

	cmd := &cobra.Command{
		Use:   progName,
		Short: "CrowdStrike Falcon MCP server",
		Long: `The CrowdStrike Falcon MCP server is a Model Context Protocol (MCP) server that connects AI agents
to the CrowdStrike Falcon platform, exposing detections, threat intelligence,
host management, and more as MCP tools.

It serves over stdio by default; the streamable-http and sse transports listen
on a network address but serve a single credential set (not multi-tenant).
Configuration precedence is flag > env > config file > default.`,
		Example: `  # stdio (default), credentials from the environment
  export FALCON_CLIENT_ID=... FALCON_CLIENT_SECRET=...
  falcon-mcp

  # streamable-http transport on all interfaces, port 8000
  falcon-mcp -t streamable-http --host 0.0.0.0 -p 8000

  # enable only specific modules
  falcon-mcp -m detections,intel,hosts`,
		Version: cliVersion,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			c, err := preRunE(cmd)
			cfg = c
			return err
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runE(cmd.Context(), cfg)
		},
	}

	registerFlags(cmd)
	return cmd
}

// preRunE resolves configuration: when --debug is set it reinstalls the logger
// at debug level, then builds a fresh viper from cmd's flags and the
// environment, reads any config file (explicit --config or discovery),
// normalizes falcon_-prefixed keys, and loads the validated config. viper is
// scoped to this call so each invocation is independent (hermetic tests). Flags
// have parsed cleanly by PreRunE, so any error here is a config error, not a
// usage error.
func preRunE(cmd *cobra.Command) (*config.Config, error) {
	v, err := newViper()
	if err != nil {
		return nil, err
	}
	bindFlags(v, cmd)
	bindEnv(v)

	// Resolve debug through viper so it honors the same flag > env precedence as
	// every other key, then install the logger before config-file discovery so
	// that work logs at the requested level. The handler is always installed (not
	// only under --debug) so the log format stays identical regardless of the
	// flag; only the level changes.
	level := slog.LevelInfo
	if v.GetBool("debug") {
		level = slog.LevelDebug
	}
	logFormat := v.GetString("log_format")
	if logFormat != "text" && logFormat != "json" {
		return nil, fmt.Errorf("%w %q", ErrInvalidLogFormat, logFormat)
	}
	slog.SetDefault(newLogger(level, logFormat))

	cfgFile, _ := cmd.Flags().GetString("config")
	if err := readConfigFile(v, cfgFile); err != nil {
		return nil, err
	}

	// Merge ./.env after the config file: ReadInConfig replaces viper's config
	// map, so .env must be merged onto it rather than before it. Merging (not
	// replacing) lets .env and a discovered config file coexist.
	if err := mergeDotEnv(v); err != nil {
		return nil, err
	}
	normalizeFalconPrefix(v)

	cfg, err := config.Load(resolve(v))
	if err != nil {
		return nil, err
	}

	if cfg.Hosted {
		slog.Warn("hosted mode not yet implemented; serving with single credential set",
			"transport", cfg.Transport)
	}
	return cfg, nil
}

// runE serves the config that preRunE resolved over the configured transport.
func runE(ctx context.Context, cfg *config.Config) error {
	return serve(ctx, cfg)
}

// registerFlags declares the falcon-mcp flags on cmd. --config is intentionally
// not bound to a viper key: it names the file to read, it is not a config value.
func registerFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.String("config", "", "path to a config file")
	f.BoolP("debug", "d", false, "enable debug-level logging")
	f.String("log-format", "text", "log output format: text or json")
	f.String("client-id", "", "Falcon OAuth2 client id")
	f.String("client-secret", "", "Falcon OAuth2 client secret")
	f.String("cloud", "autodiscover", "Falcon cloud region: autodiscover, us-1, us-2, eu-1, us-gov-1, etc.")
	f.String("base-url", "", "Falcon API base URL; overrides --cloud")
	f.String("member-cid", "", "MSSP member CID selector")
	f.String("proxy", "", "outbound HTTP/HTTPS proxy URL for Falcon API calls")
	f.StringP("transport", "t", "stdio", "transport: stdio, streamable-http, or sse.")
	f.String("host", "127.0.0.1", "host to bind for the http and sse transports")
	f.IntP("port", "p", 8000, "port to listen on for the http and sse transports")
	f.Bool("hosted", false, "reserved; logs a warning and proceeds as single-credential (not yet implemented)")
	f.String("user-agent", "", "Custom user agent appended to API requests")
	f.Bool("dynamic", false, "expose only the 3 meta-tools (falcon_search_tools/execute_tool/list_enabled_modules) instead of all tools")
	f.Bool("stateless-http", false, "run the streamable-http transport in stateless mode")
	f.String("api-key", "", "static secret required in the x-api-key header for http/sse clients")
	f.StringSliceP("modules", "m", nil, "a specific set of modules to enable (comma-separated)")
	f.Duration("keep-alive", 0, "interval to ping idle sessions and hold long-lived http/sse connections open")
	f.Duration("api-response-timeout", 30*time.Second, "max wait for Falcon API response headers before a request is abandoned; raise for heavy FQL queries")
	f.Duration("http-idle-timeout", 120*time.Second, "max time an idle keep-alive http/sse connection is held open before reaping")
	f.Int("max-idle-conns-per-host", 100, "idle Falcon API connections retained per host")

	// Alias --user-agent-comment to the canonical --user-agent flag. Normalizing
	// the input name (rather than declaring a second flag) means bindFlags's
	// VisitAll still sees only user-agent, so viper binding is unchanged. This
	// matches upstream falcon-mcp's --user-agent-comment naming.
	f.SetNormalizeFunc(func(_ *pflag.FlagSet, name string) pflag.NormalizedName {
		if name == "user-agent-comment" {
			name = "user-agent"
		}
		return pflag.NormalizedName(name)
	})
}

// bindFlags binds every flag on cmd to a viper key, converting dashes to
// underscores (client-id -> client_id). This gives flags highest precedence
// while env/file resolution flows through the same keys, all on the local viper
// instance. --config is excluded: it names the file to read, not a config value.
func bindFlags(v *viper.Viper, cmd *cobra.Command) {
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if f.Name == "config" {
			return
		}
		key := strings.ReplaceAll(f.Name, "-", "_")
		_ = v.BindPFlag(key, f)
	})
}

// bindEnv wires each viper key to its explicit environment variable name(s).
// It replaces viper's AutomaticEnv/SetEnvPrefix mechanism because that supports
// only a single prefix, whereas this command splits env vars across two: the
// gofalcon-standard FALCON_ prefix for credentials and connection settings, and
// FALCON_MCP_ for this server's own operational settings. When BindEnv is given
// explicit names, viper uses them verbatim and ignores any configured prefix, so
// the two families coexist. FALCON_MCP_USER_AGENT wins over the upstream
// FALCON_USER_AGENT_COMMENT alias when both are set (first name listed wins).
func bindEnv(v *viper.Viper) {
	// Credentials and connection settings keep the gofalcon-standard FALCON_
	// prefix that users and CI already export.
	_ = v.BindEnv("client_id", "FALCON_CLIENT_ID")
	_ = v.BindEnv("client_secret", "FALCON_CLIENT_SECRET")
	_ = v.BindEnv("cloud", "FALCON_CLOUD")
	_ = v.BindEnv("member_cid", "FALCON_MEMBER_CID")
	_ = v.BindEnv("base_url", "FALCON_BASE_URL")
	_ = v.BindEnv("user_agent", "FALCON_MCP_USER_AGENT", "FALCON_MCP_USER_AGENT_COMMENT")

	// This server's own operational settings live under FALCON_MCP_, matching
	// upstream falcon-mcp (e.g. FALCON_MCP_DYNAMIC).
	_ = v.BindEnv("transport", "FALCON_MCP_TRANSPORT")
	_ = v.BindEnv("debug", "FALCON_MCP_DEBUG")
	_ = v.BindEnv("log_format", "FALCON_MCP_LOG_FORMAT")
	_ = v.BindEnv("host", "FALCON_MCP_HOST")
	_ = v.BindEnv("port", "FALCON_MCP_PORT")
	_ = v.BindEnv("hosted", "FALCON_MCP_HOSTED")
	_ = v.BindEnv("dynamic", "FALCON_MCP_DYNAMIC")
	_ = v.BindEnv("stateless_http", "FALCON_MCP_STATELESS_HTTP")
	_ = v.BindEnv("api_key", "FALCON_MCP_API_KEY")
	_ = v.BindEnv("modules", "FALCON_MCP_MODULES")
	// FALCON_MCP_PROXY is this server's own name; FALCON_PROXY_URL is the upstream
	// falcon-mcp alias, accepted so existing Python configs keep working.
	_ = v.BindEnv("proxy", "FALCON_MCP_PROXY", "FALCON_PROXY_URL")
	_ = v.BindEnv("keep_alive", "FALCON_MCP_KEEP_ALIVE")
	_ = v.BindEnv("api_response_timeout", "FALCON_MCP_API_RESPONSE_TIMEOUT")
	_ = v.BindEnv("http_idle_timeout", "FALCON_MCP_HTTP_IDLE_TIMEOUT")
	_ = v.BindEnv("max_idle_conns_per_host", "FALCON_MCP_MAX_IDLE_CONNS_PER_HOST")
}

// newViper returns a viper instance with the INI codec registered. viper v1.20+
// dropped INI/HCL/properties from core to shed third-party deps; the codec now
// lives in github.com/go-viper/encoding/ini and must be registered explicitly.
// (WHY: an INI config file may carry a [falcon] section — see hoistFalconSection.)
func newViper() (*viper.Viper, error) {
	registry := viper.NewCodecRegistry()
	if err := registry.RegisterCodec("ini", ini.Codec{}); err != nil {
		return nil, fmt.Errorf("register ini codec: %w", err)
	}
	return viper.NewWithOptions(viper.WithCodecRegistry(registry)), nil
}

// resolve reads the resolved viper keys into a config.Config. It performs no
// I/O; v must already be populated (flags bound, env enabled, file read).
func resolve(v *viper.Viper) config.Config {
	return config.Config{
		ClientID:      v.GetString("client_id"),
		ClientSecret:  v.GetString("client_secret"),
		Cloud:         v.GetString("cloud"),
		HostOverride:  v.GetString("base_url"),
		MemberCID:     v.GetString("member_cid"),
		Proxy:         v.GetString("proxy"),
		Transport:     v.GetString("transport"),
		HTTPAddr:      net.JoinHostPort(v.GetString("host"), strconv.Itoa(v.GetInt("port"))),
		Hosted:        v.GetBool("hosted"),
		Dynamic:       v.GetBool("dynamic"),
		StatelessHTTP: v.GetBool("stateless_http"),
		APIKey:        v.GetString("api_key"),
		Modules:       v.GetStringSlice("modules"),
		UserAgent:     v.GetString("user_agent"),
		KeepAlive:     v.GetDuration("keep_alive"),

		ResponseHeaderTimeout: v.GetDuration("api_response_timeout"),
		IdleTimeout:           v.GetDuration("http_idle_timeout"),
		MaxIdleConnsPerHost:   v.GetInt("max_idle_conns_per_host"),
	}
}

// searchPaths returns the directories scanned for a config file named
// "falcon-mcp" when no explicit --config path is given, in precedence order.
func searchPaths() []string {
	paths := []string{"."}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		paths = append(paths, filepath.Join(xdg, "falcon-mcp"))
	} else if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".config", "falcon-mcp"))
	}
	return append(paths, "/etc/falcon-mcp")
}

// readConfigFile loads a config file into v. When path is non-empty it is an
// explicit file that must exist — a missing file is an error. When path is
// empty, v searches the standard locations for a "falcon-mcp" file and a
// not-found result is not an error. After a successful read the [falcon] INI
// section (if any) is hoisted to top-level keys.
func readConfigFile(v *viper.Viper, path string) error {
	if path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			return fmt.Errorf("read config %s: %w", path, err)
		}
		hoistFalconSection(v)
		return nil
	}

	v.SetConfigName("falcon-mcp")
	for _, p := range searchPaths() {
		v.AddConfigPath(p)
	}
	if err := v.ReadInConfig(); err != nil {
		var nf viper.ConfigFileNotFoundError
		if errors.As(err, &nf) {
			return nil // no config file on the search paths is fine
		}
		return fmt.Errorf("read config: %w", err)
	}
	hoistFalconSection(v)
	return nil
}

// mergeDotEnv merges ./.env (if present) into v as an "env"-format config layer.
// .env is a dotfile that viper's name-based discovery does not find, so it is
// loaded explicitly. A missing file is not an error. MergeConfig merges onto the
// existing config map rather than replacing it (as ReadInConfig would), so .env
// and a discovered config file coexist; env vars and flags still outrank both,
// matching python-dotenv's non-overriding load_dotenv.
func mergeDotEnv(v *viper.Viper) error {
	f, err := os.Open(".env")
	if err != nil {
		return nil // no .env is fine
	}
	defer f.Close()

	v.SetConfigType("env")
	if err := v.MergeConfig(f); err != nil {
		return fmt.Errorf("merge .env: %w", err)
	}
	return nil
}

// hoistFalconSection promotes an INI [falcon] section's keys to top-level
// keys, without overwriting values already set at the top level. (WHY: INI
// namespaces keys under the section header, so [falcon] client_id must be
// hoisted to client_id to resolve like every other key.)
func hoistFalconSection(v *viper.Viper) {
	sub := v.Sub("falcon")
	if sub == nil {
		return
	}
	for k, val := range sub.AllSettings() {
		if !v.IsSet(k) {
			v.Set(k, val)
		}
	}
}

// normalizeFalconPrefix strips a leading "falcon_" from any key, setting the
// stripped key only when it is not already set (non-prefixed wins). This lets a
// config file use falcon_client_id (matching the FALCON_CLIENT_ID env var)
// interchangeably with the bare client_id key.
func normalizeFalconPrefix(v *viper.Viper) {
	for k, val := range v.AllSettings() {
		stripped, ok := strings.CutPrefix(k, "falcon_")
		if !ok || stripped == "" {
			continue
		}
		if !v.IsSet(stripped) {
			v.Set(stripped, val)
		}
	}
}
