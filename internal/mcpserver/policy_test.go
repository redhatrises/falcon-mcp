package mcpserver

import (
	"errors"
	"testing"

	"github.com/crowdstrike/falcon-mcp/internal/config"
)

// TestToolPolicyKeeps exercises the per-tool inclusion decision across the
// module gate, allow-list, deny-list, and read-only switch, including their
// precedence interactions (read-only overrides the allow-list; the deny-list
// overrides the allow-list).
func TestToolPolicyKeeps(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		cfg          config.Config
		tool         string
		module       string
		readOnlyHint bool
		want         bool
	}{
		{
			name:         "no filters keeps read-only tool",
			cfg:          config.Config{},
			tool:         "falcon_search_hosts",
			module:       "hosts",
			readOnlyHint: true,
			want:         true,
		},
		{
			name:         "no filters keeps mutating tool",
			cfg:          config.Config{},
			tool:         "falcon_add_ioc",
			module:       "ioc",
			readOnlyHint: false,
			want:         true,
		},
		{
			name:         "module gate drops tool outside enabled modules",
			cfg:          config.Config{Modules: []string{"hosts"}},
			tool:         "falcon_search_detections",
			module:       "detections",
			readOnlyHint: true,
			want:         false,
		},
		{
			name:         "module gate keeps tool inside enabled modules",
			cfg:          config.Config{Modules: []string{"hosts"}},
			tool:         "falcon_search_hosts",
			module:       "hosts",
			readOnlyHint: true,
			want:         true,
		},
		{
			name:         "allow-list keeps named tool from module outside --modules",
			cfg:          config.Config{Modules: []string{"hosts"}, Tools: []string{"falcon_search_detections"}},
			tool:         "falcon_search_detections",
			module:       "detections",
			readOnlyHint: true,
			want:         true,
		},
		{
			name:         "allow-list-only mode drops unnamed tool",
			cfg:          config.Config{Tools: []string{"falcon_search_hosts"}},
			tool:         "falcon_search_detections",
			module:       "detections",
			readOnlyHint: true,
			want:         false,
		},
		{
			name:         "allow-list-only mode keeps named tool",
			cfg:          config.Config{Tools: []string{"falcon_search_hosts"}},
			tool:         "falcon_search_hosts",
			module:       "hosts",
			readOnlyHint: true,
			want:         true,
		},
		{
			name:         "deny-list drops named tool",
			cfg:          config.Config{ExcludeTools: []string{"falcon_add_ioc"}},
			tool:         "falcon_add_ioc",
			module:       "ioc",
			readOnlyHint: false,
			want:         false,
		},
		{
			name:         "deny-list overrides allow-list",
			cfg:          config.Config{Tools: []string{"falcon_add_ioc"}, ExcludeTools: []string{"falcon_add_ioc"}},
			tool:         "falcon_add_ioc",
			module:       "ioc",
			readOnlyHint: false,
			want:         false,
		},
		{
			name:         "read-only drops mutating tool",
			cfg:          config.Config{ReadOnly: true},
			tool:         "falcon_add_ioc",
			module:       "ioc",
			readOnlyHint: false,
			want:         false,
		},
		{
			name:         "read-only keeps read-only tool",
			cfg:          config.Config{ReadOnly: true},
			tool:         "falcon_search_hosts",
			module:       "hosts",
			readOnlyHint: true,
			want:         true,
		},
		{
			name:         "read-only overrides allow-listed mutating tool",
			cfg:          config.Config{ReadOnly: true, Tools: []string{"falcon_add_ioc"}},
			tool:         "falcon_add_ioc",
			module:       "ioc",
			readOnlyHint: false,
			want:         false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := newToolPolicy(&tt.cfg)
			if got := p.keeps(tt.tool, tt.module, tt.readOnlyHint); got != tt.want {
				t.Errorf("keeps(%q, %q, ro=%v) = %v, want %v", tt.tool, tt.module, tt.readOnlyHint, got, tt.want)
			}
		})
	}
}

// TestToolPolicyActiveAndDescribe verifies the human-readable filter summary and
// the active() predicate that gates it.
func TestToolPolicyActiveAndDescribe(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		cfg          config.Config
		wantActive   bool
		wantDescribe string
	}{
		{
			name:         "no filters",
			cfg:          config.Config{},
			wantActive:   false,
			wantDescribe: "none",
		},
		{
			name:         "module gate alone is not a filter",
			cfg:          config.Config{Modules: []string{"hosts"}},
			wantActive:   false,
			wantDescribe: "none",
		},
		{
			name:         "read-only only",
			cfg:          config.Config{ReadOnly: true},
			wantActive:   true,
			wantDescribe: "read-only",
		},
		{
			name:         "allow-list only",
			cfg:          config.Config{Tools: []string{"falcon_search_hosts", "falcon_search_detections"}},
			wantActive:   true,
			wantDescribe: "allow-list (2 named)",
		},
		{
			name:         "deny-list only",
			cfg:          config.Config{ExcludeTools: []string{"falcon_add_ioc"}},
			wantActive:   true,
			wantDescribe: "deny-list (1 named)",
		},
		{
			name:         "all three combined",
			cfg:          config.Config{ReadOnly: true, Tools: []string{"falcon_search_hosts"}, ExcludeTools: []string{"falcon_add_ioc"}},
			wantActive:   true,
			wantDescribe: "read-only, allow-list (1 named), deny-list (1 named)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := newToolPolicy(&tt.cfg)
			if got := p.active(); got != tt.wantActive {
				t.Errorf("active() = %v, want %v", got, tt.wantActive)
			}
			if got := p.describe(); got != tt.wantDescribe {
				t.Errorf("describe() = %q, want %q", got, tt.wantDescribe)
			}
		})
	}
}

// TestValidateToolNames confirms allow/deny-list names are validated against the
// full seen set, that unknown names surface a sorted ErrUnknownToolName, and
// that known names pass.
func TestValidateToolNames(t *testing.T) {
	t.Parallel()
	seen := map[string]string{
		"falcon_search_hosts": "hosts",
		"falcon_add_ioc":      "ioc",
	}

	t.Run("all known", func(t *testing.T) {
		t.Parallel()
		p := newToolPolicy(&config.Config{Tools: []string{"falcon_search_hosts"}, ExcludeTools: []string{"falcon_add_ioc"}})
		if err := p.validateToolNames(seen); err != nil {
			t.Fatalf("validateToolNames: %v", err)
		}
	})

	t.Run("unknown allow-list name", func(t *testing.T) {
		t.Parallel()
		p := newToolPolicy(&config.Config{Tools: []string{"falcon_no_such_tool"}})
		err := p.validateToolNames(seen)
		if !errors.Is(err, ErrUnknownToolName) {
			t.Fatalf("err = %v, want ErrUnknownToolName", err)
		}
	})

	t.Run("unknown deny-list name", func(t *testing.T) {
		t.Parallel()
		p := newToolPolicy(&config.Config{ExcludeTools: []string{"falcon_ghost"}})
		err := p.validateToolNames(seen)
		if !errors.Is(err, ErrUnknownToolName) {
			t.Fatalf("err = %v, want ErrUnknownToolName", err)
		}
	})
}

// TestWithholdingRuleModuleGate verifies that a tool absent from the catalog is
// attributed to its module gate when its module is not enabled, and to the
// active filter otherwise. With --modules hosts --read-only, a read-only tool
// from a non-enabled module must not be blamed on read-only.
func TestWithholdingRuleModuleGate(t *testing.T) {
	t.Parallel()
	policy := newToolPolicy(&config.Config{Modules: []string{"hosts"}, ReadOnly: true})
	cat := &Catalog{
		byName: map[string]catalogEntry{
			"falcon_search_hosts": {},
		},
		seen: map[string]string{
			"falcon_search_hosts":        "hosts", // kept
			"falcon_search_iom_findings": "cloud", // dropped by module gate
			"falcon_kill_process":        "hosts", // dropped by read-only
		},
		policy: policy,
	}

	tests := []struct {
		name     string
		tool     string
		wantRule string
		wantOK   bool
	}{
		{"module gate", "falcon_search_iom_findings", "module not enabled", true},
		{"read-only filter", "falcon_kill_process", "read-only", true},
		{"kept tool", "falcon_search_hosts", "", false},
		{"never existed", "falcon_no_such_tool", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule, ok := cat.withholdingRule(tt.tool)
			if ok != tt.wantOK || rule != tt.wantRule {
				t.Errorf("withholdingRule(%q) = (%q, %v), want (%q, %v)", tt.tool, rule, ok, tt.wantRule, tt.wantOK)
			}
		})
	}
}
