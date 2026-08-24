package base

import (
	"errors"
	"strings"
	"testing"
)

// TestCheckFilterSyntax exercises the classes CheckFilterSyntax accepts and
// rejects: balanced parens outside quotes pass, parens inside quotes are literal
// data, and a stray ), an unclosed (, or an unterminated quote are rejected as
// ErrInvalidFilter.
func TestCheckFilterSyntax(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"empty", "", false},
		{"simple term", "name:'chrome'", false},
		{"balanced group", "(a:'1',b:'2')", false},
		{"nested groups", "((a:'1'),(b:'2'))", false},
		{"paren inside quotes", "hostname:'foo)bar'", false},
		{"open paren inside quotes", "hostname:'foo(bar'", false},
		{"unmatched close", "a:'1')", true},
		{"unmatched close then comma", "a:'1'),b:'2'", true},
		{"unclosed open", "(a:'1'", true},
		{"unterminated quote", "name:'chrome", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := CheckFilterSyntax(tt.in)
			if tt.wantErr {
				if !errors.Is(err, ErrInvalidFilter) {
					t.Fatalf("CheckFilterSyntax(%q) err = %v, want ErrInvalidFilter", tt.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("CheckFilterSyntax(%q) = %v, want nil", tt.in, err)
			}
		})
	}
}

// TestScopeFilter verifies the scope is wrapped correctly, an empty caller filter
// yields the scope alone, and an unsafe filter is rejected without producing a
// filter string.
func TestScopeFilter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		scope   string
		filter  string
		want    string
		wantErr bool
	}{
		{"empty filter yields scope", "entity_type:'unmanaged'", "", "entity_type:'unmanaged'", false},
		{"wraps caller filter", "entity_type:'unmanaged'", "platform_name:'Windows'", "entity_type:'unmanaged'+(platform_name:'Windows')", false},
		{"rejects scope escape", "entity_type:'unmanaged'", "a:'1'),b:*", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ScopeFilter(tt.scope, tt.filter)
			if tt.wantErr {
				if !errors.Is(err, ErrInvalidFilter) {
					t.Fatalf("ScopeFilter err = %v, want ErrInvalidFilter", err)
				}
				if got != "" {
					t.Fatalf("ScopeFilter returned %q on rejection, want empty", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ScopeFilter = %v, want nil", err)
			}
			if got != tt.want {
				t.Fatalf("ScopeFilter = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestQuoteFQLValue verifies embedded backslashes and single quotes are escaped
// so caller data cannot terminate the FQL literal early.
func TestQuoteFQLValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "c1", `'c1'`},
		{"embedded quote", "c'1", `'c\'1'`},
		{"embedded backslash", `c\1`, `'c\\1'`},
		{"quote and backslash", `c\'1`, `'c\\\'1'`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := QuoteFQLValue(tt.in); got != tt.want {
				t.Fatalf("QuoteFQLValue(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// FuzzScopeFilterCannotEscapeScope asserts the security property: whenever
// ScopeFilter accepts a caller filter, the combined filter has no comma at paren
// depth zero, so every OR branch sits inside the scope's AND. A comma the caller
// supplies is safe only while it stays within the parens ScopeFilter wraps around
// the caller portion; a stray ) that closed that group early would surface a
// top-level comma, which this property would catch. hasTopLevelComma is written
// independently of CheckFilterSyntax so the fuzz target does not assert a function
// against its own logic.
func FuzzScopeFilterCannotEscapeScope(f *testing.F) {
	seeds := []string{"", "a:'1'", "(a:'1',b:'2')", "a:'1'),b:*", "name:'foo)bar'", "))", "((", "a,b", "'"}
	for _, s := range seeds {
		f.Add(s)
	}
	const scope = "entity_type:'unmanaged'"
	f.Fuzz(func(t *testing.T, userFilter string) {
		got, err := ScopeFilter(scope, userFilter)
		if err != nil {
			return
		}
		if userFilter == "" {
			if got != scope {
				t.Fatalf("empty filter: got %q, want %q", got, scope)
			}
			return
		}
		prefix := scope + "+("
		if !strings.HasPrefix(got, prefix) || !strings.HasSuffix(got, ")") {
			t.Fatalf("accepted filter %q not wrapped: %q", userFilter, got)
		}
		if hasTopLevelComma(got) {
			t.Fatalf("accepted filter %q escapes scope: %q has a top-level comma", userFilter, got)
		}
	})
}

// hasTopLevelComma reports whether s contains a comma at paren depth zero,
// ignoring commas inside single-quoted values. It is a deliberately independent
// reimplementation used only by the fuzz target.
func hasTopLevelComma(s string) bool {
	depth, quoted := 0, false
	for _, r := range s {
		switch {
		case r == '\'':
			quoted = !quoted
		case quoted:
			// Inside a quoted value: commas and parens are literal data.
		case r == '(':
			depth++
		case r == ')':
			depth--
		case r == ',' && depth == 0:
			return true
		}
	}
	return false
}
