package base

import (
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidFilter classifies a caller filter rejected client-side, before any
// request is built, so callers can distinguish it from an API error and surface
// it as a soft FQL result.
var ErrInvalidFilter = errors.New("invalid filter")

// ScopeFilter combines a mandatory scope clause with the caller's filter,
// rejecting a filter it cannot safely wrap. An empty caller filter yields the
// scope alone.
//
// The caller portion is parenthesized because FQL's , (OR) binds looser than +
// (AND): concatenating a caller filter that contains a top-level comma yields
// "scope+a,b", which the API groups as (scope AND a) OR b. The second branch
// carries no scope term, so it escapes the scoping contract the caller intends.
//
// Wrapping alone is not enough, which is why validation lives here rather than
// in the caller: a stray ) in the filter closes the wrapping group early and
// puts any following comma back at top level. Validating and wrapping in one
// function means there is no way to build a scoped filter without the check.
func ScopeFilter(scope, userFilter string) (string, error) {
	if userFilter == "" {
		return scope, nil
	}
	if err := CheckFilterSyntax(userFilter); err != nil {
		return "", err
	}
	return scope + "+(" + userFilter + ")", nil
}

// CheckFilterSyntax verifies s is safe to wrap in a parenthesized group: parens
// balance outside single-quoted values, and no quoted value is left open. It
// rejects both a ) that closes a group never opened and groups left open at the
// end. Parens inside quoted values are literal data, not grouping, so
// hostname:'foo)bar' is accepted.
//
// The no-prefix-deficit property is what makes wrapping safe: if no prefix of s
// holds more ) than (, the group ScopeFilter opens is never closed early, so a
// comma in s can never reach top level. An unterminated quote is rejected
// because it makes the paren depth unreliable in both directions.
//
// Only the stray-) class is a security boundary. The API silently accepts a
// scope-escaping filter with HTTP 200 and the widened result set (verified
// live), so that class must be caught here. It rejects the other classes itself
// with a 400 ("unmatched paren", "expected binary operator"); they are checked
// here to keep the depth model above sound, not because the API misses them.
func CheckFilterSyntax(s string) error {
	depth, quoted := 0, false
	for i, r := range s {
		if r == '\'' {
			quoted = !quoted
			continue
		}
		if quoted {
			// Inside a quoted value: parens are literal data.
			continue
		}
		switch r {
		case '(':
			depth++
		case ')':
			if depth == 0 {
				return fmt.Errorf("%w: %q has an unmatched ) at byte offset %d", ErrInvalidFilter, s, i)
			}
			depth--
		}
	}
	if quoted {
		return fmt.Errorf("%w: %q has an unterminated quoted value", ErrInvalidFilter, s)
	}
	if depth != 0 {
		return fmt.Errorf("%w: %q has %d unclosed (", ErrInvalidFilter, s, depth)
	}
	return nil
}

// fqlValueEscaper escapes the characters that would let a value break out of an
// FQL single-quoted literal: a backslash (so an escape sequence stays intact)
// and a single quote (so it does not terminate the literal early). Order within
// a NewReplacer does not matter; it scans once and never re-examines inserted
// text.
var fqlValueEscaper = strings.NewReplacer(`\`, `\\`, `'`, `\'`)

// QuoteFQLValue wraps v in single quotes for use as an FQL literal, escaping any
// embedded backslash or single quote so caller-supplied data cannot terminate
// the literal early and inject filter syntax.
func QuoteFQLValue(v string) string {
	return "'" + fqlValueEscaper.Replace(v) + "'"
}
