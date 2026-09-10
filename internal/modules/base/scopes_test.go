// MIT License
//
// Copyright (c) 2026 CrowdStrike
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package base

import (
	"slices"
	"testing"
)

func TestScopeStrings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		scope Scope
		want  []string
	}{
		{
			name:  "read only",
			scope: Scope{Name: "Hosts", Read: true},
			want:  []string{"Hosts:read"},
		},
		{
			name:  "write only",
			scope: Scope{Name: "Alerts", Write: true},
			want:  []string{"Alerts:write"},
		},
		{
			name:  "read and write",
			scope: Scope{Name: "host-group", Read: true, Write: true},
			want:  []string{"host-group:read", "host-group:write"},
		},
		{
			name:  "neither returns nil",
			scope: Scope{Name: "Hosts"},
			want:  nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.scope.Strings(); !slices.Equal(got, tc.want) {
				t.Errorf("Strings() = %v, want %v", got, tc.want)
			}
		})
	}
}
