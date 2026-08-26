package testutil

import (
	"testing"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/go-openapi/runtime"
)

func TestStatusErr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                                        string
		code                                        int
		success, redirect, clientError, serverError bool
	}{
		{"success", 200, true, false, false, false},
		{"redirect", 301, false, true, false, false},
		{"client error", 400, false, false, true, false},
		{"forbidden", 403, false, false, true, false},
		{"server error", 500, false, false, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			st, ok := StatusErr(tt.code).(runtime.ClientResponseStatus)
			if !ok {
				t.Fatalf("StatusErr(%d) does not implement runtime.ClientResponseStatus", tt.code)
			}
			if !st.IsCode(tt.code) {
				t.Errorf("IsCode(%d) = false, want true", tt.code)
			}
			if st.IsCode(tt.code + 1) {
				t.Errorf("IsCode(%d) = true, want false", tt.code+1)
			}
			if got := st.IsSuccess(); got != tt.success {
				t.Errorf("IsSuccess() = %v, want %v", got, tt.success)
			}
			if got := st.IsRedirect(); got != tt.redirect {
				t.Errorf("IsRedirect() = %v, want %v", got, tt.redirect)
			}
			if got := st.IsClientError(); got != tt.clientError {
				t.Errorf("IsClientError() = %v, want %v", got, tt.clientError)
			}
			if got := st.IsServerError(); got != tt.serverError {
				t.Errorf("IsServerError() = %v, want %v", got, tt.serverError)
			}
		})
	}
}

func TestAssertNormalizedMeta(t *testing.T) {
	t.Parallel()

	total := int64(42)
	queryTime := 0.02

	// Each case feeds a raw meta shape the real call sites pass, paired with the
	// got value a correct handler would produce: base.NormalizedMeta(raw). The
	// assertion must pass for every one, exercising the nil, typed-nil-pointer,
	// empty (normalizes to nil), and populated shapes without a spurious failure.
	tests := []struct {
		name string
		raw  any
	}{
		{"nil interface", nil},
		{"typed nil pointer", (*models.MsaMetaInfo)(nil)},
		{"empty meta normalizes to nil", &models.MsaMetaInfo{}},
		{"query_time only", &models.MsaMetaInfo{QueryTime: &queryTime}},
		{
			"pagination and trace_id",
			&models.MsaMetaInfo{
				QueryTime:  &queryTime,
				TraceID:    new("trace-1"),
				Pagination: &models.MsaPaging{Total: &total},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			AssertNormalizedMeta(t, base.NormalizedMeta(tt.raw), tt.raw)
		})
	}
}
