package falconapi

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crowdstrike/falcon-mcp/internal/config"
)

func TestProbeConnectivitySuccess201(t *testing.T) {
	t.Parallel()
	var sawMemberCID bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth2/token" {
			t.Errorf("path = %q, want /oauth2/token", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		form := string(body)
		if !strings.Contains(form, "client_id=testid01234567890123456789012") {
			t.Errorf("body missing client_id: %q", form)
		}
		if !strings.Contains(form, "client_secret=testsecret012345678901234567890123456") {
			t.Errorf("body missing client_secret: %q", form)
		}
		if strings.Contains(form, "member_cid=aabbccddeeff00112233445566778899") {
			sawMemberCID = true
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"access_token":"x","token_type":"bearer","expires_in":1800}`))
	}))
	t.Cleanup(srv.Close)

	cfg := &config.Config{
		ClientID:     "testid01234567890123456789012",
		ClientSecret: "testsecret012345678901234567890123456",
		MemberCID:    "aabbccddeeff00112233445566778899",
		HostOverride: strings.TrimPrefix(srv.URL, "https://"),
	}
	if !probeConnectivity(context.Background(), cfg, srv.Client()) {
		t.Fatal("want connected=true on HTTP 201")
	}
	if !sawMemberCID {
		t.Error("expected member_cid in token request form")
	}
}

func TestProbeConnectivityNon201(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"errors":[{"message":"access denied"}]}`))
	}))
	t.Cleanup(srv.Close)

	cfg := &config.Config{
		ClientID:     "testid01234567890123456789012",
		ClientSecret: "testsecret012345678901234567890123456",
		HostOverride: strings.TrimPrefix(srv.URL, "https://"),
	}
	if probeConnectivity(context.Background(), cfg, srv.Client()) {
		t.Fatal("want connected=false on HTTP 401")
	}
}

func TestProbeConnectivityNetworkError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// never reached — we close the server first
	}))
	cfg := &config.Config{
		ClientID:     "testid01234567890123456789012",
		ClientSecret: "testsecret012345678901234567890123456",
		HostOverride: strings.TrimPrefix(srv.URL, "https://"),
	}
	client := srv.Client()
	srv.Close()

	if probeConnectivity(context.Background(), cfg, client) {
		t.Fatal("want connected=false on network error")
	}
}

func TestProbeConnectivityNilConfig(t *testing.T) {
	t.Parallel()
	if ProbeConnectivity(context.Background(), nil) {
		t.Fatal("nil config must return false")
	}
}

func TestProbeConnectivityPublicAPIFailClosed(t *testing.T) {
	t.Parallel()
	// Public entry with empty credentials against a real-looking host should
	// fail closed (auth error or unreachable) without panicking.
	cfg := &config.Config{
		Cloud:        "us-2",
		HostOverride: "127.0.0.1:1", // nothing listening
	}
	if ProbeConnectivity(context.Background(), cfg) {
		t.Fatal("empty credentials / dead host must return false")
	}
}
