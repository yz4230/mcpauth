package mcpauth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

const redirect = "https://chatgpt.com/connector_platform_oauth_redirect"

func TestFullFlow(t *testing.T) {
	a, err := New(Config{PublicURL: "https://mcp.example.com", Password: "pw",
		StateFile: filepath.Join(t.TempDir(), "s.json")})
	if err != nil {
		t.Fatal(err)
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("mcp ok")) })
	srv := httptest.NewServer(a.Middleware(next))
	defer srv.Close()
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// Unauthenticated -> 401 with resource_metadata
	res, _ := http.Post(srv.URL+"/mcp", "application/json", nil)
	if res.StatusCode != 401 || !strings.Contains(res.Header.Get("WWW-Authenticate"), "resource_metadata") {
		t.Fatalf("unauth: %d %q", res.StatusCode, res.Header.Get("WWW-Authenticate"))
	}

	// Registration with a non-allowlisted redirect URI is rejected
	res, _ = http.Post(srv.URL+"/register", "application/json", strings.NewReader(`{"redirect_uris":["https://evil.example/cb"]}`))
	if res.StatusCode != 400 {
		t.Fatalf("bad register: %d", res.StatusCode)
	}

	// DCR
	res, _ = http.Post(srv.URL+"/register", "application/json", strings.NewReader(`{"redirect_uris":["`+redirect+`"],"client_name":"ChatGPT"}`))
	var reg struct {
		ClientID string `json:"client_id"`
	}
	json.NewDecoder(res.Body).Decode(&reg)
	if res.StatusCode != 201 || reg.ClientID == "" {
		t.Fatalf("register: %d", res.StatusCode)
	}

	verifier := "verifier-verifier-verifier-verifier-verifier-12345"
	sum := sha256.Sum256([]byte(verifier))
	p := url.Values{"client_id": {reg.ClientID}, "redirect_uri": {redirect}, "response_type": {"code"},
		"state": {"xyz"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"}, "scope": {"mcp"}}

	if res, _ = http.Get(srv.URL + "/authorize?" + p.Encode()); res.StatusCode != 200 {
		t.Fatalf("authorize GET: %d", res.StatusCode)
	}

	p.Set("password", "pw")
	res, _ = noRedirect.PostForm(srv.URL+"/authorize", p)
	loc, _ := url.Parse(res.Header.Get("Location"))
	if res.StatusCode != 302 || loc.Query().Get("state") != "xyz" {
		t.Fatalf("authorize POST: %d %s", res.StatusCode, loc)
	}
	code := loc.Query().Get("code")

	tokReq := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {reg.ClientID},
		"redirect_uri": {redirect}, "code_verifier": {verifier}}
	res, _ = http.PostForm(srv.URL+"/token", tokReq)
	var tok struct{ AccessToken, RefreshToken string }
	var raw map[string]any
	json.NewDecoder(res.Body).Decode(&raw)
	tok.AccessToken, _ = raw["access_token"].(string)
	tok.RefreshToken, _ = raw["refresh_token"].(string)
	if res.StatusCode != 200 || tok.AccessToken == "" {
		t.Fatalf("token: %d %v", res.StatusCode, raw)
	}

	// Authorization codes are single-use
	if res, _ = http.PostForm(srv.URL+"/token", tokReq); res.StatusCode != 400 {
		t.Fatalf("code reuse: %d", res.StatusCode)
	}

	// A valid bearer token reaches next
	req, _ := http.NewRequest("POST", srv.URL+"/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	if res, _ = http.DefaultClient.Do(req); res.StatusCode != 200 {
		t.Fatalf("authed mcp: %d", res.StatusCode)
	}

	// Refresh tokens rotate; the old one is rejected
	ref := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}, "client_id": {reg.ClientID}}
	if res, _ = http.PostForm(srv.URL+"/token", ref); res.StatusCode != 200 {
		t.Fatalf("refresh: %d", res.StatusCode)
	}
	if res, _ = http.PostForm(srv.URL+"/token", ref); res.StatusCode != 400 {
		t.Fatalf("refresh reuse: %d", res.StatusCode)
	}

	// Access token survives a restart (persistence check)
	a2, err := New(a.cfg)
	if err != nil || !a2.validAccess(tok.AccessToken) {
		t.Fatalf("persistence: %v", err)
	}
}

func TestParseBaseURL(t *testing.T) {
	ok := map[string]string{
		"https://mcp.example.com":  "https://mcp.example.com",
		"https://mcp.example.com/": "https://mcp.example.com",
		"https://example.com/sub/": "https://example.com/sub",
		"http://localhost:8000":    "http://localhost:8000",
	}
	for in, want := range ok {
		u, err := parseBaseURL(in)
		if err != nil || u.String() != want {
			t.Errorf("%q: got %v, %v; want %q", in, u, err, want)
		}
		a := &Auth{base: u}
		if got := a.endpoint("/token"); got != want+"/token" {
			t.Errorf("%q endpoint: %q", in, got)
		}
	}
	for _, in := range []string{"mcp.example.com", "http://mcp.example.com", "https://mcp.example.com?x=1",
		"https://mcp.example.com#f", "https://user:pw@mcp.example.com"} {
		if _, err := parseBaseURL(in); err == nil {
			t.Errorf("%q: expected error", in)
		}
	}
}

func TestRedirectURIAllowed(t *testing.T) {
	a, err := New(Config{PublicURL: "https://mcp.example.com", Password: "pw",
		StateFile: filepath.Join(t.TempDir(), "s.json")})
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{redirect, "https://claude.ai/api/mcp/auth_callback",
		"https://chatgpt.com/connector/oauth/yYVsRYZPDCPc"} {
		if !a.redirectURIAllowed(u) {
			t.Errorf("%q: expected allowed", u)
		}
	}
	for _, u := range []string{"https://chatgpt.com/connector/oauth/", "https://chatgpt.com/connector/oauth",
		"https://chatgpt.com/connector/oauth/a/b", "https://chatgpt.com/connector/oauth/a?x=1",
		"https://chatgpt.com/connector/oauth/a#f", "https://chatgpt.com/connector/oauth/a/",
		"https://chatgpt.com.evil.example/connector/oauth/a", "http://chatgpt.com/connector/oauth/a"} {
		if a.redirectURIAllowed(u) {
			t.Errorf("%q: expected rejected", u)
		}
	}

	// An empty (non-nil) prefix list disables prefix matching
	a, err = New(Config{PublicURL: "https://mcp.example.com", Password: "pw",
		StateFile: filepath.Join(t.TempDir(), "s.json"), AllowedRedirectURIPrefixes: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if a.redirectURIAllowed("https://chatgpt.com/connector/oauth/yYVsRYZPDCPc") {
		t.Error("prefix matching should be disabled")
	}
}

func TestRegisterWithPrefixRedirectURI(t *testing.T) {
	a, err := New(Config{PublicURL: "https://mcp.example.com", Password: "pw",
		StateFile: filepath.Join(t.TempDir(), "s.json")})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.Middleware(http.NotFoundHandler()))
	defer srv.Close()
	for body, want := range map[string]int{
		`{"redirect_uris":["https://chatgpt.com/connector/oauth/yYVsRYZPDCPc"]}`: 201,
		`{"redirect_uris":["https://chatgpt.com/connector/oauth/a/b"]}`:          400,
	} {
		res, err := http.Post(srv.URL+"/register", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != want {
			t.Errorf("%s: got %d, want %d", body, res.StatusCode, want)
		}
	}
}
