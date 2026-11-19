// Package mcpauth provides a minimal OAuth 2.1 (DCR + PKCE) authorization server
// for personal MCP servers, packaged as net/http middleware. Standard library only.
//
//	auth, _ := mcpauth.New(mcpauth.Config{PublicURL: "https://mcp.example.com", Password: "..."})
//	http.ListenAndServe(":8000", auth.Middleware(mcpHandler))
//
// The middleware answers the OAuth endpoints itself and forwards every other
// request to next only if it carries a valid bearer token.
package mcpauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

type Config struct {
	PublicURL           string   // e.g. https://mcp.example.com (no trailing slash)
	Password            string   // password for the login page
	StateFile           string   // where clients and tokens are persisted (default: oauth_state.json)
	MCPPath             string   // path of the MCP endpoint (default: /mcp)
	AllowedRedirectURIs []string // redirect URIs allowed at registration (default: ChatGPT and Claude)
	// AllowedRedirectURIPrefixes allows any redirect URI made of a prefix plus one
	// non-empty segment without '/', '?' or '#' (default: ChatGPT's per-connector URIs).
	AllowedRedirectURIPrefixes []string
	AccessTTL                  time.Duration // default: 1 hour
	RefreshTTL                 time.Duration // default: 90 days
}

var DefaultRedirectURIs = []string{
	"https://chatgpt.com/connector_platform_oauth_redirect", // ChatGPT
	"https://claude.ai/api/mcp/auth_callback",               // Claude
}

var DefaultRedirectURIPrefixes = []string{
	"https://chatgpt.com/connector/oauth/", // ChatGPT: https://chatgpt.com/connector/oauth/<id>
}

const codeTTL = 5 * time.Minute

type client struct {
	RedirectURIs []string `json:"redirect_uris"`
	Name         string   `json:"client_name"`
}

type tokenRec struct {
	ClientID string    `json:"client_id"`
	Scope    string    `json:"scope"`
	Exp      time.Time `json:"exp"`
}

type codeRec struct {
	ClientID, RedirectURI, Challenge, Scope string
	Exp                                     time.Time
}

type state struct {
	Clients map[string]client   `json:"clients"`
	Access  map[string]tokenRec `json:"access"`  // key: sha256(token)
	Refresh map[string]tokenRec `json:"refresh"` // key: sha256(token)
}

type Auth struct {
	cfg   Config
	mu    sync.Mutex
	st    state
	codes map[string]codeRec
	mux   *http.ServeMux
	base  *url.URL // parsed and validated PublicURL
}

// endpoint returns the absolute URL of p under PublicURL.
func (a *Auth) endpoint(p string) string {
	return a.base.JoinPath(p).String()
}

// parseBaseURL validates PublicURL: absolute https (http only for localhost),
// with no userinfo, query, or fragment. A trailing slash is removed.
func parseBaseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("mcpauth: invalid PublicURL: %w", err)
	}
	local := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"
	switch {
	case u.Host == "":
		return nil, errors.New("mcpauth: PublicURL must be absolute")
	case u.Scheme != "https" && !(u.Scheme == "http" && local):
		return nil, errors.New("mcpauth: PublicURL must use https")
	case u.User != nil || u.RawQuery != "" || u.Fragment != "":
		return nil, errors.New("mcpauth: PublicURL must not contain userinfo, query, or fragment")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u, nil
}

func New(cfg Config) (*Auth, error) {
	if cfg.PublicURL == "" || cfg.Password == "" {
		return nil, errors.New("mcpauth: PublicURL and Password are required")
	}
	base, err := parseBaseURL(cfg.PublicURL)
	if err != nil {
		return nil, err
	}
	cfg.PublicURL = base.String()
	if cfg.StateFile == "" {
		cfg.StateFile = "oauth_state.json"
	}
	if cfg.MCPPath == "" {
		cfg.MCPPath = "/mcp"
	}
	if cfg.AllowedRedirectURIs == nil {
		cfg.AllowedRedirectURIs = DefaultRedirectURIs
	}
	if cfg.AllowedRedirectURIPrefixes == nil {
		cfg.AllowedRedirectURIPrefixes = DefaultRedirectURIPrefixes
	}
	if cfg.AccessTTL == 0 {
		cfg.AccessTTL = time.Hour
	}
	if cfg.RefreshTTL == 0 {
		cfg.RefreshTTL = 90 * 24 * time.Hour
	}

	a := &Auth{
		cfg:   cfg,
		st:    state{Clients: map[string]client{}, Access: map[string]tokenRec{}, Refresh: map[string]tokenRec{}},
		codes: map[string]codeRec{},
		mux:   http.NewServeMux(),
		base:  base,
	}
	if b, err := os.ReadFile(cfg.StateFile); err == nil {
		if err := json.Unmarshal(b, &a.st); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	a.mux.HandleFunc("GET /.well-known/oauth-protected-resource", a.protectedResource)
	a.mux.HandleFunc("GET /.well-known/oauth-protected-resource"+cfg.MCPPath, a.protectedResource)
	a.mux.HandleFunc("GET /.well-known/oauth-authorization-server", a.authServerMeta)
	a.mux.HandleFunc("GET /.well-known/openid-configuration", a.authServerMeta)
	a.mux.HandleFunc("POST /register", a.register)
	a.mux.HandleFunc("GET /authorize", a.authorize)
	a.mux.HandleFunc("POST /authorize", a.authorize)
	a.mux.HandleFunc("POST /token", a.token)
	return a, nil
}

// Middleware serves the OAuth endpoints and protects everything else with bearer tokens.
func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, pattern := a.mux.Handler(r); pattern != "" {
			a.mux.ServeHTTP(w, r)
			return
		}
		if tok, ok := bearer(r); ok && a.validAccess(tok) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("WWW-Authenticate",
			`Bearer resource_metadata="`+a.endpoint("/.well-known/oauth-protected-resource")+`"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
	})
}

// ---------- state ----------

func hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func randToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// saveLocked prunes expired tokens and writes the state to disk. Caller must hold a.mu.
func (a *Auth) saveLocked() {
	now := time.Now()
	for _, m := range []map[string]tokenRec{a.st.Access, a.st.Refresh} {
		for k, v := range m {
			if now.After(v.Exp) {
				delete(m, k)
			}
		}
	}
	b, _ := json.Marshal(a.st)
	tmp := a.cfg.StateFile + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		log.Printf("[mcpauth] failed to save state: %v", err)
		return
	}
	if err := os.Rename(tmp, filepath.Clean(a.cfg.StateFile)); err != nil {
		log.Printf("[mcpauth] failed to save state: %v", err)
	}
}

func (a *Auth) issueLocked(clientID, scope string) map[string]any {
	now := time.Now()
	access, refresh := randToken(), randToken()
	a.st.Access[hash(access)] = tokenRec{clientID, scope, now.Add(a.cfg.AccessTTL)}
	a.st.Refresh[hash(refresh)] = tokenRec{clientID, scope, now.Add(a.cfg.RefreshTTL)}
	a.saveLocked()
	return map[string]any{
		"access_token": access, "token_type": "Bearer",
		"expires_in": int(a.cfg.AccessTTL.Seconds()), "refresh_token": refresh, "scope": scope,
	}
}

func (a *Auth) validAccess(tok string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	rec, ok := a.st.Access[hash(tok)]
	return ok && time.Now().Before(rec.Exp)
}

func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:]), true
	}
	return "", false
}

// ---------- handlers ----------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func oauthErr(w http.ResponseWriter, code, desc string) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": code, "error_description": desc})
}

func (a *Auth) protectedResource(w http.ResponseWriter, r *http.Request) { // RFC 9728
	writeJSON(w, 200, map[string]any{
		"resource":                 a.endpoint(a.cfg.MCPPath),
		"authorization_servers":    []string{a.cfg.PublicURL},
		"bearer_methods_supported": []string{"header"},
		"scopes_supported":         []string{"mcp"},
	})
}

func (a *Auth) authServerMeta(w http.ResponseWriter, r *http.Request) { // RFC 8414
	writeJSON(w, 200, map[string]any{
		"issuer":                                a.cfg.PublicURL,
		"authorization_endpoint":                a.endpoint("/authorize"),
		"token_endpoint":                        a.endpoint("/token"),
		"registration_endpoint":                 a.endpoint("/register"),
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"scopes_supported":                      []string{"mcp"},
	})
}

func (a *Auth) register(w http.ResponseWriter, r *http.Request) { // RFC 7591
	var body struct {
		RedirectURIs []string `json:"redirect_uris"`
		ClientName   string   `json:"client_name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		oauthErr(w, "invalid_client_metadata", "JSON body required")
		return
	}
	if len(body.RedirectURIs) == 0 || slices.ContainsFunc(body.RedirectURIs, func(u string) bool {
		return !a.redirectURIAllowed(u)
	}) {
		log.Printf("[mcpauth] registration rejected: redirect_uris=%v", body.RedirectURIs) // use this to tune the allowlist
		oauthErr(w, "invalid_redirect_uri", "redirect_uri not allowed")
		return
	}
	id := randToken()[:22]
	a.mu.Lock()
	a.st.Clients[id] = client{body.RedirectURIs, body.ClientName}
	a.saveLocked()
	a.mu.Unlock()
	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id": id, "client_id_issued_at": time.Now().Unix(), "client_name": body.ClientName,
		"redirect_uris": body.RedirectURIs, "token_endpoint_auth_method": "none",
		"grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"},
	})
}

func (a *Auth) redirectURIAllowed(u string) bool {
	if slices.Contains(a.cfg.AllowedRedirectURIs, u) {
		return true
	}
	return slices.ContainsFunc(a.cfg.AllowedRedirectURIPrefixes, func(p string) bool {
		rest, ok := strings.CutPrefix(u, p)
		return ok && rest != "" && !strings.ContainsAny(rest, "/?#")
	})
}

var passThrough = []string{"client_id", "redirect_uri", "response_type", "state",
	"code_challenge", "code_challenge_method", "scope", "resource"}

var loginTmpl = template.Must(template.New("login").Parse(`<!doctype html><meta charset="utf-8">
<meta name="viewport" content="width=device-width"><title>MCP Login</title>
<body style="font-family:sans-serif;max-width:22rem;margin:4rem auto">
<h3>{{.Client}} is requesting access</h3>
{{if .Msg}}<p style="color:#c00">{{.Msg}}</p>{{end}}
<form method="post">{{range $k, $v := .Hidden}}<input type="hidden" name="{{$k}}" value="{{$v}}">{{end}}
<input type="password" name="password" autofocus style="width:100%;padding:.5rem" placeholder="Password">
<button style="margin-top:1rem;padding:.5rem 1rem">Allow</button></form></body>`))

func (a *Auth) checkAuthz(p url.Values) (client, string) {
	a.mu.Lock()
	c, ok := a.st.Clients[p.Get("client_id")]
	a.mu.Unlock()
	switch {
	case !ok:
		return c, "unknown client_id"
	case !slices.Contains(c.RedirectURIs, p.Get("redirect_uri")):
		return c, "redirect_uri mismatch"
	case p.Get("response_type") != "code":
		return c, "response_type must be code"
	case p.Get("code_challenge") == "" || p.Get("code_challenge_method") != "S256":
		return c, "PKCE (S256) required"
	}
	return c, ""
}

func (a *Auth) authorize(w http.ResponseWriter, r *http.Request) {
	var p url.Values
	if r.Method == http.MethodPost {
		r.ParseForm()
		p = r.PostForm
	} else {
		p = r.URL.Query()
	}
	c, e := a.checkAuthz(p)
	if e != "" { // redirect_uri is not verified, so show the error instead of redirecting
		http.Error(w, "invalid request: "+e, http.StatusBadRequest)
		return
	}

	render := func(msg string) {
		hidden := map[string]string{}
		for _, k := range passThrough {
			hidden[k] = p.Get(k)
		}
		name := c.Name
		if name == "" {
			name = "A client"
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		loginTmpl.Execute(w, map[string]any{"Client": name, "Msg": msg, "Hidden": hidden})
	}

	if r.Method == http.MethodGet {
		render("")
		return
	}
	if subtle.ConstantTimeCompare([]byte(p.Get("password")), []byte(a.cfg.Password)) != 1 {
		time.Sleep(time.Second) // crude brute-force throttling
		render("Incorrect password")
		return
	}

	code := randToken()
	scope := p.Get("scope")
	if scope == "" {
		scope = "mcp"
	}
	a.mu.Lock()
	a.codes[code] = codeRec{p.Get("client_id"), p.Get("redirect_uri"), p.Get("code_challenge"), scope, time.Now().Add(codeTTL)}
	a.mu.Unlock()

	q := url.Values{"code": {code}}
	if s := p.Get("state"); s != "" {
		q.Set("state", s)
	}
	http.Redirect(w, r, p.Get("redirect_uri")+"?"+q.Encode(), http.StatusFound)
}

func (a *Auth) token(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	f := r.PostForm
	a.mu.Lock()
	defer a.mu.Unlock()

	switch f.Get("grant_type") {
	case "authorization_code":
		rec, ok := a.codes[f.Get("code")]
		delete(a.codes, f.Get("code")) // single-use
		if !ok || time.Now().After(rec.Exp) {
			oauthErr(w, "invalid_grant", "code invalid or expired")
			return
		}
		if f.Get("client_id") != rec.ClientID || f.Get("redirect_uri") != rec.RedirectURI {
			oauthErr(w, "invalid_grant", "client_id / redirect_uri mismatch")
			return
		}
		sum := sha256.Sum256([]byte(f.Get("code_verifier")))
		if subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(rec.Challenge)) != 1 {
			oauthErr(w, "invalid_grant", "PKCE verification failed")
			return
		}
		writeJSON(w, 200, a.issueLocked(rec.ClientID, rec.Scope))

	case "refresh_token":
		key := hash(f.Get("refresh_token"))
		rec, ok := a.st.Refresh[key]
		delete(a.st.Refresh, key) // rotate
		if !ok || time.Now().After(rec.Exp) {
			a.saveLocked()
			oauthErr(w, "invalid_grant", "refresh_token invalid or expired")
			return
		}
		if cid := f.Get("client_id"); cid != "" && cid != rec.ClientID {
			oauthErr(w, "invalid_grant", "client_id mismatch")
			return
		}
		writeJSON(w, 200, a.issueLocked(rec.ClientID, rec.Scope))

	default:
		oauthErr(w, "unsupported_grant_type", "")
	}
}
