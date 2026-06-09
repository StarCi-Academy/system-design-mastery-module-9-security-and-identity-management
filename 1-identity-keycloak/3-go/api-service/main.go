// Identity & Keycloak lab — Go API service.
// Delegates authentication to Keycloak (OIDC) and validates JWTs OFFLINE against
// the realm's JWKS using coreos/go-oidc. Public + confidential client demo and a
// protected /api/orders resource. English-only comments per repo convention.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// ---------------------------------------------------------------------------
// Config — read from environment (Docker `environment:` or .env outside Compose).
// ---------------------------------------------------------------------------

type config struct {
	port                string
	keycloakBaseURL     string
	realm               string
	publicClientID      string
	privateClientID     string
	privateClientSecret string
	defaultUsername     string
	defaultPassword     string
	redirectURI         string
}

func loadConfig() config {
	return config{
		port:                envOr("PORT", "3000"),
		keycloakBaseURL:     envOr("KEYCLOAK_BASE_URL", "http://keycloak:8080"),
		realm:               envOr("KEYCLOAK_REALM", "starci-realm"),
		publicClientID:      envOr("KEYCLOAK_PUBLIC_CLIENT_ID", "go-app"),
		privateClientID:     envOr("KEYCLOAK_PRIVATE_CLIENT_ID", "go-private-app"),
		privateClientSecret: envOr("KEYCLOAK_PRIVATE_CLIENT_SECRET", "super-secret-key"),
		defaultUsername:     envOr("KEYCLOAK_DEFAULT_USERNAME", "student"),
		defaultPassword:     envOr("KEYCLOAK_DEFAULT_PASSWORD", "student123"),
		redirectURI:         envOr("KEYCLOAK_REDIRECT_URI", "http://localhost:3000/auth/callback"),
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func (c config) issuerURL() string {
	return fmt.Sprintf("%s/realms/%s", c.keycloakBaseURL, c.realm)
}

func (c config) tokenEndpoint() string {
	return c.issuerURL() + "/protocol/openid-connect/token"
}

func (c config) authorizeEndpoint() string {
	return c.issuerURL() + "/protocol/openid-connect/auth"
}

// ---------------------------------------------------------------------------
// Shared types.
// ---------------------------------------------------------------------------

// TokenResponse is the OIDC token endpoint response, returned verbatim to clients.
type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in,omitempty"`
	RefreshToken     string `json:"refresh_token,omitempty"`
	TokenType        string `json:"token_type"`
	IDToken          string `json:"id_token,omitempty"`
	Scope            string `json:"scope,omitempty"`
}

// claims is the subset of the decoded JWT the lab cares about.
type claims struct {
	Sub               string `json:"sub"`
	PreferredUsername string `json:"preferred_username"`
	Email             string `json:"email"`
}

type ctxKey string

const userCtxKey ctxKey = "user"

// ---------------------------------------------------------------------------
// AuthService — produces tokens via password grant (public + confidential).
// ---------------------------------------------------------------------------

type AuthService struct {
	cfg    config
	client *http.Client
}

func newAuthService(cfg config) *AuthService {
	return &AuthService{cfg: cfg, client: &http.Client{Timeout: 10 * time.Second}}
}

// LoginPublicClient exchanges username/password via the public client (no secret).
func (s *AuthService) LoginPublicClient(ctx context.Context, username, password string) (*TokenResponse, error) {
	form := url.Values{}
	form.Set("client_id", s.cfg.publicClientID)
	form.Set("grant_type", "password")
	form.Set("username", username)
	form.Set("password", password)
	return s.fetchToken(ctx, form)
}

// LoginPrivateClient exchanges username/password via the confidential client (with secret).
func (s *AuthService) LoginPrivateClient(ctx context.Context, username, password string) (*TokenResponse, error) {
	form := url.Values{}
	form.Set("client_id", s.cfg.privateClientID)
	form.Set("client_secret", s.cfg.privateClientSecret)
	form.Set("grant_type", "password")
	form.Set("username", username)
	form.Set("password", password)
	return s.fetchToken(ctx, form)
}

// ExchangeCode exchanges an authorization code for tokens via the public client.
func (s *AuthService) ExchangeCode(ctx context.Context, code string) (*TokenResponse, error) {
	form := url.Values{}
	form.Set("client_id", s.cfg.publicClientID)
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", s.cfg.redirectURI)
	return s.fetchToken(ctx, form)
}

// fetchToken POSTs a form-urlencoded body to Keycloak's /token endpoint.
// OIDC requires application/x-www-form-urlencoded; JSON would be rejected with 415.
func (s *AuthService) fetchToken(ctx context.Context, form url.Values) (*TokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.tokenEndpoint(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("keycloak token request failed: %d %s", resp.StatusCode, string(body))
	}
	var token TokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, err
	}
	return &token, nil
}

// ---------------------------------------------------------------------------
// Auth middleware — offline JWT validation via cached JWKS.
// ---------------------------------------------------------------------------

// requireAuth wraps protected handlers: it verifies the Bearer JWT offline against
// the realm's JWKS (cached by the provider) and pushes decoded claims into context.
func requireAuth(verifier *oidc.IDTokenVerifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authz := r.Header.Get("Authorization")
			if !strings.HasPrefix(authz, "Bearer ") {
				writeJSON(w, http.StatusUnauthorized, map[string]any{"statusCode": 401, "message": "Unauthorized"})
				return
			}
			raw := strings.TrimPrefix(authz, "Bearer ")
			idToken, err := verifier.Verify(r.Context(), raw)
			if err != nil {
				writeJSON(w, http.StatusUnauthorized, map[string]any{"statusCode": 401, "message": "Unauthorized"})
				return
			}
			var c claims
			if err := idToken.Claims(&c); err != nil {
				writeJSON(w, http.StatusUnauthorized, map[string]any{"statusCode": 401, "message": "Unauthorized"})
				return
			}
			ctx := context.WithValue(r.Context(), userCtxKey, c)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func userFromContext(ctx context.Context) claims {
	if c, ok := ctx.Value(userCtxKey).(claims); ok {
		return c
	}
	return claims{}
}

// ---------------------------------------------------------------------------
// HTTP handlers.
// ---------------------------------------------------------------------------

type server struct {
	cfg  config
	auth *AuthService
}

type passwordLogin struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"message": "Identity Keycloak Go demo is running.",
		"endpoints": map[string]string{
			"loginPublic":     "POST /auth/login/public",
			"loginPrivate":    "POST /auth/login/private",
			"authorizeUrl":    "GET /auth/authorize/url",
			"authCallback":    "GET /auth/callback?code=...",
			"protectedOrders": "GET /api/orders (requires Bearer token)",
		},
	})
}

func (s *server) loginPublic(w http.ResponseWriter, r *http.Request) {
	body := s.decodeLogin(r)
	token, err := s.auth.LoginPublicClient(r.Context(), body.Username, body.Password)
	s.writeToken(w, token, err)
}

func (s *server) loginPrivate(w http.ResponseWriter, r *http.Request) {
	body := s.decodeLogin(r)
	token, err := s.auth.LoginPrivateClient(r.Context(), body.Username, body.Password)
	s.writeToken(w, token, err)
}

func (s *server) authorizeURL(w http.ResponseWriter, _ *http.Request) {
	state := fmt.Sprintf("%d", time.Now().UnixNano())
	params := url.Values{}
	params.Set("client_id", s.cfg.publicClientID)
	params.Set("response_type", "code")
	params.Set("scope", "openid profile email")
	params.Set("redirect_uri", s.cfg.redirectURI)
	params.Set("state", state)
	writeJSON(w, http.StatusOK, map[string]any{
		"authorizeUrl": s.cfg.authorizeEndpoint() + "?" + params.Encode(),
		"note":         "Open authorizeUrl in browser, then copy `code` from callback query params.",
	})
}

func (s *server) callback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	token, err := s.auth.ExchangeCode(r.Context(), code)
	s.writeToken(w, token, err)
}

func (s *server) listOrders(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	username := user.PreferredUsername
	if username == "" {
		username = user.Email
	}
	if username == "" {
		username = "user"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "success",
		"message": fmt.Sprintf("Welcome %s. Here are your orders", username),
		"data": []map[string]any{
			{"id": 1, "total": 500},
			{"id": 2, "total": 1000},
		},
	})
}

func (s *server) decodeLogin(r *http.Request) passwordLogin {
	var body passwordLogin
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Username == "" {
		body.Username = s.cfg.defaultUsername
	}
	if body.Password == "" {
		body.Password = s.cfg.defaultPassword
	}
	return body
}

func (s *server) writeToken(w http.ResponseWriter, token *TokenResponse, err error) {
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"statusCode": 400, "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, token)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// ---------------------------------------------------------------------------
// Bootstrap.
// ---------------------------------------------------------------------------

func main() {
	cfg := loadConfig()
	auth := newAuthService(cfg)

	// Build the offline verifier. Retry discovery because Keycloak may still be
	// importing the realm when this container starts.
	var verifier *oidc.IDTokenVerifier
	ctx := context.Background()
	for i := 0; i < 60; i++ {
		provider, err := oidc.NewProvider(ctx, cfg.issuerURL())
		if err == nil {
			// SkipClientIDCheck: accept any token valid for the realm, regardless
			// of which client (public or confidential) issued it.
			verifier = provider.Verifier(&oidc.Config{SkipClientIDCheck: true})
			break
		}
		log.Printf("waiting for Keycloak OIDC discovery (%d): %v", i, err)
		time.Sleep(2 * time.Second)
	}
	if verifier == nil {
		log.Fatal("could not reach Keycloak OIDC discovery endpoint")
	}

	srv := &server{cfg: cfg, auth: auth}
	protect := requireAuth(verifier)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", srv.health)
	mux.HandleFunc("POST /auth/login/public", srv.loginPublic)
	mux.HandleFunc("POST /auth/login/private", srv.loginPrivate)
	mux.HandleFunc("GET /auth/authorize/url", srv.authorizeURL)
	mux.HandleFunc("GET /auth/callback", srv.callback)
	// Protected resource — gated by the offline-validation middleware.
	mux.Handle("GET /api/orders", protect(http.HandlerFunc(srv.listOrders)))

	addr := "0.0.0.0:" + cfg.port
	log.Printf("Identity Keycloak Go demo listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
