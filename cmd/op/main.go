package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/sirosfoundation/mini-oidc/internal/config"
	"github.com/sirosfoundation/mini-oidc/internal/keys"
	"github.com/sirosfoundation/mini-oidc/internal/users"
)

var version = "dev"

type authCode struct {
	ClientID            string
	RedirectURI         string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Scope               string
	State               string
	UserSub             string
	CreatedAt           time.Time
}

var (
	cfg       *config.Config
	userStore *users.UsersFile
	ks        *keys.KeySet
	codes     = struct {
		sync.RWMutex
		m map[string]*authCode
	}{m: make(map[string]*authCode)}
	tokenStore = struct {
		sync.RWMutex
		m map[string]string
	}{m: make(map[string]string)}
)

func main() {
	configFile := envOr("CONFIG_FILE", "configs/config.yaml")
	usersFile := envOr("USERS_FILE", "users.yaml")

	var err error
	cfg, err = config.Load(configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	userStore, err = users.Load(usersFile)
	if err != nil {
		log.Fatalf("Failed to load users: %v", err)
	}
	log.Printf("Loaded %d users from %s", len(userStore.Users), usersFile)

	ks, err = keys.Generate()
	if err != nil {
		log.Fatalf("Failed to generate keys: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", handleDiscovery)
	mux.HandleFunc("GET /jwks", handleJWKS)
	mux.HandleFunc("POST /register", handleRegister)
	mux.HandleFunc("GET /authorize", handleAuthorize)
	mux.HandleFunc("POST /authorize/login", handleLogin)
	mux.HandleFunc("POST /token", handleToken)
	mux.HandleFunc("GET /userinfo", handleUserinfo)
	mux.HandleFunc("GET /health", handleHealth)
	mux.HandleFunc("GET /readyz", handleHealth)

	addr := fmt.Sprintf(":%d", cfg.Server.OPPort)
	log.Printf("mini-oidc-op %s listening on %s, issuer=%s", version, addr, cfg.Server.Issuer)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

func handleDiscovery(w http.ResponseWriter, r *http.Request) {
	issuer := cfg.Server.Issuer
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"userinfo_endpoint":                     issuer + "/userinfo",
		"jwks_uri":                              issuer + "/jwks",
		"registration_endpoint":                 issuer + "/register",
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic", "none"},
		"code_challenge_methods_supported":      []string{"S256", "plain"},
	})
}

func handleJWKS(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, ks.JWKSet)
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RedirectURIs            []string `json:"redirect_uris"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		body.RedirectURIs = nil
	}
	clientID := "dyn-" + randomHex(8)
	clientSecret := randomHex(32)
	authMethod := body.TokenEndpointAuthMethod
	if authMethod == "" {
		authMethod = "client_secret_basic"
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id":                  clientID,
		"client_secret":              clientSecret,
		"client_id_issued_at":        time.Now().Unix(),
		"client_secret_expires_at":   0,
		"redirect_uris":              body.RedirectURIs,
		"grant_types":                []string{"authorization_code"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": authMethod,
	})
}

func handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	data := struct {
		ClientID string
		Scope    string
		Users    []users.User
		Query    string
	}{
		ClientID: q.Get("client_id"),
		Scope:    q.Get("scope"),
		Users:    userStore.Users,
		Query:    r.URL.RawQuery,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := loginTmpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	userSub := r.FormValue("user")
	rawQuery := r.FormValue("query")

	if userStore.FindBySub(userSub) == nil {
		http.Error(w, "unknown user", http.StatusBadRequest)
		return
	}

	q, _ := url.ParseQuery(rawQuery)

	code := randomHex(32)
	codes.Lock()
	codes.m[code] = &authCode{
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		Nonce:               q.Get("nonce"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: orDefault(q.Get("code_challenge_method"), "plain"),
		Scope:               orDefault(q.Get("scope"), "openid"),
		State:               q.Get("state"),
		UserSub:             userSub,
		CreatedAt:           time.Now(),
	}
	codes.Unlock()

	redirectURI := q.Get("redirect_uri")
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	params := u.Query()
	params.Set("code", code)
	if state := q.Get("state"); state != "" {
		params.Set("state", state)
	}
	u.RawQuery = params.Encode()

	log.Printf("[op] user %s approved → %s", userSub, u.String())
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}

	code := r.FormValue("code")
	codeVerifier := r.FormValue("code_verifier")

	codes.Lock()
	ac, ok := codes.m[code]
	if ok {
		delete(codes.m, code)
	}
	codes.Unlock()

	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "unknown code"})
		return
	}

	if time.Since(ac.CreatedAt) > 5*time.Minute {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "code expired"})
		return
	}

	if ac.CodeChallenge != "" && codeVerifier != "" {
		if !verifyPKCE(codeVerifier, ac.CodeChallenge, ac.CodeChallengeMethod) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "PKCE verification failed"})
			return
		}
	}

	user := userStore.FindBySub(ac.UserSub)
	if user == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "user not found"})
		return
	}

	now := time.Now()
	claims := josejwt.Claims{
		Issuer:    cfg.Server.Issuer,
		Subject:   user.Sub,
		Audience:  josejwt.Audience{ac.ClientID},
		IssuedAt:  josejwt.NewNumericDate(now),
		Expiry:    josejwt.NewNumericDate(now.Add(time.Hour)),
		NotBefore: josejwt.NewNumericDate(now),
	}

	extra := map[string]any{
		"given_name":  user.GivenName,
		"family_name": user.FamilyName,
		"name":        user.Name,
		"email":       user.Email,
	}
	if ac.Nonce != "" {
		extra["nonce"] = ac.Nonce
	}

	raw, err := josejwt.Signed(ks.Signer).Claims(claims).Claims(extra).Serialize()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	accessToken := randomHex(32)
	tokenStore.Lock()
	tokenStore.m[accessToken] = user.Sub
	tokenStore.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     raw,
		"scope":        ac.Scope,
	})
}

func handleUserinfo(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	token := strings.TrimPrefix(auth, "Bearer ")

	tokenStore.RLock()
	sub, ok := tokenStore.m[token]
	tokenStore.RUnlock()

	if !ok {
		writeJSON(w, http.StatusOK, userStore.Users[0])
		return
	}

	user := userStore.FindBySub(sub)
	if user == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user_not_found"})
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": version})
}

// --- Helpers ---

func verifyPKCE(verifier, challenge, method string) bool {
	if method == "S256" {
		h := sha256.Sum256([]byte(verifier))
		expected := base64.RawURLEncoding.EncodeToString(h[:])
		return expected == challenge
	}
	return verifier == challenge
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

var loginTmpl = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Mini OIDC — Sign In</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
           background: #f0f2f5; display: flex; justify-content: center; align-items: center;
           min-height: 100vh; padding: 16px; }
    .card { background: #fff; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,.1);
            padding: 32px; max-width: 400px; width: 100%; }
    h1 { font-size: 20px; color: #111; margin-bottom: 4px; text-align: center; }
    .sub { color: #666; font-size: 13px; margin-bottom: 20px; text-align: center; }
    label { display: block; font-size: 14px; font-weight: 600; margin-bottom: 6px; color: #333; }
    select { width: 100%; padding: 10px 12px; border: 1px solid #d1d5db; border-radius: 8px;
             font-size: 15px; margin-bottom: 20px; background: #fff; }
    .info { background: #f8f9fa; border-radius: 8px; padding: 10px 14px; margin-bottom: 20px;
            font-size: 13px; color: #555; }
    .info dt { font-weight: 600; margin-top: 6px; }
    .info dt:first-child { margin-top: 0; }
    button { width: 100%; padding: 12px; border: none; border-radius: 8px; font-size: 15px;
             font-weight: 600; cursor: pointer; background: #4f46e5; color: #fff; }
    button:hover { background: #4338ca; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Sign In</h1>
    <p class="sub">Select a test user to authenticate</p>
    <form method="POST" action="/authorize/login">
      <input type="hidden" name="query" value="{{.Query}}">
      <label for="user">User</label>
      <select name="user" id="user">
        {{range .Users}}
        <option value="{{.Sub}}">{{.Name}} ({{.Email}})</option>
        {{end}}
      </select>
      <div class="info">
        <dl>
          <dt>Application</dt>
          <dd>{{.ClientID}}</dd>
          <dt>Requested scopes</dt>
          <dd>{{.Scope}}</dd>
        </dl>
      </div>
      <button type="submit">Sign In</button>
    </form>
  </div>
</body>
</html>`))
