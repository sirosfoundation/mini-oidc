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
	mux.HandleFunc("POST /par", handlePAR)
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
		"pushed_authorization_request_endpoint": issuer + "/par",
		"scopes_supported":                      cfg.Server.ScopesSupported,
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic", "none"},
		"code_challenge_methods_supported":      []string{"S256", "plain"},
		"require_pushed_authorization_requests": false,
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
	// Store dynamically registered client in config
	cfg.Clients = append(cfg.Clients, config.ClientConfig{
		ClientID:                clientID,
		ClientName:              "dynamic",
		ClientSecret:            clientSecret,
		RedirectURIs:            body.RedirectURIs,
		TokenEndpointAuthMethod: authMethod,
	})
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

// --- Pushed Authorization Request (RFC 9126) ---

var parStore = struct {
	sync.RWMutex
	m map[string]url.Values
}{m: make(map[string]url.Values)}

func handlePAR(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}

	// Authenticate client
	clientID, _, _ := extractClientAuth(r)
	if clientID == "" {
		clientID = r.FormValue("client_id")
	}
	if clientID == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client", "error_description": "client_id required"})
		return
	}

	// Store the authorization parameters
	requestURI := "urn:ietf:params:oauth:request_uri:" + randomHex(16)
	parStore.Lock()
	parStore.m[requestURI] = r.Form
	parStore.Unlock()

	// Clean up after 90 seconds
	go func() {
		time.Sleep(90 * time.Second)
		parStore.Lock()
		delete(parStore.m, requestURI)
		parStore.Unlock()
	}()

	writeJSON(w, http.StatusCreated, map[string]any{
		"request_uri": requestURI,
		"expires_in":  90,
	})
}

func handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	// Support PAR: if request_uri is present, look up stored params
	if requestURI := q.Get("request_uri"); requestURI != "" {
		parStore.RLock()
		stored, ok := parStore.m[requestURI]
		parStore.RUnlock()
		if !ok {
			http.Error(w, "invalid or expired request_uri", http.StatusBadRequest)
			return
		}
		// Merge stored PAR params (they take precedence)
		for k, v := range stored {
			q[k] = v
		}
		// Clean up used request_uri
		parStore.Lock()
		delete(parStore.m, requestURI)
		parStore.Unlock()
	}

	data := struct {
		ClientID string
		Scope    string
		Users    []users.User
		Query    string
	}{
		ClientID: q.Get("client_id"),
		Scope:    q.Get("scope"),
		Users:    userStore.Users,
		Query:    q.Encode(),
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

	// --- Client Authentication ---
	clientID, clientSecret, hasAuth := extractClientAuth(r)
	if clientID == "" {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}

	client := cfg.FindClient(clientID)
	// For unknown clients (e.g. dynamically registered), allow through
	if client != nil {
		if client.TokenEndpointAuthMethod != "none" && !hasAuth && clientSecret == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client", "error_description": "client authentication required"})
			return
		}
		if !client.VerifyClientSecret(clientSecret) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client", "error_description": "invalid client credentials"})
			return
		}
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

	extra := claimsForScopes(user, ac.Scope)
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

// --- Client Authentication ---

// extractClientAuth extracts client credentials from the Authorization header (Basic auth).
func extractClientAuth(r *http.Request) (clientID, clientSecret string, ok bool) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Basic ") {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(auth[6:])
	if err != nil {
		return "", "", false
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	// URL-decode per RFC 6749 §2.3.1
	id, _ := url.QueryUnescape(parts[0])
	secret, _ := url.QueryUnescape(parts[1])
	return id, secret, true
}

// --- Scope-Based Claim Filtering ---

// claimsForScopes returns user claims filtered by the requested OIDC scopes.
func claimsForScopes(user *users.User, scopeStr string) map[string]any {
	scopes := strings.Fields(scopeStr)
	claims := make(map[string]any)

	has := func(s string) bool {
		for _, sc := range scopes {
			if sc == s {
				return true
			}
		}
		return false
	}

	// "profile" scope → name, family_name, given_name, birthdate, etc.
	if has("profile") {
		if user.GivenName != "" {
			claims["given_name"] = user.GivenName
		}
		if user.FamilyName != "" {
			claims["family_name"] = user.FamilyName
		}
		if user.Name != "" {
			claims["name"] = user.Name
		}
		if user.Birthdate != "" {
			claims["birthdate"] = user.Birthdate
		}
		if user.PlaceOfBirth != "" {
			claims["place_of_birth"] = user.PlaceOfBirth
		}
		if len(user.Nationalities) > 0 {
			claims["nationalities"] = user.Nationalities
		}
		if user.IssuingAuthority != "" {
			claims["issuing_authority"] = user.IssuingAuthority
		}
		if user.IssuingCountry != "" {
			claims["issuing_country"] = user.IssuingCountry
		}
	}

	// "email" scope → email
	if has("email") {
		if user.Email != "" {
			claims["email"] = user.Email
		}
	}

	// "organisation" scope → company affiliation, role, representation
	if has("organisation") {
		if user.Organisation != nil {
			claims["organisation"] = user.Organisation
		}
		if user.Role != "" {
			claims["role"] = user.Role
		}
		if user.RepresentationType != "" {
			claims["representation_type"] = user.RepresentationType
		}
		if user.EmployeeID != "" {
			claims["employee_id"] = user.EmployeeID
		}
	}

	// If no recognized scopes matched, return all claims (backwards compat)
	if !has("profile") && !has("email") && !has("organisation") {
		claims["given_name"] = user.GivenName
		claims["family_name"] = user.FamilyName
		claims["name"] = user.Name
		claims["email"] = user.Email
	}

	return claims
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
        <option value="{{.Sub}}">{{.Name}} ({{.Email}}){{if .Organisation}} — {{.Role}}, {{.Organisation.Name}}{{end}}</option>
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
