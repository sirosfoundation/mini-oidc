package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/sirosfoundation/mini-oidc/internal/config"
)

var version = "dev"

type session struct {
	State        string
	Nonce        string
	CodeVerifier string
	CreatedAt    time.Time
}

type tokenResult struct {
	IDToken      string         `json:"id_token"`
	AccessToken  string         `json:"access_token"`
	IDClaims     map[string]any `json:"id_claims"`
	UserInfo     map[string]any `json:"userinfo"`
	TokenType    string         `json:"token_type"`
	ExpiresIn    int            `json:"expires_in"`
	Scope        string         `json:"scope"`
	IDTokenValid bool           `json:"id_token_valid"`
	Error        string         `json:"error,omitempty"`
}

var (
	cfg      *config.Config
	sessions = struct {
		sync.RWMutex
		m map[string]*session
	}{m: make(map[string]*session)}
)

func main() {
	configFile := envOr("CONFIG_FILE", "configs/config.yaml")

	var err error
	cfg, err = config.Load(configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", handleIndex)
	mux.HandleFunc("GET /login", handleLogin)
	mux.HandleFunc("GET /callback", handleCallback)
	mux.HandleFunc("GET /health", handleHealth)
	mux.HandleFunc("GET /readyz", handleHealth)

	addr := fmt.Sprintf(":%d", cfg.Server.RPPort)
	log.Printf("mini-oidc-rp %s listening on %s, op=%s", version, addr, cfg.RP.OPIssuer)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	indexTmpl.Execute(w, map[string]string{"OPIssuer": cfg.RP.OPIssuer})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	state := randomHex(16)
	nonce := randomHex(16)
	verifier := randomHex(32)

	sessions.Lock()
	sessions.m[state] = &session{
		State:        state,
		Nonce:        nonce,
		CodeVerifier: verifier,
		CreatedAt:    time.Now(),
	}
	sessions.Unlock()

	challenge := pkceChallenge(verifier)
	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {cfg.RP.ClientID},
		"redirect_uri":          {cfg.RP.BaseURL + "/callback"},
		"scope":                 {"openid profile email"},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}

	authURL := cfg.RP.OPIssuer + "/authorize?" + params.Encode()
	http.Redirect(w, r, authURL, http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	errParam := r.URL.Query().Get("error")

	if errParam != "" {
		renderResult(w, &tokenResult{Error: errParam + ": " + r.URL.Query().Get("error_description")})
		return
	}

	sessions.RLock()
	sess, ok := sessions.m[state]
	sessions.RUnlock()
	if !ok {
		renderResult(w, &tokenResult{Error: "invalid state parameter"})
		return
	}

	sessions.Lock()
	delete(sessions.m, state)
	sessions.Unlock()

	tokenResp, err := exchangeCode(code, sess.CodeVerifier)
	if err != nil {
		renderResult(w, &tokenResult{Error: fmt.Sprintf("token exchange failed: %v", err)})
		return
	}

	result := &tokenResult{
		IDToken:     tokenResp.IDToken,
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
		ExpiresIn:   tokenResp.ExpiresIn,
		Scope:       tokenResp.Scope,
	}

	claims, valid, err := verifyIDToken(tokenResp.IDToken, sess.Nonce)
	if err != nil {
		result.Error = fmt.Sprintf("ID token verification: %v", err)
	}
	result.IDClaims = claims
	result.IDTokenValid = valid

	userinfo, err := fetchUserinfo(tokenResp.AccessToken)
	if err != nil {
		if result.Error != "" {
			result.Error += "; "
		}
		result.Error += fmt.Sprintf("userinfo fetch: %v", err)
	}
	result.UserInfo = userinfo

	renderResult(w, result)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": version})
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token"`
	Scope       string `json:"scope"`
}

func exchangeCode(code, verifier string) (*tokenResponse, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {cfg.RP.BaseURL + "/callback"},
		"client_id":     {cfg.RP.ClientID},
		"code_verifier": {verifier},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.RP.OPIssuer+"/token", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, err
	}
	return &tr, nil
}

func verifyIDToken(rawToken, expectedNonce string) (map[string]any, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.RP.OPIssuer+"/jwks", nil)
	if err != nil {
		return nil, false, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, false, err
	}

	tok, err := josejwt.ParseSigned(rawToken, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return nil, false, err
	}

	var key any
	for _, k := range jwks.Keys {
		if k.KeyID == tok.Headers[0].KeyID {
			key = k.Key
			break
		}
	}
	if key == nil {
		return nil, false, fmt.Errorf("no matching key for kid %s", tok.Headers[0].KeyID)
	}

	var claims map[string]any
	if err := tok.Claims(key, &claims); err != nil {
		return claims, false, err
	}

	valid := true
	if iss, _ := claims["iss"].(string); iss != cfg.RP.OPIssuer {
		valid = false
	}
	if nonce, _ := claims["nonce"].(string); nonce != expectedNonce {
		valid = false
	}

	return claims, valid, nil
}

func fetchUserinfo(accessToken string) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.RP.OPIssuer+"/userinfo", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var info map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}
	return info, nil
}

func renderResult(w http.ResponseWriter, result *tokenResult) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	resultTmpl.Execute(w, result)
}

func pkceChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
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

var indexTmpl = template.Must(template.New("index").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Mini OIDC — Relying Party</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
           background: #f0f2f5; display: flex; justify-content: center; align-items: center;
           min-height: 100vh; padding: 16px; }
    .card { background: #fff; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,.1);
            padding: 32px; max-width: 400px; width: 100%; text-align: center; }
    h1 { font-size: 20px; margin-bottom: 8px; }
    p { color: #666; margin-bottom: 20px; font-size: 14px; }
    a.btn { display: inline-block; padding: 12px 32px; background: #4f46e5; color: #fff;
            text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 15px; }
    a.btn:hover { background: #4338ca; }
    .info { margin-top: 16px; font-size: 12px; color: #999; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Mini OIDC Relying Party</h1>
    <p>Test the OpenID Connect flow against the mini-oidc provider.</p>
    <a href="/login" class="btn">Login with OIDC</a>
    <p class="info">OP: {{.OPIssuer}}</p>
  </div>
</body>
</html>`))

var tmplFuncs = template.FuncMap{
	"json": func(v any) string {
		b, _ := json.MarshalIndent(v, "", "  ")
		return string(b)
	},
}

var resultTmpl = template.Must(template.New("result").Funcs(tmplFuncs).Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Mini OIDC RP — Result</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
           background: #f0f2f5; padding: 16px; }
    .container { max-width: 800px; margin: 0 auto; }
    h1 { font-size: 20px; margin-bottom: 16px; }
    .error { background: #fee2e2; border: 1px solid #fca5a5; border-radius: 8px;
             padding: 12px 16px; margin-bottom: 16px; color: #991b1b; font-size: 14px; }
    .section { background: #fff; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,.06);
               padding: 20px; margin-bottom: 16px; }
    .section h2 { font-size: 15px; color: #4f46e5; margin-bottom: 12px; display: flex;
                  align-items: center; gap: 8px; }
    .badge { font-size: 11px; padding: 2px 8px; border-radius: 4px; font-weight: 600; }
    .valid { background: #d1fae5; color: #065f46; }
    .invalid { background: #fee2e2; color: #991b1b; }
    pre { background: #f8f9fa; border-radius: 8px; padding: 12px; overflow-x: auto;
          font-size: 13px; line-height: 1.5; white-space: pre-wrap; word-break: break-all; }
    .meta { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 12px; font-size: 13px; color: #666; }
    .meta span { background: #f3f4f6; padding: 4px 10px; border-radius: 4px; }
    a.btn { display: inline-block; padding: 10px 24px; background: #4f46e5; color: #fff;
            text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 14px; margin-top: 8px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Authentication Result</h1>
    {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
    <div class="meta">
      <span>Token Type: {{.TokenType}}</span>
      <span>Expires In: {{.ExpiresIn}}s</span>
      <span>Scope: {{.Scope}}</span>
    </div>
    {{if .IDClaims}}
    <div class="section">
      <h2>ID Token Claims
        {{if .IDTokenValid}}<span class="badge valid">VALID</span>
        {{else}}<span class="badge invalid">INVALID</span>{{end}}
      </h2>
      <pre>{{.IDClaims | json}}</pre>
    </div>
    {{end}}
    {{if .UserInfo}}
    <div class="section">
      <h2>UserInfo Response</h2>
      <pre>{{.UserInfo | json}}</pre>
    </div>
    {{end}}
    {{if .IDToken}}
    <div class="section">
      <h2>Raw ID Token</h2>
      <pre>{{.IDToken}}</pre>
    </div>
    {{end}}
    <a href="/" class="btn">Try Again</a>
  </div>
</body>
</html>`))
