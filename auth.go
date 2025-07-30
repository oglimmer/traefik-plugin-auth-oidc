package traefik_plugin_auth

import (
    "context"
    "crypto/rand"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net/http"
    "net/url"
    "strings"
    "sync"
    "time"
)

type Config struct {
    IssuerUrl     string   `json:"issuerUrl"`
    ClientId      string   `json:"clientId"`
    ClientSecret  string   `json:"clientSecret"`
    RedirectUrl   string   `json:"redirectUrl"`
    Scopes        []string `json:"scopes"`
    SkippedPaths  []string `json:"skippedPaths"`
    Debug         bool     `json:"debug"`
}

func CreateConfig() *Config {
    return &Config{
        Scopes: []string{"openid", "profile", "email"},
        SkippedPaths: []string{},
    }
}

type AuthPlugin struct {
    next      http.Handler
    name      string
    config    *Config
    endpoints *OIDCEndpoints
    sessions  *SessionStore
}

func (a *AuthPlugin) debugLog(format string, v ...interface{}) {
    if a.config.Debug {
        log.Printf("[AUTH-DEBUG] "+format, v...)
    }
}

type SessionStore struct {
    mu       sync.RWMutex
    sessions map[string]map[string]interface{}
}

func NewSessionStore() *SessionStore {
    return &SessionStore{
        sessions: make(map[string]map[string]interface{}),
    }
}

func (s *SessionStore) Set(sessionID string, data map[string]interface{}) {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.sessions[sessionID] = data
}

func (s *SessionStore) Get(sessionID string) (map[string]interface{}, bool) {
    s.mu.RLock()
    defer s.mu.RUnlock()
    data, exists := s.sessions[sessionID]
    return data, exists
}

func (s *SessionStore) Delete(sessionID string) {
    s.mu.Lock()
    defer s.mu.Unlock()
    delete(s.sessions, sessionID)
}

type OIDCEndpoints struct {
    AuthorizationEndpoint string `json:"authorization_endpoint"`
    TokenEndpoint        string `json:"token_endpoint"`
    UserinfoEndpoint     string `json:"userinfo_endpoint"`
    JwksUri             string `json:"jwks_uri"`
    EndSessionEndpoint   string `json:"end_session_endpoint"`
}

type TokenResponse struct {
    AccessToken  string `json:"access_token"`
    TokenType    string `json:"token_type"`
    ExpiresIn    int    `json:"expires_in"`
    RefreshToken string `json:"refresh_token"`
    IdToken      string `json:"id_token"`
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
    if config.Debug {
        log.Printf("[AUTH-DEBUG] Initializing plugin %s with issuer: %s", name, config.IssuerUrl)
    }
    
    if config.IssuerUrl == "" {
        return nil, fmt.Errorf("issuerUrl is required")
    }
    if config.ClientId == "" {
        return nil, fmt.Errorf("clientId is required")
    }
    if config.ClientSecret == "" {
        return nil, fmt.Errorf("clientSecret is required")
    }
    if config.RedirectUrl == "" {
        return nil, fmt.Errorf("redirectUrl is required")
    }

    if config.Debug {
        log.Printf("[AUTH-DEBUG] Discovering OIDC endpoints for: %s", config.IssuerUrl)
    }
    endpoints, err := discoverOIDCEndpoints(config.IssuerUrl, config.Debug)
    if err != nil {
        if config.Debug {
            log.Printf("[AUTH-DEBUG] Failed to discover OIDC endpoints: %v", err)
        }
        return nil, fmt.Errorf("failed to discover OIDC endpoints: %v", err)
    }

    if config.Debug {
        log.Printf("[AUTH-DEBUG] OIDC endpoints discovered - Auth: %s, Token: %s", 
            endpoints.AuthorizationEndpoint, endpoints.TokenEndpoint)
    }

    return &AuthPlugin{
        next:      next,
        name:      name,
        config:    config,
        endpoints: endpoints,
        sessions:  NewSessionStore(),
    }, nil
}

func (a *AuthPlugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
    a.debugLog("Request to: %s %s", req.Method, req.URL.Path)
    
    // Skip authentication for certain paths
    if a.shouldSkipAuth(req.URL.Path) {
        a.debugLog("Skipping auth for path: %s", req.URL.Path)
        a.next.ServeHTTP(rw, req)
        return
    }
    
    if req.URL.Path == "/oauth2/callback" {
        a.debugLog("Handling OAuth2 callback")
        a.handleCallback(rw, req)
        return
    }
    
    if req.URL.Path == "/oauth2/logout" {
        a.debugLog("Handling logout request")
        a.handleLogout(rw, req)
        return
    }

    if a.hasValidToken(req) {
        a.debugLog("Valid token found, proceeding to next handler")
        a.next.ServeHTTP(rw, req)
        return
    }

    a.debugLog("No valid token, initiating OAuth2 flow")
    a.initiateOAuth2Flow(rw, req)
}

func (a *AuthPlugin) shouldSkipAuth(path string) bool {
    for _, skipPath := range a.config.SkippedPaths {
        if strings.HasPrefix(path, skipPath) {
            return true
        }
    }
    return false
}

func (a *AuthPlugin) handleCallback(rw http.ResponseWriter, req *http.Request) {
    code := req.URL.Query().Get("code")
    state := req.URL.Query().Get("state")
    
    a.debugLog("Callback received - code present: %t, state: %s", code != "", state)
    
    if code == "" {
        a.debugLog("No authorization code in callback")
        http.Error(rw, "No code in callback", http.StatusBadRequest)
        return
    }

    expectedState, err := req.Cookie("oauth_state")
    if err != nil || expectedState.Value != state {
        a.debugLog("State validation failed - expected: %s, got: %s, cookie error: %v", 
            expectedState.Value, state, err)
        http.Error(rw, "Invalid state parameter", http.StatusBadRequest)
        return
    }

    a.debugLog("Exchanging authorization code for token")
    tokenResp, err := a.exchangeCodeForToken(code)
    if err != nil {
        a.debugLog("Token exchange failed: %v", err)
        http.Error(rw, "Failed to exchange code for token", http.StatusInternalServerError)
        return
    }

    tokenData := map[string]interface{}{
        "access_token":  tokenResp.AccessToken,
        "refresh_token": tokenResp.RefreshToken,
        "id_token":      tokenResp.IdToken,
        "expires_at":    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second).Unix(),
    }

    a.debugLog("Token received successfully, expires in %d seconds", tokenResp.ExpiresIn)

    // Generate a session ID
    sessionID, err := generateRandomString(32)
    if err != nil {
        a.debugLog("Failed to generate session ID: %v", err)
        http.Error(rw, "Failed to generate session", http.StatusInternalServerError)
        return
    }

    // Store token data in session store
    a.sessions.Set(sessionID, tokenData)
    a.debugLog("Stored token in session store with ID: %s", sessionID)

    // Also set as cookie for persistence
    tokenJSON, err := json.Marshal(tokenData)
    if err != nil {
        a.debugLog("Failed to marshal token data: %v", err)
        http.Error(rw, "Failed to marshal token data", http.StatusInternalServerError)
        return
    }

    encodedToken := base64.StdEncoding.EncodeToString(tokenJSON)

    isSecure := req.TLS != nil || req.Header.Get("X-Forwarded-Proto") == "https"
    a.debugLog("Setting authentication cookie with MaxAge: %d, Secure: %t, TLS: %t, X-Forwarded-Proto: %s", 
        tokenResp.ExpiresIn, isSecure, req.TLS != nil, req.Header.Get("X-Forwarded-Proto"))
    a.debugLog("Cookie domain: %s, path: /, httponly: true", req.Host)
    
    // Set session ID cookie
    sessionCookie := &http.Cookie{
        Name:     "traefik_session_id",
        Value:    sessionID,
        Path:     "/",
        MaxAge:   tokenResp.ExpiresIn,
    }
    http.SetCookie(rw, sessionCookie)
    
    // Also set token cookie as backup
    tokenCookie := &http.Cookie{
        Name:     "traefik_oauth_token",
        Value:    encodedToken,
        Path:     "/",
        MaxAge:   tokenResp.ExpiresIn,
    }
    http.SetCookie(rw, tokenCookie)
    
    a.debugLog("Session cookie set: %s", sessionCookie.String())
    a.debugLog("Token cookie set: %s", tokenCookie.String())

    http.SetCookie(rw, &http.Cookie{
        Name:     "oauth_state",
        Value:    "",
        Path:     "/",
        HttpOnly: true,
        MaxAge:   -1,
    })

    originalURL, err := req.Cookie("original_url")
    redirectURL := "/"
    if err == nil && originalURL.Value != "" {
        redirectURL = originalURL.Value
        a.debugLog("Redirecting to original URL: %s", redirectURL)
        http.SetCookie(rw, &http.Cookie{
            Name:     "original_url",
            Value:    "",
            Path:     "/",
            HttpOnly: true,
            MaxAge:   -1,
        })
    } else {
        a.debugLog("Redirecting to default URL: %s", redirectURL)
    }

    // Use HTTP redirect
    http.Redirect(rw, req, redirectURL, http.StatusFound)
}

func (a *AuthPlugin) handleLogout(rw http.ResponseWriter, req *http.Request) {
    a.debugLog("Processing logout request")
    
    // Get current session/token info for logout URL
    var idToken string
    
    // Try to get ID token from session store first
    if sessionCookie, err := req.Cookie("traefik_session_id"); err == nil {
        if tokenData, exists := a.sessions.Get(sessionCookie.Value); exists {
            if idTokenStr, ok := tokenData["id_token"].(string); ok {
                idToken = idTokenStr
                a.debugLog("Found ID token in session store for logout")
            }
            // Delete from session store
            a.sessions.Delete(sessionCookie.Value)
            a.debugLog("Deleted session from store")
        }
    }
    
    // Fallback to token cookie if no session
    if idToken == "" {
        if cookie, err := req.Cookie("traefik_oauth_token"); err == nil {
            tokenJSON, err := base64.StdEncoding.DecodeString(cookie.Value)
            if err == nil {
                var tokenData map[string]interface{}
                if err := json.Unmarshal(tokenJSON, &tokenData); err == nil {
                    if idTokenStr, ok := tokenData["id_token"].(string); ok {
                        idToken = idTokenStr
                        a.debugLog("Found ID token in cookie for logout")
                    }
                }
            }
        }
    }
    
    // Clear all auth cookies
    a.clearAuthCookies(rw)
    a.debugLog("Cleared authentication cookies")
    
    // Redirect to OIDC provider logout if available
    if a.endpoints.EndSessionEndpoint != "" {
        logoutURL := a.buildLogoutURL(idToken, req)
        a.debugLog("Redirecting to OIDC logout: %s", logoutURL)
        http.Redirect(rw, req, logoutURL, http.StatusFound)
    } else {
        // No OIDC logout endpoint, just redirect to home
        a.debugLog("No OIDC logout endpoint, redirecting to home")
        http.Redirect(rw, req, "/", http.StatusFound)
    }
}

func (a *AuthPlugin) clearAuthCookies(rw http.ResponseWriter) {
    cookies := []string{
        "traefik_session_id",
        "traefik_oauth_token",
        "oauth_state",
        "original_url",
    }
    
    for _, cookieName := range cookies {
        http.SetCookie(rw, &http.Cookie{
            Name:     cookieName,
            Value:    "",
            Path:     "/",
            MaxAge:   -1,
            HttpOnly: true,
        })
    }
}

func (a *AuthPlugin) buildLogoutURL(idToken string, req *http.Request) string {
    logoutURL := a.endpoints.EndSessionEndpoint
    
    // Build logout URL with parameters
    params := url.Values{}
    
    // Add ID token hint if available
    if idToken != "" {
        params.Set("id_token_hint", idToken)
    }
    
    // Add post logout redirect URI
    postLogoutRedirectURI := req.URL.Query().Get("redirect_uri")
    if postLogoutRedirectURI == "" {
        // Default to the current host root
        scheme := "http"
        if req.TLS != nil || req.Header.Get("X-Forwarded-Proto") == "https" {
            scheme = "https"
        }
        postLogoutRedirectURI = fmt.Sprintf("%s://%s/", scheme, req.Host)
    }
    params.Set("post_logout_redirect_uri", postLogoutRedirectURI)
    
    if len(params) > 0 {
        logoutURL += "?" + params.Encode()
    }
    
    return logoutURL
}

func (a *AuthPlugin) hasValidToken(req *http.Request) bool {
    // Debug: log all cookies
    allCookies := req.Cookies()
    cookieNames := make([]string, len(allCookies))
    for i, c := range allCookies {
        cookieNames[i] = c.Name
    }
    a.debugLog("All cookies present: %v", cookieNames)
    
    // First try to get token from session store
    if sessionCookie, err := req.Cookie("traefik_session_id"); err == nil {
        a.debugLog("Found session ID cookie: %s", sessionCookie.Value)
        if tokenData, exists := a.sessions.Get(sessionCookie.Value); exists {
            a.debugLog("Found token in session store")
            return a.validateTokenData(tokenData)
        } else {
            a.debugLog("Session ID not found in session store")
        }
    } else {
        a.debugLog("No session ID cookie found: %v", err)
    }
    
    // Fallback to token cookie
    cookie, err := req.Cookie("traefik_oauth_token")
    if err != nil {
        a.debugLog("No traefik_oauth_token cookie found: %v", err)
        return false
    }

    tokenJSON, err := base64.StdEncoding.DecodeString(cookie.Value)
    if err != nil {
        a.debugLog("Failed to decode token cookie: %v", err)
        return false
    }

    var tokenData map[string]interface{}
    if err := json.Unmarshal(tokenJSON, &tokenData); err != nil {
        a.debugLog("Failed to unmarshal token data: %v", err)
        return false
    }

    return a.validateTokenData(tokenData)
}

func (a *AuthPlugin) validateTokenData(tokenData map[string]interface{}) bool {
    expiresAt, ok := tokenData["expires_at"].(float64)
    if ok {
        if time.Now().Unix() > int64(expiresAt) {
            a.debugLog("Token expired at %d, current time: %d", int64(expiresAt), time.Now().Unix())
            return false
        }
        a.debugLog("Token is valid, expires at %d", int64(expiresAt))
    } else {
        a.debugLog("No expiry time found in token, assuming valid")
    }

    return true
}

func (a *AuthPlugin) initiateOAuth2Flow(rw http.ResponseWriter, req *http.Request) {
    state, err := generateRandomString(32)
    if err != nil {
        a.debugLog("Failed to generate state: %v", err)
        http.Error(rw, "Failed to generate state", http.StatusInternalServerError)
        return
    }

    isSecure := req.TLS != nil || req.Header.Get("X-Forwarded-Proto") == "https"
    a.debugLog("Generated state: %s, Secure cookies: %t", state, isSecure)
    http.SetCookie(rw, &http.Cookie{
        Name:     "oauth_state",
        Value:    state,
        Path:     "/",
        HttpOnly: true,
        Secure:   isSecure,
        SameSite: http.SameSiteDefaultMode,
        MaxAge:   600,
    })

    if !strings.HasPrefix(req.URL.Path, "/oauth2/") {
        originalURL := req.URL.String()
        a.debugLog("Storing original URL: %s", originalURL)
        http.SetCookie(rw, &http.Cookie{
            Name:     "original_url",
            Value:    originalURL,
            Path:     "/",
            HttpOnly: true,
            Secure:   isSecure,
            SameSite: http.SameSiteDefaultMode,
            MaxAge:   600,
        })
    }

    params := url.Values{}
    params.Set("response_type", "code")
    params.Set("client_id", a.config.ClientId)
    params.Set("redirect_uri", a.config.RedirectUrl)
    params.Set("scope", strings.Join(a.config.Scopes, " "))
    params.Set("state", state)

    authURL := a.endpoints.AuthorizationEndpoint + "?" + params.Encode()
    a.debugLog("Redirecting to authorization endpoint: %s", authURL)
    http.Redirect(rw, req, authURL, http.StatusFound)
}

func (a *AuthPlugin) exchangeCodeForToken(code string) (*TokenResponse, error) {
    a.debugLog("Exchanging code for token at: %s", a.endpoints.TokenEndpoint)
    
    data := url.Values{}
    data.Set("grant_type", "authorization_code")
    data.Set("code", code)
    data.Set("redirect_uri", a.config.RedirectUrl)
    data.Set("client_id", a.config.ClientId)
    data.Set("client_secret", a.config.ClientSecret)

    resp, err := http.PostForm(a.endpoints.TokenEndpoint, data)
    if err != nil {
        a.debugLog("HTTP request to token endpoint failed: %v", err)
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        a.debugLog("Token endpoint returned status: %d", resp.StatusCode)
        return nil, fmt.Errorf("token exchange failed with status: %d", resp.StatusCode)
    }

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        a.debugLog("Failed to read token response body: %v", err)
        return nil, err
    }

    a.debugLog("Token response received, body length: %d", len(body))

    var tokenResp TokenResponse
    if err := json.Unmarshal(body, &tokenResp); err != nil {
        a.debugLog("Failed to unmarshal token response: %v", err)
        return nil, err
    }

    return &tokenResp, nil
}

func discoverOIDCEndpoints(issuerURL string, debug bool) (*OIDCEndpoints, error) {
    wellKnownURL := strings.TrimSuffix(issuerURL, "/") + "/.well-known/openid-configuration"
    if debug {
        log.Printf("[AUTH-DEBUG] Fetching OIDC configuration from: %s", wellKnownURL)
    }
    
    resp, err := http.Get(wellKnownURL)
    if err != nil {
        if debug {
            log.Printf("[AUTH-DEBUG] Failed to fetch OIDC configuration: %v", err)
        }
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        if debug {
            log.Printf("[AUTH-DEBUG] OIDC configuration endpoint returned status: %d", resp.StatusCode)
        }
        return nil, fmt.Errorf("failed to fetch OIDC configuration: %d", resp.StatusCode)
    }

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        if debug {
            log.Printf("[AUTH-DEBUG] Failed to read OIDC configuration response: %v", err)
        }
        return nil, err
    }

    if debug {
        log.Printf("[AUTH-DEBUG] OIDC configuration response length: %d", len(body))
    }

    var endpoints OIDCEndpoints
    if err := json.Unmarshal(body, &endpoints); err != nil {
        if debug {
            log.Printf("[AUTH-DEBUG] Failed to unmarshal OIDC configuration: %v", err)
        }
        return nil, err
    }

    return &endpoints, nil
}

func generateRandomString(length int) (string, error) {
    bytes := make([]byte, length)
    if _, err := rand.Read(bytes); err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}