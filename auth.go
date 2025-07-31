package traefik_plugin_auth

import (
    "context"
    "crypto"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "math/big"
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
    AllowedUsers  []string `json:"allowedUsers"`
    BasicAuth     string   `json:"basicAuth"`
}

type JWTHeader struct {
    Alg string `json:"alg"`
    Typ string `json:"typ"`
    Kid string `json:"kid"`
}

type JWTClaims struct {
    Iss           string `json:"iss"`
    Sub           string `json:"sub"`
    Aud           interface{} `json:"aud"`
    Exp           int64  `json:"exp"`
    Iat           int64  `json:"iat"`
    AuthTime      int64  `json:"auth_time,omitempty"`
    Nonce         string `json:"nonce,omitempty"`
    Email         string `json:"email,omitempty"`
    EmailVerified bool   `json:"email_verified,omitempty"`
    Name          string `json:"name,omitempty"`
    PreferredUsername string `json:"preferred_username,omitempty"`
}

type JWK struct {
    Kty string `json:"kty"`
    Use string `json:"use"`
    Kid string `json:"kid"`
    N   string `json:"n"`
    E   string `json:"e"`
}

type JWKSet struct {
    Keys []JWK `json:"keys"`
}

func CreateConfig() *Config {
    return &Config{
        Scopes: []string{"openid", "profile", "email"},
        SkippedPaths: []string{},
        AllowedUsers: []string{},
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

    // Check basic auth first if configured
    if a.validateBasicAuth(req) {
        a.debugLog("Basic auth validation successful, proceeding to next handler")
        a.next.ServeHTTP(rw, req)
        return
    }

    if a.hasValidToken(req) {
        a.debugLog("Valid token found, proceeding to next handler")
        a.next.ServeHTTP(rw, req)
        return
    }

    a.debugLog("No valid authentication, initiating OAuth2 flow")
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

    // Verify the ID token and check user authorization before storing
    if tokenResp.IdToken != "" {
        claims, err := a.verifyJWT(tokenResp.IdToken)
        if err != nil {
            a.debugLog("JWT verification failed during callback: %v", err)
            http.Error(rw, "Unauthorized: Invalid token", http.StatusUnauthorized)
            return
        }

        if !a.isUserAllowed(claims) {
            a.debugLog("User not allowed access during callback")
            http.Error(rw, "Unauthorized: Access denied", http.StatusUnauthorized)
            return
        }
        
        a.debugLog("User %s authorized successfully", claims.Email)
    }

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

    idToken, ok := tokenData["id_token"].(string)
    if !ok || idToken == "" {
        a.debugLog("No ID token found in token data")
        return false
    }

    claims, err := a.verifyJWT(idToken)
    if err != nil {
        a.debugLog("JWT verification failed: %v", err)
        return false
    }

    if !a.isUserAllowed(claims) {
        a.debugLog("User not allowed access")
        return false
    }

    return true
}

func (a *AuthPlugin) verifyJWT(tokenString string) (*JWTClaims, error) {
    parts := strings.Split(tokenString, ".")
    if len(parts) != 3 {
        return nil, fmt.Errorf("invalid JWT format")
    }

    headerData, err := base64.RawURLEncoding.DecodeString(parts[0])
    if err != nil {
        return nil, fmt.Errorf("failed to decode JWT header: %v", err)
    }

    var header JWTHeader
    if err := json.Unmarshal(headerData, &header); err != nil {
        return nil, fmt.Errorf("failed to unmarshal JWT header: %v", err)
    }

    a.debugLog("JWT Header - Algorithm: %s, Type: %s, Key ID: %s", header.Alg, header.Typ, header.Kid)

    // Only allow RS256 algorithm for security
    if header.Alg != "RS256" {
        return nil, fmt.Errorf("unsupported or insecure JWT algorithm: %s (only RS256 allowed)", header.Alg)
    }

    // Verify signature FIRST to prevent timing attacks on claims
    if err := a.verifyRS256Signature(parts, header.Kid); err != nil {
        return nil, fmt.Errorf("signature verification failed: %v", err)
    }

    // Only process claims after signature verification succeeds
    claimsData, err := base64.RawURLEncoding.DecodeString(parts[1])
    if err != nil {
        return nil, fmt.Errorf("failed to decode JWT claims: %v", err)
    }

    var claims JWTClaims
    if err := json.Unmarshal(claimsData, &claims); err != nil {
        return nil, fmt.Errorf("failed to unmarshal JWT claims: %v", err)
    }

    a.debugLog("JWT Claims - Subject: %s, Email: %s, Name: %s, Username: %s, Issuer: %s", 
        claims.Sub, claims.Email, claims.Name, claims.PreferredUsername, claims.Iss)
    a.debugLog("JWT Claims - Expires: %d, Issued: %d, Email Verified: %t", 
        claims.Exp, claims.Iat, claims.EmailVerified)

    // Validate claims after signature verification
    if time.Now().Unix() > claims.Exp {
        return nil, fmt.Errorf("JWT token expired")
    }

    if claims.Iss != a.config.IssuerUrl {
        return nil, fmt.Errorf("invalid issuer: expected %s, got %s", a.config.IssuerUrl, claims.Iss)
    }

    // Validate audience claim
    if !a.validateAudience(claims.Aud) {
        return nil, fmt.Errorf("invalid audience: token not intended for this client")
    }

    return &claims, nil
}

func (a *AuthPlugin) validateAudience(aud interface{}) bool {
    if aud == nil {
        return false
    }

    // Audience can be a string or array of strings
    switch audience := aud.(type) {
    case string:
        return audience == a.config.ClientId
    case []interface{}:
        for _, audItem := range audience {
            if audStr, ok := audItem.(string); ok && audStr == a.config.ClientId {
                return true
            }
        }
        return false
    case []string:
        for _, audStr := range audience {
            if audStr == a.config.ClientId {
                return true
            }
        }
        return false
    default:
        return false
    }
}

func (a *AuthPlugin) verifyRS256Signature(parts []string, keyId string) error {
    jwks, err := a.fetchJWKS()
    if err != nil {
        return fmt.Errorf("failed to fetch JWKS: %v", err)
    }

    var publicKey *rsa.PublicKey
    for _, key := range jwks.Keys {
        if key.Kid == keyId && key.Kty == "RSA" {
            publicKey, err = a.jwkToRSAPublicKey(key)
            if err != nil {
                return fmt.Errorf("failed to convert JWK to RSA public key: %v", err)
            }
            break
        }
    }

    if publicKey == nil {
        return fmt.Errorf("no matching public key found for kid: %s", keyId)
    }

    signatureData, err := base64.RawURLEncoding.DecodeString(parts[2])
    if err != nil {
        return fmt.Errorf("failed to decode signature: %v", err)
    }

    message := parts[0] + "." + parts[1]
    hash := sha256.Sum256([]byte(message))

    err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], signatureData)
    if err != nil {
        return fmt.Errorf("signature verification failed: %v", err)
    }

    a.debugLog("JWT signature verified successfully")
    return nil
}

func (a *AuthPlugin) fetchJWKS() (*JWKSet, error) {
    if a.endpoints.JwksUri == "" {
        return nil, fmt.Errorf("no JWKS URI configured")
    }

    a.debugLog("Fetching JWKS from: %s", a.endpoints.JwksUri)
    resp, err := http.Get(a.endpoints.JwksUri)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("JWKS endpoint returned status: %d", resp.StatusCode)
    }

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }

    var jwks JWKSet
    if err := json.Unmarshal(body, &jwks); err != nil {
        return nil, err
    }

    a.debugLog("Fetched %d keys from JWKS", len(jwks.Keys))
    return &jwks, nil
}

func (a *AuthPlugin) jwkToRSAPublicKey(jwk JWK) (*rsa.PublicKey, error) {
    nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
    if err != nil {
        return nil, err
    }

    eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
    if err != nil {
        return nil, err
    }

    n := big.NewInt(0)
    n.SetBytes(nBytes)

    e := 0
    for _, b := range eBytes {
        e = e*256 + int(b)
    }

    return &rsa.PublicKey{N: n, E: e}, nil
}

func (a *AuthPlugin) isUserAllowed(claims *JWTClaims) bool {
    if len(a.config.AllowedUsers) == 0 {
        a.debugLog("No user restrictions configured, allowing access")
        return true
    }

    if claims.Email == "" {
        a.debugLog("No email found in JWT claims, access denied")
        return false
    }

    for _, allowedEmail := range a.config.AllowedUsers {
        if claims.Email == allowedEmail {
            a.debugLog("User allowed: email %s matches allowed list", claims.Email)
            return true
        }
    }

    a.debugLog("User email %s not in allowed list: %v", claims.Email, a.config.AllowedUsers)
    return false
}

func (a *AuthPlugin) validateBasicAuth(req *http.Request) bool {
    if a.config.BasicAuth == "" {
        return false
    }

    auth := req.Header.Get("Authorization")
    if auth == "" {
        return false
    }

    if !strings.HasPrefix(auth, "Basic ") {
        return false
    }

    credentials, err := base64.StdEncoding.DecodeString(auth[6:])
    if err != nil {
        a.debugLog("Failed to decode basic auth credentials: %v", err)
        return false
    }

    providedAuth := string(credentials)
    if providedAuth == a.config.BasicAuth {
        a.debugLog("Basic auth validation successful")
        return true
    }

    a.debugLog("Basic auth validation failed")
    return false
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