package traefik_plugin_auth

import (
    "bufio"
    "context"
    "crypto"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/tls"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io"
    "io/ioutil"
    "log"
    "math/big"
    "net"
    "net/http"
    "net/url"
    "strconv"
    "strings"
    "sync"
    "time"
)

type Config struct {
    IssuerUrl      string   `json:"issuerUrl"`
    ClientId       string   `json:"clientId"`
    ClientSecret   string   `json:"clientSecret"`
    RedirectUrl    string   `json:"redirectUrl"`
    Scopes         []string `json:"scopes"`
    SkippedPaths   []string `json:"skippedPaths"`
    Debug          bool     `json:"debug"`
    AllowedUsers   []string `json:"allowedUsers"`
    AllowedGroups  []string `json:"allowedGroups"`
    BasicAuth      string   `json:"basicAuth"`
    InsecureTLS    bool     `json:"insecureTLS"`
    DefaultReply   string   `json:"defaultReply"`
    SessionBackend string   `json:"sessionBackend"`
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
    SpecialGroupClaim []string `json:"specialGroupClaim,omitempty"`
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
        AllowedGroups: []string{},
        DefaultReply: "oidc",
        SessionBackend: "in-memory",
    }
}

type AuthPlugin struct {
    next         http.Handler
    name         string
    config       *Config
    endpoints    *OIDCEndpoints
    sessions     SessionBackend
    callbackPath string
}

// Global cache for OIDC endpoints to survive config reloads
var (
    globalEndpointsCache      = make(map[string]*OIDCEndpoints)
    globalEndpointsCacheMutex sync.RWMutex
    globalEndpointsCacheTTL   = 1 * time.Hour
)

// Global cache for JWKS to prevent fetching on every request
type jwksCacheEntry struct {
    jwks      *JWKSet
    timestamp time.Time
}

var (
    globalJWKSCache      = make(map[string]*jwksCacheEntry)
    globalJWKSCacheMutex sync.RWMutex
    globalJWKSCacheTTL   = 1 * time.Hour
)

func (a *AuthPlugin) debugLog(format string, v ...interface{}) {
    if a.config.Debug {
        log.Printf("[AUTH-DEBUG] "+format, v...)
    }
}

func (a *AuthPlugin) getHTTPClient() *http.Client {
    if a.config.InsecureTLS {
        return &http.Client{
            Transport: &http.Transport{
                TLSClientConfig: &tls.Config{
                    InsecureSkipVerify: true,
                },
            },
        }
    }
    return http.DefaultClient
}

type SessionBackend interface {
    Set(sessionID string, data map[string]interface{}) error
    Get(sessionID string) (map[string]interface{}, bool, error)
    Delete(sessionID string) error
}

type InMemorySessionStore struct {
    mu       sync.RWMutex
    sessions map[string]map[string]interface{}
}

func NewInMemorySessionStore() *InMemorySessionStore {
    return &InMemorySessionStore{
        sessions: make(map[string]map[string]interface{}),
    }
}

func (s *InMemorySessionStore) Set(sessionID string, data map[string]interface{}) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.sessions[sessionID] = data
    return nil
}

func (s *InMemorySessionStore) Get(sessionID string) (map[string]interface{}, bool, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()
    data, exists := s.sessions[sessionID]
    return data, exists, nil
}

func (s *InMemorySessionStore) Delete(sessionID string) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    delete(s.sessions, sessionID)
    return nil
}

type RedisSessionStore struct {
    redisURL string
    debug    bool
}

func NewRedisSessionStore(redisURL string, debug bool) *RedisSessionStore {
    return &RedisSessionStore{
        redisURL: redisURL,
        debug:    debug,
    }
}

func (r *RedisSessionStore) debugLog(format string, v ...interface{}) {
    if r.debug {
        log.Printf("[REDIS-DEBUG] "+format, v...)
    }
}

func (r *RedisSessionStore) parseRedisURL() (host, port string, err error) {
    // Handle different URL formats
    redisURL := r.redisURL
    
    // Remove protocol if present
    if strings.HasPrefix(redisURL, "http://") {
        redisURL = strings.TrimPrefix(redisURL, "http://")
    } else if strings.HasPrefix(redisURL, "redis://") {
        redisURL = strings.TrimPrefix(redisURL, "redis://")
    }
    
    // Split host and port
    if strings.Contains(redisURL, ":") {
        host, port, err = net.SplitHostPort(redisURL)
        if err != nil {
            return "", "", err
        }
    } else {
        host = redisURL
        port = "6379" // Default Redis port
    }
    
    return host, port, nil
}

func (r *RedisSessionStore) Set(sessionID string, data map[string]interface{}) error {
    r.debugLog("Setting session data for ID: %s", sessionID)
    
    jsonData, err := json.Marshal(data)
    if err != nil {
        return fmt.Errorf("failed to marshal session data: %v", err)
    }
    
    // Parse Redis URL to get host and port
    redisHost, redisPort, err := r.parseRedisURL()
    if err != nil {
        return fmt.Errorf("failed to parse Redis URL: %v", err)
    }
    
    // Connect to Redis using TCP
    conn, err := net.DialTimeout("tcp", net.JoinHostPort(redisHost, redisPort), 5*time.Second)
    if err != nil {
        return fmt.Errorf("failed to connect to Redis: %v", err)
    }
    defer conn.Close()
    
    // Set a timeout for the connection
    conn.SetDeadline(time.Now().Add(10 * time.Second))
    
    key := fmt.Sprintf("session:%s", sessionID)
    
    // Send Redis SET command using RESP protocol
    // Format: *3\r\n$3\r\nSET\r\n$<keylen>\r\n<key>\r\n$<vallen>\r\n<value>\r\n
    cmd := fmt.Sprintf("*3\r\n$3\r\nSET\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n", 
        len(key), key, len(jsonData), string(jsonData))
    
    _, err = conn.Write([]byte(cmd))
    if err != nil {
        return fmt.Errorf("failed to send SET command to Redis: %v", err)
    }
    
    // Read response
    reader := bufio.NewReader(conn)
    response, err := reader.ReadString('\n')
    if err != nil {
        return fmt.Errorf("failed to read Redis response: %v", err)
    }
    
    if !strings.HasPrefix(response, "+OK") {
        return fmt.Errorf("Redis SET command failed: %s", strings.TrimSpace(response))
    }
    
    r.debugLog("Session data stored successfully in Redis for ID: %s", sessionID)
    return nil
}

func (r *RedisSessionStore) Get(sessionID string) (map[string]interface{}, bool, error) {
    r.debugLog("Getting session data for ID: %s", sessionID)
    
    // Parse Redis URL to get host and port
    redisHost, redisPort, err := r.parseRedisURL()
    if err != nil {
        return nil, false, fmt.Errorf("failed to parse Redis URL: %v", err)
    }
    
    // Connect to Redis using TCP
    conn, err := net.DialTimeout("tcp", net.JoinHostPort(redisHost, redisPort), 5*time.Second)
    if err != nil {
        return nil, false, fmt.Errorf("failed to connect to Redis: %v", err)
    }
    defer conn.Close()
    
    // Set a timeout for the connection
    conn.SetDeadline(time.Now().Add(10 * time.Second))
    
    key := fmt.Sprintf("session:%s", sessionID)
    
    // Send Redis GET command using RESP protocol
    // Format: *2\r\n$3\r\nGET\r\n$<keylen>\r\n<key>\r\n
    cmd := fmt.Sprintf("*2\r\n$3\r\nGET\r\n$%d\r\n%s\r\n", len(key), key)
    
    _, err = conn.Write([]byte(cmd))
    if err != nil {
        return nil, false, fmt.Errorf("failed to send GET command to Redis: %v", err)
    }
    
    // Read response
    reader := bufio.NewReader(conn)
    response, err := reader.ReadString('\n')
    if err != nil {
        return nil, false, fmt.Errorf("failed to read Redis response: %v", err)
    }
    
    response = strings.TrimSpace(response)
    
    // Handle null response (key not found)
    if response == "$-1" {
        r.debugLog("Session not found in Redis for ID: %s", sessionID)
        return nil, false, nil
    }
    
    // Handle bulk string response
    if strings.HasPrefix(response, "$") {
        // Parse the length
        lengthStr := response[1:]
        length, err := strconv.Atoi(lengthStr)
        if err != nil {
            return nil, false, fmt.Errorf("failed to parse Redis response length: %v", err)
        }
        
        if length == -1 {
            r.debugLog("Session not found in Redis for ID: %s", sessionID)
            return nil, false, nil
        }
        
        // Read the actual data
        data := make([]byte, length+2) // +2 for \r\n
        _, err = io.ReadFull(reader, data)
        if err != nil {
            return nil, false, fmt.Errorf("failed to read Redis data: %v", err)
        }
        
        // Remove trailing \r\n
        jsonData := data[:length]
        
        var sessionData map[string]interface{}
        if err := json.Unmarshal(jsonData, &sessionData); err != nil {
            return nil, false, fmt.Errorf("failed to unmarshal session data: %v", err)
        }
        
        r.debugLog("Session data retrieved successfully from Redis for ID: %s", sessionID)
        return sessionData, true, nil
    }
    
    return nil, false, fmt.Errorf("unexpected Redis response format: %s", response)
}

func (r *RedisSessionStore) Delete(sessionID string) error {
    r.debugLog("Deleting session data for ID: %s", sessionID)
    
    // Parse Redis URL to get host and port
    redisHost, redisPort, err := r.parseRedisURL()
    if err != nil {
        return fmt.Errorf("failed to parse Redis URL: %v", err)
    }
    
    // Connect to Redis using TCP
    conn, err := net.DialTimeout("tcp", net.JoinHostPort(redisHost, redisPort), 5*time.Second)
    if err != nil {
        return fmt.Errorf("failed to connect to Redis: %v", err)
    }
    defer conn.Close()
    
    // Set a timeout for the connection
    conn.SetDeadline(time.Now().Add(10 * time.Second))
    
    key := fmt.Sprintf("session:%s", sessionID)
    
    // Send Redis DEL command using RESP protocol
    // Format: *2\r\n$3\r\nDEL\r\n$<keylen>\r\n<key>\r\n
    cmd := fmt.Sprintf("*2\r\n$3\r\nDEL\r\n$%d\r\n%s\r\n", len(key), key)
    
    _, err = conn.Write([]byte(cmd))
    if err != nil {
        return fmt.Errorf("failed to send DEL command to Redis: %v", err)
    }
    
    // Read response
    reader := bufio.NewReader(conn)
    response, err := reader.ReadString('\n')
    if err != nil {
        return fmt.Errorf("failed to read Redis response: %v", err)
    }
    
    response = strings.TrimSpace(response)
    
    // Handle integer response (number of keys deleted)
    if strings.HasPrefix(response, ":") {
        r.debugLog("Session data deleted successfully from Redis for ID: %s", sessionID)
        return nil
    }
    
    return fmt.Errorf("unexpected Redis DEL response: %s", response)
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
    endpoints, err := discoverOIDCEndpoints(config.IssuerUrl, config.Debug, config.InsecureTLS)
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

    // Extract callback path from RedirectUrl
    redirectURL, err := url.Parse(config.RedirectUrl)
    if err != nil {
        return nil, fmt.Errorf("invalid redirectUrl: %v", err)
    }
    callbackPath := redirectURL.Path
    if callbackPath == "" {
        callbackPath = "/oauth2/callback"
    }

    if config.Debug {
        log.Printf("[AUTH-DEBUG] Callback path extracted: %s", callbackPath)
    }

    // Create session backend based on configuration
    var sessionBackend SessionBackend
    if config.SessionBackend == "" || config.SessionBackend == "in-memory" {
        if config.Debug {
            log.Printf("[AUTH-DEBUG] Using in-memory session backend")
        }
        sessionBackend = NewInMemorySessionStore()
    } else if strings.HasPrefix(config.SessionBackend, "redis:") {
        redisURL := strings.TrimPrefix(config.SessionBackend, "redis:")
        if config.Debug {
            log.Printf("[AUTH-DEBUG] Using Redis session backend with URL: %s", redisURL)
        }
        sessionBackend = NewRedisSessionStore(redisURL, config.Debug)
    } else {
        return nil, fmt.Errorf("unsupported session backend: %s (supported: 'in-memory' or 'redis:REDIS_URL')", config.SessionBackend)
    }

    return &AuthPlugin{
        next:         next,
        name:         name,
        config:       config,
        endpoints:    endpoints,
        sessions:     sessionBackend,
        callbackPath: callbackPath,
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
    
    if req.URL.Path == a.callbackPath {
        a.debugLog("Handling OAuth2 callback")
        a.handleCallback(rw, req)
        return
    }
    
    // Handle logout relative to callback path
    logoutPath := strings.Replace(a.callbackPath, "/callback", "/logout", 1)
    if req.URL.Path == logoutPath {
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

    a.debugLog("No valid authentication, handling failure with defaultReply: %s", a.config.DefaultReply)
    a.handleAuthFailure(rw, req)
}

func (a *AuthPlugin) handleAuthFailure(rw http.ResponseWriter, req *http.Request) {
    if a.config.DefaultReply == "basic" {
        a.debugLog("Sending WWW-Authenticate header for basic auth")
        rw.Header().Set("WWW-Authenticate", "Basic realm=\"Authentication Required\"")
        http.Error(rw, "Authentication required", http.StatusUnauthorized)
        return
    }
    
    // Default to OIDC flow
    a.debugLog("Initiating OAuth2 flow")
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
    if err := a.sessions.Set(sessionID, tokenData); err != nil {
        a.debugLog("Failed to store token in session store: %v", err)
        http.Error(rw, "Failed to store session", http.StatusInternalServerError)
        return
    }
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
        if tokenData, exists, err := a.sessions.Get(sessionCookie.Value); err == nil && exists {
            if idTokenStr, ok := tokenData["id_token"].(string); ok {
                idToken = idTokenStr
                a.debugLog("Found ID token in session store for logout")
            }
            // Delete from session store
            if err := a.sessions.Delete(sessionCookie.Value); err != nil {
                a.debugLog("Failed to delete session from store: %v", err)
            } else {
                a.debugLog("Deleted session from store")
            }
        } else if err != nil {
            a.debugLog("Failed to get session from store: %v", err)
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
        if tokenData, exists, err := a.sessions.Get(sessionCookie.Value); err == nil && exists {
            a.debugLog("Found token in session store")
            return a.validateTokenData(tokenData)
        } else if err != nil {
            a.debugLog("Failed to get session from store: %v", err)
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
    a.debugLog("JWT Claims - Expires: %d, Issued: %d, Email Verified: %t, Special Groups: %v", 
        claims.Exp, claims.Iat, claims.EmailVerified, claims.SpecialGroupClaim)

    // Print the complete decoded JWT when debug is enabled
    decodedJWT := map[string]interface{}{
        "header": map[string]interface{}{
            "alg": header.Alg,
            "typ": header.Typ,
            "kid": header.Kid,
        },
        "payload": claims,
    }
    if decodedJWTJSON, err := json.MarshalIndent(decodedJWT, "", "  "); err == nil {
        a.debugLog("Decoded JWT:\n%s", string(decodedJWTJSON))
    }

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

    // Check cache first
    globalJWKSCacheMutex.RLock()
    if entry, exists := globalJWKSCache[a.endpoints.JwksUri]; exists {
        if time.Since(entry.timestamp) < globalJWKSCacheTTL {
            a.debugLog("Using cached JWKS (age: %v)", time.Since(entry.timestamp))
            globalJWKSCacheMutex.RUnlock()
            return entry.jwks, nil
        }
    }
    globalJWKSCacheMutex.RUnlock()

    a.debugLog("Fetching JWKS from: %s", a.endpoints.JwksUri)
    client := a.getHTTPClient()
    resp, err := client.Get(a.endpoints.JwksUri)
    if err != nil {
        a.debugLog("Failed to fetch JWKS: %v", err)

        // Try to use stale cache as fallback
        globalJWKSCacheMutex.RLock()
        if entry, exists := globalJWKSCache[a.endpoints.JwksUri]; exists {
            a.debugLog("Using stale cached JWKS as fallback (age: %v)", time.Since(entry.timestamp))
            globalJWKSCacheMutex.RUnlock()
            return entry.jwks, nil
        }
        globalJWKSCacheMutex.RUnlock()

        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        a.debugLog("JWKS endpoint returned status: %d", resp.StatusCode)

        // Try to use stale cache as fallback
        globalJWKSCacheMutex.RLock()
        if entry, exists := globalJWKSCache[a.endpoints.JwksUri]; exists {
            a.debugLog("Using stale cached JWKS as fallback (age: %v)", time.Since(entry.timestamp))
            globalJWKSCacheMutex.RUnlock()
            return entry.jwks, nil
        }
        globalJWKSCacheMutex.RUnlock()

        return nil, fmt.Errorf("JWKS endpoint returned status: %d", resp.StatusCode)
    }

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        a.debugLog("Failed to read JWKS response: %v", err)

        // Try to use stale cache as fallback
        globalJWKSCacheMutex.RLock()
        if entry, exists := globalJWKSCache[a.endpoints.JwksUri]; exists {
            a.debugLog("Using stale cached JWKS as fallback (age: %v)", time.Since(entry.timestamp))
            globalJWKSCacheMutex.RUnlock()
            return entry.jwks, nil
        }
        globalJWKSCacheMutex.RUnlock()

        return nil, err
    }

    var jwks JWKSet
    if err := json.Unmarshal(body, &jwks); err != nil {
        a.debugLog("Failed to unmarshal JWKS: %v", err)

        // Try to use stale cache as fallback
        globalJWKSCacheMutex.RLock()
        if entry, exists := globalJWKSCache[a.endpoints.JwksUri]; exists {
            a.debugLog("Using stale cached JWKS as fallback (age: %v)", time.Since(entry.timestamp))
            globalJWKSCacheMutex.RUnlock()
            return entry.jwks, nil
        }
        globalJWKSCacheMutex.RUnlock()

        return nil, err
    }

    // Cache the fresh JWKS
    globalJWKSCacheMutex.Lock()
    globalJWKSCache[a.endpoints.JwksUri] = &jwksCacheEntry{
        jwks:      &jwks,
        timestamp: time.Now(),
    }
    globalJWKSCacheMutex.Unlock()

    a.debugLog("Fetched and cached %d keys from JWKS", len(jwks.Keys))
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
    // If no restrictions are configured, allow access
    if len(a.config.AllowedUsers) == 0 && len(a.config.AllowedGroups) == 0 {
        a.debugLog("No user or group restrictions configured, allowing access")
        return true
    }

    // Check allowed users first
    if len(a.config.AllowedUsers) > 0 && claims.Email != "" {
        for _, allowedEmail := range a.config.AllowedUsers {
            if claims.Email == allowedEmail {
                a.debugLog("User allowed: email %s matches allowed list", claims.Email)
                return true
            }
        }
    }

    // Check allowed groups
    if len(a.config.AllowedGroups) > 0 && len(claims.SpecialGroupClaim) > 0 {
        for _, userGroup := range claims.SpecialGroupClaim {
            for _, allowedGroup := range a.config.AllowedGroups {
                if userGroup == allowedGroup {
                    a.debugLog("User allowed: group %s matches allowed groups", userGroup)
                    return true
                }
            }
        }
    }

    a.debugLog("User access denied - email %s not in allowed users %v and groups %v not in allowed groups %v", 
        claims.Email, a.config.AllowedUsers, claims.SpecialGroupClaim, a.config.AllowedGroups)
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

    // Don't store original URL for OAuth2 related paths
    callbackDir := strings.TrimSuffix(a.callbackPath, "/callback")
    if !strings.HasPrefix(req.URL.Path, callbackDir+"/") {
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

    client := a.getHTTPClient()
    resp, err := client.PostForm(a.endpoints.TokenEndpoint, data)
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

func discoverOIDCEndpoints(issuerURL string, debug bool, insecureTLS bool) (*OIDCEndpoints, error) {
    // Check global cache first
    globalEndpointsCacheMutex.RLock()
    if cachedEndpoints, exists := globalEndpointsCache[issuerURL]; exists {
        if debug {
            log.Printf("[AUTH-DEBUG] Using cached OIDC endpoints for %s", issuerURL)
        }
        globalEndpointsCacheMutex.RUnlock()
        return cachedEndpoints, nil
    }
    globalEndpointsCacheMutex.RUnlock()

    wellKnownURL := strings.TrimSuffix(issuerURL, "/") + "/.well-known/openid-configuration"
    if debug {
        log.Printf("[AUTH-DEBUG] Fetching OIDC configuration from: %s", wellKnownURL)
    }

    client := http.DefaultClient
    if insecureTLS {
        client = &http.Client{
            Transport: &http.Transport{
                TLSClientConfig: &tls.Config{
                    InsecureSkipVerify: true,
                },
            },
        }
        if debug {
            log.Printf("[AUTH-DEBUG] Using insecure TLS for OIDC discovery")
        }
    }

    resp, err := client.Get(wellKnownURL)
    if err != nil {
        if debug {
            log.Printf("[AUTH-DEBUG] Failed to fetch OIDC configuration: %v", err)
        }
        return loadFallbackConfiguration(issuerURL, debug)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        if debug {
            log.Printf("[AUTH-DEBUG] OIDC configuration endpoint returned status: %d", resp.StatusCode)
        }
        return loadFallbackConfiguration(issuerURL, debug)
    }

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        if debug {
            log.Printf("[AUTH-DEBUG] Failed to read OIDC configuration response: %v", err)
        }
        return loadFallbackConfiguration(issuerURL, debug)
    }

    if debug {
        log.Printf("[AUTH-DEBUG] OIDC configuration response length: %d", len(body))
    }

    var endpoints OIDCEndpoints
    if err := json.Unmarshal(body, &endpoints); err != nil {
        if debug {
            log.Printf("[AUTH-DEBUG] Failed to unmarshal OIDC configuration: %v", err)
        }
        return loadFallbackConfiguration(issuerURL, debug)
    }

    // Cache the successfully discovered endpoints
    globalEndpointsCacheMutex.Lock()
    globalEndpointsCache[issuerURL] = &endpoints
    globalEndpointsCacheMutex.Unlock()

    if debug {
        log.Printf("[AUTH-DEBUG] Cached OIDC endpoints for %s", issuerURL)
    }

    return &endpoints, nil
}

func loadFallbackConfiguration(issuerURL string, debug bool) (*OIDCEndpoints, error) {
    if debug {
        log.Printf("[AUTH-DEBUG] Loading fallback OIDC configuration from ./openid-configuration.json")
    }

    body, err := ioutil.ReadFile("./openid-configuration.json")
    if err != nil {
        if debug {
            log.Printf("[AUTH-DEBUG] Failed to read fallback configuration file: %v", err)
        }

        // Try to use previously cached endpoints as last resort
        globalEndpointsCacheMutex.RLock()
        cachedEndpoints, exists := globalEndpointsCache[issuerURL]
        globalEndpointsCacheMutex.RUnlock()

        if exists {
            if debug {
                log.Printf("[AUTH-DEBUG] Using previously cached OIDC endpoints as fallback for %s", issuerURL)
            }
            return cachedEndpoints, nil
        }

        return nil, fmt.Errorf("failed to load fallback OIDC configuration and no cached endpoints available: %v", err)
    }

    var endpoints OIDCEndpoints
    if err := json.Unmarshal(body, &endpoints); err != nil {
        if debug {
            log.Printf("[AUTH-DEBUG] Failed to unmarshal fallback OIDC configuration: %v", err)
        }

        // Try to use previously cached endpoints as last resort
        globalEndpointsCacheMutex.RLock()
        cachedEndpoints, exists := globalEndpointsCache[issuerURL]
        globalEndpointsCacheMutex.RUnlock()

        if exists {
            if debug {
                log.Printf("[AUTH-DEBUG] Using previously cached OIDC endpoints as fallback for %s", issuerURL)
            }
            return cachedEndpoints, nil
        }

        return nil, fmt.Errorf("failed to parse fallback OIDC configuration and no cached endpoints available: %v", err)
    }

    // Cache the fallback endpoints too
    globalEndpointsCacheMutex.Lock()
    globalEndpointsCache[issuerURL] = &endpoints
    globalEndpointsCacheMutex.Unlock()

    if debug {
        log.Printf("[AUTH-DEBUG] Fallback OIDC configuration loaded successfully and cached")
        log.Printf("[AUTH-DEBUG] Fallback endpoints - Auth: %s, Token: %s",
            endpoints.AuthorizationEndpoint, endpoints.TokenEndpoint)
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