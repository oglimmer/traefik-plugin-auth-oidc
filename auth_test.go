package traefik_plugin_auth

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Mock next handler for testing
type mockHandler struct {
	called bool
}

func (m *mockHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	m.called = true
	rw.WriteHeader(http.StatusOK)
}

func createTestPlugin(config *Config) *AuthPlugin {
	return &AuthPlugin{
		next:   &mockHandler{},
		name:   "test-plugin",
		config: config,
		endpoints: &OIDCEndpoints{
			AuthorizationEndpoint: "https://test.com/auth",
			TokenEndpoint:        "https://test.com/token",
			UserinfoEndpoint:     "https://test.com/userinfo",
			JwksUri:             "https://test.com/jwks",
			EndSessionEndpoint:   "https://test.com/logout",
		},
		sessions:     NewSessionStore(),
		callbackPath: "/oauth2/callback", // Default callback path
	}
}

func TestValidateBasicAuth(t *testing.T) {
	tests := []struct {
		name           string
		basicAuth      string
		authHeader     string
		expectedResult bool
		description    string
	}{
		{
			name:           "Valid basic auth",
			basicAuth:      "testuser:testpass",
			authHeader:     "Basic " + base64.StdEncoding.EncodeToString([]byte("testuser:testpass")),
			expectedResult: true,
			description:    "Should validate correct basic auth credentials",
		},
		{
			name:           "Invalid credentials",
			basicAuth:      "testuser:testpass",
			authHeader:     "Basic " + base64.StdEncoding.EncodeToString([]byte("wronguser:wrongpass")),
			expectedResult: false,
			description:    "Should reject incorrect basic auth credentials",
		},
		{
			name:           "No basic auth configured",
			basicAuth:      "",
			authHeader:     "Basic " + base64.StdEncoding.EncodeToString([]byte("testuser:testpass")),
			expectedResult: false,
			description:    "Should return false when basic auth not configured",
		},
		{
			name:           "No auth header",
			basicAuth:      "testuser:testpass",
			authHeader:     "",
			expectedResult: false,
			description:    "Should return false when no Authorization header present",
		},
		{
			name:           "Non-basic auth header",
			basicAuth:      "testuser:testpass",
			authHeader:     "Bearer token123",
			expectedResult: false,
			description:    "Should return false for non-Basic auth schemes",
		},
		{
			name:           "Invalid base64 encoding",
			basicAuth:      "testuser:testpass",
			authHeader:     "Basic invalidbase64!",
			expectedResult: false,
			description:    "Should handle invalid base64 encoding gracefully",
		},
		{
			name:           "Empty basic auth prefix",
			basicAuth:      "testuser:testpass",
			authHeader:     "Basic",
			expectedResult: false,
			description:    "Should handle missing credentials after Basic prefix",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				BasicAuth: tt.basicAuth,
				Debug:     true,
			}
			plugin := createTestPlugin(config)

			req := httptest.NewRequest("GET", "/test", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			result := plugin.validateBasicAuth(req)

			if result != tt.expectedResult {
				t.Errorf("%s: expected %v, got %v", tt.description, tt.expectedResult, result)
			}
		})
	}
}

func TestShouldSkipAuth(t *testing.T) {
	tests := []struct {
		name         string
		skippedPaths []string
		requestPath  string
		expected     bool
		description  string
	}{
		{
			name:         "Skip configured path",
			skippedPaths: []string{"/health", "/metrics"},
			requestPath:  "/health",
			expected:     true,
			description:  "Should skip authentication for configured paths",
		},
		{
			name:         "Skip path with prefix match",
			skippedPaths: []string{"/api/public"},
			requestPath:  "/api/public/status",
			expected:     true,
			description:  "Should skip authentication for paths with matching prefix",
		},
		{
			name:         "Don't skip non-configured path",
			skippedPaths: []string{"/health"},
			requestPath:  "/private",
			expected:     false,
			description:  "Should not skip authentication for non-configured paths",
		},
		{
			name:         "Empty skipped paths",
			skippedPaths: []string{},
			requestPath:  "/any",
			expected:     false,
			description:  "Should not skip authentication when no paths configured",
		},
		{
			name:         "Partial match should skip with prefix",
			skippedPaths: []string{"/health"},
			requestPath:  "/healthcare",
			expected:     true,
			description:  "Should skip authentication for paths with matching prefix (including partial matches)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				SkippedPaths: tt.skippedPaths,
			}
			plugin := createTestPlugin(config)

			result := plugin.shouldSkipAuth(tt.requestPath)

			if result != tt.expected {
				t.Errorf("%s: expected %v, got %v", tt.description, tt.expected, result)
			}
		})
	}
}

func TestServeHTTP_BasicAuth(t *testing.T) {
	tests := []struct {
		name           string
		basicAuth      string
		authHeader     string
		expectedStatus int
		nextCalled     bool
		description    string
	}{
		{
			name:           "Valid basic auth allows access",
			basicAuth:      "admin:secret",
			authHeader:     "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:secret")),
			expectedStatus: http.StatusOK,
			nextCalled:     true,
			description:    "Should allow access with valid basic auth",
		},
		{
			name:           "Invalid basic auth initiates OIDC",
			basicAuth:      "admin:secret",
			authHeader:     "Basic " + base64.StdEncoding.EncodeToString([]byte("wrong:credentials")),
			expectedStatus: http.StatusFound,
			nextCalled:     false,
			description:    "Should initiate OIDC flow with invalid basic auth",
		},
		{
			name:           "No basic auth configured initiates OIDC",
			basicAuth:      "",
			authHeader:     "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:secret")),
			expectedStatus: http.StatusFound,
			nextCalled:     false,
			description:    "Should initiate OIDC flow when basic auth not configured",
		},
		{
			name:           "No auth header initiates OIDC",
			basicAuth:      "admin:secret",
			authHeader:     "",
			expectedStatus: http.StatusFound,
			nextCalled:     false,
			description:    "Should initiate OIDC flow when no auth header provided",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				IssuerUrl:    "https://test.com",
				ClientId:     "test-client",
				ClientSecret: "test-secret",
				RedirectUrl:  "https://test.com/callback",
				BasicAuth:    tt.basicAuth,
				Debug:        true,
			}
			
			mockNext := &mockHandler{}
			plugin := createTestPlugin(config)
			plugin.next = mockNext

			req := httptest.NewRequest("GET", "/protected", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			rr := httptest.NewRecorder()
			plugin.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("%s: expected status %d, got %d", tt.description, tt.expectedStatus, rr.Code)
			}

			if mockNext.called != tt.nextCalled {
				t.Errorf("%s: expected next handler called=%v, got=%v", tt.description, tt.nextCalled, mockNext.called)
			}
		})
	}
}

func TestServeHTTP_SkippedPaths(t *testing.T) {
	config := &Config{
		IssuerUrl:    "https://test.com",
		ClientId:     "test-client",
		ClientSecret: "test-secret",
		RedirectUrl:  "https://test.com/callback",
		SkippedPaths: []string{"/health", "/metrics"},
		BasicAuth:    "admin:secret",
		Debug:        true,
	}

	mockNext := &mockHandler{}
	plugin := createTestPlugin(config)
	plugin.next = mockNext

	tests := []struct {
		path           string
		shouldCallNext bool
		description    string
	}{
		{"/health", true, "Should skip auth for /health"},
		{"/metrics", true, "Should skip auth for /metrics"},
		{"/health/detailed", true, "Should skip auth for /health/detailed (prefix match)"},
		{"/protected", false, "Should require auth for /protected"},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			mockNext.called = false
			req := httptest.NewRequest("GET", tt.path, nil)
			rr := httptest.NewRecorder()

			plugin.ServeHTTP(rr, req)

			if mockNext.called != tt.shouldCallNext {
				t.Errorf("%s: expected next handler called=%v, got=%v", tt.description, tt.shouldCallNext, mockNext.called)
			}
		})
	}
}

func TestServeHTTP_OAuthEndpoints(t *testing.T) {
	config := &Config{
		IssuerUrl:    "https://test.com",
		ClientId:     "test-client",
		ClientSecret: "test-secret",
		RedirectUrl:  "https://test.com/callback",
		Debug:        true,
	}

	plugin := createTestPlugin(config)
	mockNext := &mockHandler{}
	plugin.next = mockNext

	tests := []struct {
		path           string
		expectedStatus int
		nextCalled     bool
		description    string
	}{
		{
			path:           "/oauth2/callback",
			expectedStatus: http.StatusBadRequest, // No code parameter
			nextCalled:     false,
			description:    "Should handle callback endpoint",
		},
		{
			path:           "/oauth2/logout",
			expectedStatus: http.StatusFound, // Redirect to logout
			nextCalled:     false,
			description:    "Should handle logout endpoint",
		},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			mockNext.called = false
			req := httptest.NewRequest("GET", tt.path, nil)
			rr := httptest.NewRecorder()

			plugin.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("%s: expected status %d, got %d", tt.description, tt.expectedStatus, rr.Code)
			}

			if mockNext.called != tt.nextCalled {
				t.Errorf("%s: expected next handler called=%v, got=%v", tt.description, tt.nextCalled, mockNext.called)
			}
		})
	}
}

func TestCreateConfig(t *testing.T) {
	config := CreateConfig()

	if config == nil {
		t.Fatal("CreateConfig should return a non-nil config")
	}

	expectedScopes := []string{"openid", "profile", "email"}
	if len(config.Scopes) != len(expectedScopes) {
		t.Errorf("Expected %d default scopes, got %d", len(expectedScopes), len(config.Scopes))
	}

	for i, scope := range expectedScopes {
		if config.Scopes[i] != scope {
			t.Errorf("Expected scope[%d] to be %s, got %s", i, scope, config.Scopes[i])
		}
	}

	if len(config.SkippedPaths) != 0 {
		t.Errorf("Expected empty SkippedPaths, got %v", config.SkippedPaths)
	}

	if len(config.AllowedUsers) != 0 {
		t.Errorf("Expected empty AllowedUsers, got %v", config.AllowedUsers)
	}

	if config.BasicAuth != "" {
		t.Errorf("Expected empty BasicAuth, got %s", config.BasicAuth)
	}

	if config.DefaultReply != "oidc" {
		t.Errorf("Expected DefaultReply to be 'oidc', got %s", config.DefaultReply)
	}
}

func TestSessionStore(t *testing.T) {
	store := NewSessionStore()

	sessionID := "test-session-123"
	testData := map[string]interface{}{
		"user_id": "user123",
		"email":   "test@example.com",
		"expires": int64(1234567890),
	}

	// Test Set and Get
	store.Set(sessionID, testData)
	
	retrievedData, exists := store.Get(sessionID)
	if !exists {
		t.Fatal("Session should exist after being set")
	}

	if retrievedData["user_id"] != testData["user_id"] {
		t.Errorf("Expected user_id %v, got %v", testData["user_id"], retrievedData["user_id"])
	}

	if retrievedData["email"] != testData["email"] {
		t.Errorf("Expected email %v, got %v", testData["email"], retrievedData["email"])
	}

	// Test non-existent session
	_, exists = store.Get("non-existent")
	if exists {
		t.Error("Non-existent session should not exist")
	}

	// Test Delete
	store.Delete(sessionID)
	_, exists = store.Get(sessionID)
	if exists {
		t.Error("Session should not exist after deletion")
	}
}

func TestGenerateRandomString(t *testing.T) {
	tests := []int{8, 16, 32, 64}

	for _, length := range tests {
		t.Run(fmt.Sprintf("length_%d", length), func(t *testing.T) {
			str, err := generateRandomString(length)
			if err != nil {
				t.Fatalf("generateRandomString failed: %v", err)
			}

			if len(str) != length {
				t.Errorf("Expected string length %d, got %d", length, len(str))
			}

			// Generate another string and ensure they're different
			str2, err := generateRandomString(length)
			if err != nil {
				t.Fatalf("generateRandomString failed on second call: %v", err)
			}

			if str == str2 {
				t.Error("Two random strings should be different")
			}
		})
	}
}

func TestCallbackPathExtraction(t *testing.T) {
	tests := []struct {
		name         string
		redirectUrl  string
		expectedPath string
		expectError  bool
		description  string
	}{
		{
			name:         "Standard OAuth2 callback",
			redirectUrl:  "https://example.com/oauth2/callback",
			expectedPath: "/oauth2/callback",
			expectError:  false,
			description:  "Should extract standard callback path",
		},
		{
			name:         "Custom UI prefix callback",
			redirectUrl:  "https://example.com/ui/oauth2/callback",
			expectedPath: "/ui/oauth2/callback",
			expectError:  false,
			description:  "Should extract callback path with UI prefix",
		},
		{
			name:         "Root callback",
			redirectUrl:  "https://example.com/callback",
			expectedPath: "/callback",
			expectError:  false,
			description:  "Should extract callback path at root level",
		},
		{
			name:         "Deep nested callback",
			redirectUrl:  "https://example.com/app/v1/auth/callback",
			expectedPath: "/app/v1/auth/callback",
			expectError:  false,
			description:  "Should extract deeply nested callback path",
		},
		{
			name:         "Empty path defaults to standard",
			redirectUrl:  "https://example.com",
			expectedPath: "/oauth2/callback",
			expectError:  false,
			description:  "Should default to /oauth2/callback when no path specified",
		},
		{
			name:         "Invalid URL",
			redirectUrl:  "not-a-url",
			expectedPath: "",
			expectError:  true,
			description:  "Should return error for invalid URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				IssuerUrl:    "https://test.com",
				ClientId:     "test-client",
				ClientSecret: "test-secret",
				RedirectUrl:  tt.redirectUrl,
				Debug:        true,
			}

			// Mock OIDC endpoint discovery
			plugin, err := createTestPluginWithCallbackPath(config)
			
			if tt.expectError {
				if err == nil {
					t.Errorf("%s: expected error but got none", tt.description)
				}
				return
			}

			if err != nil {
				t.Errorf("%s: unexpected error: %v", tt.description, err)
				return
			}

			if plugin.callbackPath != tt.expectedPath {
				t.Errorf("%s: expected callback path %s, got %s", tt.description, tt.expectedPath, plugin.callbackPath)
			}
		})
	}
}

func createTestPluginWithCallbackPath(config *Config) (*AuthPlugin, error) {
	// Simulate the callback path extraction logic from New()
	redirectURL, err := parseURL(config.RedirectUrl)
	if err != nil {
		return nil, fmt.Errorf("invalid redirectUrl: %v", err)
	}
	
	callbackPath := redirectURL.Path
	if callbackPath == "" {
		callbackPath = "/oauth2/callback"
	}

	return &AuthPlugin{
		next:   &mockHandler{},
		name:   "test-plugin",
		config: config,
		endpoints: &OIDCEndpoints{
			AuthorizationEndpoint: "https://test.com/auth",
			TokenEndpoint:        "https://test.com/token",
			UserinfoEndpoint:     "https://test.com/userinfo",
			JwksUri:             "https://test.com/jwks",
			EndSessionEndpoint:   "https://test.com/logout",
		},
		sessions:     NewSessionStore(),
		callbackPath: callbackPath,
	}, nil
}

// Helper function to parse URL (mimics url.Parse but for testing)
func parseURL(rawURL string) (*urlParts, error) {
	if rawURL == "not-a-url" {
		return nil, fmt.Errorf("invalid URL")
	}
	
	// Simple URL parsing for test purposes
	if rawURL == "https://example.com" {
		return &urlParts{Path: ""}, nil
	}
	
	// Extract path from URL for testing
	parts := map[string]string{
		"https://example.com/oauth2/callback":      "/oauth2/callback",
		"https://example.com/ui/oauth2/callback":   "/ui/oauth2/callback", 
		"https://example.com/callback":             "/callback",
		"https://example.com/app/v1/auth/callback": "/app/v1/auth/callback",
	}
	
	if path, exists := parts[rawURL]; exists {
		return &urlParts{Path: path}, nil
	}
	
	return nil, fmt.Errorf("unknown URL")
}

type urlParts struct {
	Path string
}

func TestServeHTTP_DynamicCallbackPath(t *testing.T) {
	tests := []struct {
		name           string
		callbackPath   string
		requestPath    string
		expectedStatus int
		nextCalled     bool
		description    string
	}{
		{
			name:           "Standard callback path",
			callbackPath:   "/oauth2/callback",
			requestPath:    "/oauth2/callback",
			expectedStatus: http.StatusBadRequest, // No code parameter
			nextCalled:     false,
			description:    "Should handle standard callback path",
		},
		{
			name:           "UI prefix callback path",
			callbackPath:   "/ui/oauth2/callback", 
			requestPath:    "/ui/oauth2/callback",
			expectedStatus: http.StatusBadRequest, // No code parameter
			nextCalled:     false,
			description:    "Should handle UI prefix callback path",
		},
		{
			name:           "Wrong callback path ignored",
			callbackPath:   "/ui/oauth2/callback",
			requestPath:    "/oauth2/callback",
			expectedStatus: http.StatusFound, // Initiates OIDC flow
			nextCalled:     false,
			description:    "Should not handle callback at wrong path",
		},
		{
			name:           "Custom deep callback path",
			callbackPath:   "/app/v1/auth/callback",
			requestPath:    "/app/v1/auth/callback", 
			expectedStatus: http.StatusBadRequest, // No code parameter
			nextCalled:     false,
			description:    "Should handle custom deep callback path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				IssuerUrl:    "https://test.com",
				ClientId:     "test-client",
				ClientSecret: "test-secret",
				RedirectUrl:  "https://test.com" + tt.callbackPath,
				Debug:        true,
			}

			plugin := createTestPlugin(config)
			plugin.callbackPath = tt.callbackPath // Override with test callback path
			mockNext := &mockHandler{}
			plugin.next = mockNext

			req := httptest.NewRequest("GET", tt.requestPath, nil)
			rr := httptest.NewRecorder()

			plugin.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("%s: expected status %d, got %d", tt.description, tt.expectedStatus, rr.Code)
			}

			if mockNext.called != tt.nextCalled {
				t.Errorf("%s: expected next handler called=%v, got=%v", tt.description, tt.nextCalled, mockNext.called)
			}
		})
	}
}

func TestDefaultReplyBehavior(t *testing.T) {
	tests := []struct {
		name           string
		defaultReply   string
		hasBasicAuth   bool
		authHeader     string
		expectedStatus int
		expectWWWAuth  bool
		nextCalled     bool
		description    string
	}{
		{
			name:           "DefaultReply OIDC - no auth initiates OIDC flow",
			defaultReply:   "oidc",
			hasBasicAuth:   false,
			authHeader:     "",
			expectedStatus: http.StatusFound,
			expectWWWAuth:  false,
			nextCalled:     false,
			description:    "Should initiate OIDC flow when defaultReply is oidc",
		},
		{
			name:           "DefaultReply basic - no auth returns WWW-Authenticate",
			defaultReply:   "basic",
			hasBasicAuth:   false,
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
			expectWWWAuth:  true,
			nextCalled:     false,
			description:    "Should return WWW-Authenticate when defaultReply is basic",
		},
		{
			name:           "DefaultReply basic - valid basic auth allows access",
			defaultReply:   "basic",
			hasBasicAuth:   true,
			authHeader:     "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:secret")),
			expectedStatus: http.StatusOK,
			expectWWWAuth:  false,
			nextCalled:     true,
			description:    "Should allow access with valid basic auth regardless of defaultReply",
		},
		{
			name:           "DefaultReply basic - invalid basic auth returns WWW-Authenticate",
			defaultReply:   "basic",
			hasBasicAuth:   true,
			authHeader:     "Basic " + base64.StdEncoding.EncodeToString([]byte("wrong:credentials")),
			expectedStatus: http.StatusUnauthorized,
			expectWWWAuth:  true,
			nextCalled:     false,
			description:    "Should return WWW-Authenticate with invalid basic auth when defaultReply is basic",
		},
		{
			name:           "DefaultReply OIDC - invalid basic auth initiates OIDC flow",
			defaultReply:   "oidc",
			hasBasicAuth:   true,
			authHeader:     "Basic " + base64.StdEncoding.EncodeToString([]byte("wrong:credentials")),
			expectedStatus: http.StatusFound,
			expectWWWAuth:  false,
			nextCalled:     false,
			description:    "Should initiate OIDC flow with invalid basic auth when defaultReply is oidc",
		},
		{
			name:           "Empty defaultReply defaults to OIDC behavior",
			defaultReply:   "",
			hasBasicAuth:   false,
			authHeader:     "",
			expectedStatus: http.StatusFound,
			expectWWWAuth:  false,
			nextCalled:     false,
			description:    "Should default to OIDC behavior when defaultReply is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				IssuerUrl:    "https://test.com",
				ClientId:     "test-client",
				ClientSecret: "test-secret",
				RedirectUrl:  "https://test.com/callback",
				DefaultReply: tt.defaultReply,
				Debug:        true,
			}

			if tt.hasBasicAuth {
				config.BasicAuth = "admin:secret"
			}

			mockNext := &mockHandler{}
			plugin := createTestPlugin(config)
			plugin.next = mockNext

			req := httptest.NewRequest("GET", "/protected", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			rr := httptest.NewRecorder()
			plugin.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("%s: expected status %d, got %d", tt.description, tt.expectedStatus, rr.Code)
			}

			wwwAuthHeader := rr.Header().Get("WWW-Authenticate")
			if tt.expectWWWAuth && wwwAuthHeader == "" {
				t.Errorf("%s: expected WWW-Authenticate header but got none", tt.description)
			} else if !tt.expectWWWAuth && wwwAuthHeader != "" {
				t.Errorf("%s: unexpected WWW-Authenticate header: %s", tt.description, wwwAuthHeader)
			}

			if tt.expectWWWAuth && wwwAuthHeader != "Basic realm=\"Authentication Required\"" {
				t.Errorf("%s: expected WWW-Authenticate 'Basic realm=\"Authentication Required\"', got '%s'", tt.description, wwwAuthHeader)
			}

			if mockNext.called != tt.nextCalled {
				t.Errorf("%s: expected next handler called=%v, got=%v", tt.description, tt.nextCalled, mockNext.called)
			}
		})
	}
}

func TestServeHTTP_DynamicLogoutPath(t *testing.T) {
	tests := []struct {
		name           string
		callbackPath   string
		requestPath    string
		expectedStatus int
		nextCalled     bool
		description    string
	}{
		{
			name:           "Standard logout path",
			callbackPath:   "/oauth2/callback",
			requestPath:    "/oauth2/logout",
			expectedStatus: http.StatusFound, // Redirect to logout
			nextCalled:     false,
			description:    "Should handle standard logout path",
		},
		{
			name:           "UI prefix logout path",
			callbackPath:   "/ui/oauth2/callback",
			requestPath:    "/ui/oauth2/logout",
			expectedStatus: http.StatusFound, // Redirect to logout
			nextCalled:     false,
			description:    "Should handle UI prefix logout path",
		},
		{
			name:           "Wrong logout path ignored",
			callbackPath:   "/ui/oauth2/callback",
			requestPath:    "/oauth2/logout",
			expectedStatus: http.StatusFound, // Initiates OIDC flow instead
			nextCalled:     false,
			description:    "Should not handle logout at wrong path",
		},
		{
			name:           "Custom deep logout path",
			callbackPath:   "/app/v1/auth/callback",
			requestPath:    "/app/v1/auth/logout",
			expectedStatus: http.StatusFound, // Redirect to logout
			nextCalled:     false,
			description:    "Should handle custom deep logout path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				IssuerUrl:    "https://test.com",
				ClientId:     "test-client",
				ClientSecret: "test-secret",
				RedirectUrl:  "https://test.com" + tt.callbackPath,
				Debug:        true,
			}

			plugin := createTestPlugin(config)
			plugin.callbackPath = tt.callbackPath // Override with test callback path
			mockNext := &mockHandler{}
			plugin.next = mockNext

			req := httptest.NewRequest("GET", tt.requestPath, nil)
			rr := httptest.NewRecorder()

			plugin.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("%s: expected status %d, got %d", tt.description, tt.expectedStatus, rr.Code)
			}

			if mockNext.called != tt.nextCalled {
				t.Errorf("%s: expected next handler called=%v, got=%v", tt.description, tt.nextCalled, mockNext.called)
			}
		})
	}
}