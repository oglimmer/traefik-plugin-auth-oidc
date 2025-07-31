# Traefik OIDC Auth Plugin

A Traefik middleware plugin that provides OIDC (OpenID Connect) authentication with cookie-based session management.

## Features

- OIDC authentication flow with automatic endpoint discovery
- Optional Basic Authentication support as an alternative to OIDC
- Cookie-based session management with fallback token storage
- Configurable redirect URLs and scopes
- Logout support with OIDC provider integration
- Debug mode for troubleshooting
- Skip authentication for specific paths

## Configuration

```yaml
http:
  middlewares:
    oidc-auth:
      plugin:
        traefik-plugin-auth:
          issuerUrl: "https://your-oidc-provider.com"
          clientId: "your-client-id"
          clientSecret: "your-client-secret"
          redirectUrl: "https://your-app.com/oauth2/callback"  # Can be any path ending with /callback
          scopes:
            - "openid"
            - "profile" 
            - "email"
          skippedPaths: []
          debug: false
          basicAuth: "user:password"  # Optional: enables basic auth as alternative
```

or as CLI

```bash
  - "--experimental.localPlugins.traefikpluginauth.modulename=github.com/oglimmer/traefik-plugin-auth"
```

in a docker container mount as `- ./plugins-local/src/github.com/oglimmer/traefik-plugin-auth:/plugins-local/src/github.com/oglimmer/traefik-plugin-auth`

then using this as

```yml
       - "traefik.http.routers.http-app.middlewares=siteauth"
      - "traefik.http.middlewares.siteauth.plugin.traefikpluginauth.issuerUrl=https://your-oidc-provider.com"
      - "traefik.http.middlewares.siteauth.plugin.traefikpluginauth.clientId=your-client-id"
      - "traefik.http.middlewares.siteauth.plugin.traefikpluginauth.clientSecret=your-client-secret"
      - "traefik.http.middlewares.siteauth.plugin.traefikpluginauth.redirectUrl=https://your-app.com/oauth2/callback"  # Can be any path ending with /callback
      - "traefik.http.middlewares.siteauth.plugin.traefikpluginauth.scopes[0]=openid"
      - "traefik.http.middlewares.siteauth.plugin.traefikpluginauth.scopes[1]=email"
      - "traefik.http.middlewares.siteauth.plugin.traefikpluginauth.allowedUsers[0]=user@foobar.de"
      - "traefik.http.middlewares.siteauth.plugin.traefikpluginauth.basicAuth=user:password"
```

### Configuration Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `issuerUrl` | string | Yes* | - | OIDC provider issuer URL |
| `clientId` | string | Yes* | - | OAuth2 client ID |
| `clientSecret` | string | Yes* | - | OAuth2 client secret |
| `redirectUrl` | string | Yes* | - | OAuth2 redirect URI (callback path is automatically extracted) |
| `scopes` | []string | No | `["openid", "profile", "email"]` | OAuth2 scopes to request |
| `skippedPaths` | []string | No | `[]` | Paths to skip authentication for |
| `debug` | bool | No | `false` | Enable debug logging |
| `allowedUsers` | []string | No | `[]` | List of allowed user emails for OIDC auth |
| `basicAuth` | string | No | - | Basic auth credentials in format "user:password" |

*Required only when `basicAuth` is not configured

## Usage

### OIDC Authentication

1. Configure your OIDC provider with the redirect URI (e.g., `https://your-app.com/oauth2/callback` or `https://your-app.com/ui/oauth2/callback`)
2. Add the middleware to your Traefik configuration with OIDC parameters
3. Apply the middleware to your routes

### Basic Authentication

1. Set the `basicAuth` parameter with credentials in "user:password" format
2. Clients can authenticate using the standard HTTP Basic Authentication header
3. Basic auth is checked before OIDC authentication

### Authentication Flow

The plugin checks authentication in this order:
1. Skipped paths (no authentication required)
2. OAuth2 callback and logout endpoints
3. **Basic Authentication** (if configured and provided)
4. OIDC token validation (cookies/session)
5. Initiate OIDC flow (if no valid authentication found)

The plugin automatically handles:
- OAuth2 callback endpoint (path extracted from `redirectUrl`)
- Logout endpoint (relative to callback path, e.g., `/oauth2/logout` or `/ui/oauth2/logout`)
- Authentication for all other paths (except skipped paths)

## Skipped Paths

By default, no paths are skipped for authentication. You can configure specific paths to skip authentication by setting the `skippedPaths` parameter. For example:

```yaml
skippedPaths:
  - "/favicon.ico"
  - "/robots.txt"
  - "/health"
  - "/ping"
  - "/.well-known/"
```

Paths are matched using prefix matching, so `/health` will match `/health`, `/health/status`, etc.

## Session Management

The plugin uses a dual-layer session management approach:
1. In-memory session store with session ID cookies
2. Fallback to base64-encoded token cookies

Sessions automatically expire based on the token expiration time from the OIDC provider.

## Development

This plugin is built for Traefik v3 and requires Go 1.22+.

### Plugin Structure

- `auth.go` - Main plugin implementation
- `auth_test.go` - Comprehensive unit tests
- `go.mod` - Go module definition
- `.traefik.yml` - Traefik plugin manifest

### Testing

The plugin includes comprehensive unit tests covering:

- Basic authentication validation
- Authentication flow logic
- Path skipping functionality
- OAuth2 endpoint handling
- Session management
- Configuration validation
- Utility functions

#### Running Tests

```bash
# Run all tests
go test -v

# Run tests with coverage
go test -cover

# Run specific test
go test -run TestValidateBasicAuth -v
```

#### Test Coverage

Current test coverage focuses on:
- ✅ Basic auth credential validation and edge cases
- ✅ HTTP request/response flows for authentication
- ✅ Path-based authentication skipping
- ✅ OAuth2 callback and logout endpoint handling (including dynamic path support)
- ✅ Session store operations
- ✅ Configuration defaults and validation

The tests achieve comprehensive coverage of authentication flows and security-critical functionality.

## License

This plugin is provided as-is for educational and development purposes.