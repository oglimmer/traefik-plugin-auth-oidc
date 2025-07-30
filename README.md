# Traefik OIDC Auth Plugin

A Traefik middleware plugin that provides OIDC (OpenID Connect) authentication with cookie-based session management.

## Features

- OIDC authentication flow with automatic endpoint discovery
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
          redirectUrl: "https://your-app.com/oauth2/callback"
          scopes:
            - "openid"
            - "profile" 
            - "email"
          skippedPaths: []
          debug: false
```

### Configuration Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `issuerUrl` | string | Yes | - | OIDC provider issuer URL |
| `clientId` | string | Yes | - | OAuth2 client ID |
| `clientSecret` | string | Yes | - | OAuth2 client secret |
| `redirectUrl` | string | Yes | - | OAuth2 redirect URI (must end with `/oauth2/callback`) |
| `scopes` | []string | No | `["openid", "profile", "email"]` | OAuth2 scopes to request |
| `skippedPaths` | []string | No | `[]` | Paths to skip authentication for |
| `debug` | bool | No | `false` | Enable debug logging |

## Usage

1. Configure your OIDC provider with the redirect URI ending in `/oauth2/callback`
2. Add the middleware to your Traefik configuration
3. Apply the middleware to your routes

The plugin automatically handles:
- `/oauth2/callback` - OAuth2 callback endpoint
- `/oauth2/logout` - Logout endpoint
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
- `go.mod` - Go module definition
- `.traefik.yml` - Traefik plugin manifest

## License

This plugin is provided as-is for educational and development purposes.