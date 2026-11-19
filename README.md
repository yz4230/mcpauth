# mcpauth

[![test](https://github.com/yz4230/mcpauth/actions/workflows/test.yaml/badge.svg)](https://github.com/yz4230/mcpauth/actions/workflows/test.yaml)
[![Go Reference](https://pkg.go.dev/badge/github.com/yz4230/mcpauth.svg)](https://pkg.go.dev/github.com/yz4230/mcpauth)

A minimal OAuth 2.1 authorization server for personal [MCP](https://modelcontextprotocol.io) servers, packaged as `net/http` middleware. Standard library only.

It lets ChatGPT and Claude connect to your own MCP server through their OAuth connector flow (Dynamic Client Registration + PKCE), protected by a single password.

## Install

```sh
go get github.com/yz4230/mcpauth
```

Requires Go 1.27 or later.

## Usage

```go
auth, err := mcpauth.New(mcpauth.Config{
	PublicURL: "https://mcp.example.com",
	Password:  os.Getenv("MCP_PASSWORD"),
})
if err != nil {
	log.Fatal(err)
}
log.Fatal(http.ListenAndServe(":8000", auth.Middleware(mcpHandler)))
```

The middleware answers the OAuth endpoints itself and forwards every other request to `mcpHandler` only if it carries a valid bearer token. Unauthenticated requests get `401` with a `WWW-Authenticate: Bearer resource_metadata="..."` header, which is how MCP clients discover the authorization server.

When a client connects, you are shown a login page; entering the password completes the flow.

## Configuration

| Field | Default | Description |
|---|---|---|
| `PublicURL` | required | Public base URL as clients see it. Must be `https` (`http` is allowed only for `localhost`, `127.0.0.1`, `::1`). No userinfo, query or fragment. |
| `Password` | required | Password for the login page. |
| `StateFile` | `oauth_state.json` | Where registered clients and tokens are persisted (mode `0600`). |
| `MCPPath` | `/mcp` | Path of the MCP endpoint, advertised as the protected resource. |
| `AllowedRedirectURIs` | ChatGPT and Claude | Redirect URIs accepted at client registration (exact match). Setting it replaces the defaults; use `append(mcpauth.DefaultRedirectURIs, ...)` to extend them. |
| `AllowedRedirectURIPrefixes` | ChatGPT (`https://chatgpt.com/connector/oauth/`) | Prefixes for redirect URIs accepted at client registration: a URI matches when it is a prefix followed by a non-empty segment without `/`, `?` or `#` (e.g. ChatGPT's per-connector `https://chatgpt.com/connector/oauth/<id>`). Setting it replaces the defaults; use `append(mcpauth.DefaultRedirectURIPrefixes, ...)` to extend them, or `[]string{}` to disable prefix matching. |
| `AccessTTL` | 1 hour | Access token lifetime. |
| `RefreshTTL` | 90 days | Refresh token lifetime. |

Rejected registrations are logged with the redirect URIs the client sent, which helps when adding a new client to the allowlist.

## Endpoints

| Endpoint | Spec |
|---|---|
| `GET /.well-known/oauth-protected-resource` (also `…/mcp`) | RFC 9728 |
| `GET /.well-known/oauth-authorization-server` (also `/.well-known/openid-configuration`) | RFC 8414 |
| `POST /register` | RFC 7591 (Dynamic Client Registration) |
| `GET`, `POST /authorize` | Password login, issues an authorization code |
| `POST /token` | `authorization_code` (PKCE `S256` required) and `refresh_token` grants |

## Behavior

- Tokens are stored as SHA-256 hashes, so the state file does not contain usable tokens.
- Authorization codes are single-use, expire after 5 minutes and are kept in memory only.
- Refresh tokens rotate on every use; the old one is rejected.
- Access tokens survive restarts.
- A wrong password delays the response by one second.

## Deployment notes

- Behind a TLS-terminating reverse proxy, listen on plain HTTP and set `PublicURL` to the public `https` URL.
- The OAuth endpoints are served at the root path. If `PublicURL` includes a path prefix (for example `https://example.com/sub`), the proxy must strip that prefix before forwarding.
- Every path not handled by mcpauth requires a token. Route health checks or other public paths outside the middleware.

## License

[MIT](LICENSE)
