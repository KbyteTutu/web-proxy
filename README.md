# Web Proxy

A password-protected web proxy you use entirely from the browser. You log in,
type any URL, and the page is fetched through the server's network egress (or
through an upstream SOCKS5 proxy if configured). Built on
[Ultraviolet](https://github.com/titaniumnetwork-dev/Ultraviolet) +
[bare-server-node](https://github.com/tomphttp/bare-server-node).

## How it works

```
Browser ── login (cookie) ── Web Proxy server ── [SOCKS5] ── Internet
   │                              │
   └─ Service Worker (Ultraviolet) rewrites the page in-browser
      and tunnels every request through the bare server.
```

- A login page guards everything with a single password (signed session cookie).
- After login, the home page registers the Ultraviolet service worker and hands
  it a short-lived, HMAC-signed **token**. The bare endpoint (`/wp/<token>/bare/`)
  only accepts requests carrying a valid token, so the proxy cannot be used
  without logging in.
- All outbound traffic is made by the bare server. When `UPSTREAM_SOCKS5` is set,
  the bare server's HTTP/HTTPS/WS agents are `SocksProxyAgent`, so every request
  exits through that SOCKS5 proxy (nested proxying).

## Setup

```bash
npm install
PROXY_PASSWORD=yourpassword npm start
```

Open `http://SERVER_IP:8080`, log in, and browse.

## Configuration

All configuration is via environment variables:

| Variable | Default | Description |
|---|---|---|
| `PROXY_PASSWORD` | `changeme` | Login password (set this!) |
| `PROXY_PORT` | `8080` | Listen port |
| `PROXY_HOST` | `0.0.0.0` | Bind address |
| `UPSTREAM_SOCKS5` | _(empty)_ | Upstream SOCKS5 URL for nested proxying |
| `PROXY_BLOCK_LOCAL` | `true` | Block requests to private/local IPs (set `false` to allow) |
| `SESSION_SECRET` | random | Secret for signing cookies/tokens; set a fixed value to keep sessions across restarts |
| `SESSION_TTL_MS` | `43200000` | Session lifetime in ms (12h) |

### Routing through a SOCKS5 proxy

```bash
PROXY_PASSWORD=yourpassword \
UPSTREAM_SOCKS5=socks5://127.0.0.1:1080 \
npm start
```

With authentication:

```bash
UPSTREAM_SOCKS5=socks5://user:pass@127.0.0.1:1080 npm start
```

## Notes

- Service workers require a secure context. On a remote server, serve this behind
  HTTPS (e.g. a reverse proxy / TLS terminator). `localhost` and `127.0.0.1` are
  exempt, so local testing works over plain HTTP.
- The default `SESSION_SECRET` is randomized on each start, which invalidates
  existing sessions on restart. Set a fixed `SESSION_SECRET` in production.
```
