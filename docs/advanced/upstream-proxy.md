# Upstream Proxy

By default httpjail contacts destination servers directly. When httpjail itself
runs in an environment that has no direct internet access — for example behind a
corporate proxy — you can route httpjail's own outbound requests through an
upstream proxy with `--upstream-proxy` (or the `HTTPJAIL_UPSTREAM_PROXY`
environment variable).

Rule evaluation still happens locally on the intercepted traffic. Only the
request that httpjail re-originates towards the real destination is forwarded
through the upstream proxy.

```bash
# Route httpjail's egress through a corporate proxy
httpjail --upstream-proxy http://proxy.corp:3128 --js "true" -- curl https://api.github.com

# With Basic authentication
httpjail --upstream-proxy http://user:pass@proxy.corp:3128 --js "true" -- ./my-app

# Through an HTTPS proxy
httpjail --upstream-proxy https://proxy.corp:8443 --js "true" -- ./my-app

# Via the environment variable (equivalent to --upstream-proxy)
HTTPJAIL_UPSTREAM_PROXY=http://proxy.corp:3128 httpjail --js "true" -- ./my-app
```

## Accepted formats

| Form | Example | Notes |
| --- | --- | --- |
| `http://host:port` | `http://proxy.corp:3128` | Plain HTTP proxy |
| `https://host:port` | `https://proxy.corp:8443` | Connection to the proxy is wrapped in TLS |
| `host:port` | `proxy.corp:3128` | Bare authority, `http` scheme assumed |
| With credentials | `http://user:pass@proxy.corp:3128` | Sends `Proxy-Authorization: Basic ...` |

The command-line flag takes precedence over the environment variable. Credentials
are never written to the logs.

## How it works

- **HTTPS destinations** are reached by issuing a `CONNECT` to the upstream
  proxy to obtain a raw TCP tunnel; httpjail then performs the destination TLS
  handshake over that tunnel. TLS is validated against Mozilla's webpki roots
  plus the httpjail CA, exactly as for a direct connection.
- **Plain HTTP destinations** are forwarded to the proxy in absolute-form, with
  the `Proxy-Authorization` header attached when credentials are configured.
- Only connection setup (TCP connect, optional TLS to the proxy, and the
  `CONNECT` exchange) is bounded by a timeout. The established tunnel carries no
  timeout, so long-running connections such as WebSocket and gRPC keep working.

## Relationship to `HTTP_PROXY` / `HTTPS_PROXY`

This feature is independent of the `HTTP_PROXY` and `HTTPS_PROXY` variables that
httpjail sets *inside* the jail to point sandboxed processes at httpjail itself.

```
[ jailed process ] --HTTP_PROXY/HTTPS_PROXY--> [ httpjail ] --upstream-proxy--> [ corporate proxy ] --> internet
```

The jailed process always talks to httpjail; `--upstream-proxy` only affects the
hop from httpjail to the outside world.
