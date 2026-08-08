# Upstream Proxy

By default httpjail contacts destination servers directly. When httpjail itself
runs in an environment that has no direct internet access — for example behind a
corporate proxy — you can route httpjail's own outbound requests through an
upstream proxy with the `HTTP_PROXY` and/or `HTTPS_PROXY` environment variables.

Rule evaluation still happens locally on the intercepted traffic. Only the
request that httpjail re-originates towards the real destination is forwarded
through the upstream proxy.

```bash
# Route httpjail's HTTPS egress through a corporate proxy
HTTPS_PROXY=http://proxy.corp:3128 httpjail --js "true" -- curl https://api.github.com

# Route both HTTP and HTTPS egress through the same proxy
HTTP_PROXY=http://proxy.corp:3128 HTTPS_PROXY=http://proxy.corp:3128 \
  httpjail --js "true" -- ./my-app

# With Basic authentication
HTTPS_PROXY=http://user:pass@proxy.corp:3128 httpjail --js "true" -- ./my-app
```

## Accepted formats

| Form | Example | Notes |
| --- | --- | --- |
| `http://host:port` | `http://proxy.corp:3128` | Plain HTTP proxy |
| `host:port` | `proxy.corp:3128` | Bare authority, `http` scheme assumed |
| With credentials | `http://user:pass@proxy.corp:3128` | Sends `Proxy-Authorization: Basic ...` |

`HTTP_PROXY` is used for `http://` destinations. `HTTPS_PROXY` is used for
`https://` destinations. Credentials are never written to the logs.

Note that the value describes how httpjail reaches the proxy, not the scheme of
the destinations it covers: `HTTPS_PROXY=http://proxy.corp:3128` is the normal
configuration and sends HTTPS destinations through a plain HTTP proxy. Reaching
the proxy itself over TLS (an `https://` proxy URL) is not supported and is
rejected with an error.

## Bypassing the proxy with `NO_PROXY`

`NO_PROXY` lists destinations that httpjail contacts directly instead of through
the upstream proxy. The syntax follows curl 8.14.1.

| Form | Example | Notes |
| --- | --- | --- |
| Domain | `example.com` | Matches the domain and its subdomains, not `notexample.com` |
| Leading dot | `.example.com` | One leading dot is ignored; same as above |
| Wildcard | `*` | Only when the whole list is exactly `*`: no proxy is used at all |
| IPv4 CIDR | `192.168.0.0/16` | Only for destinations written as an IP literal |
| IPv6 CIDR | `2001:db8::/32` | Only for destinations written as an IP literal |
| Address | `192.168.1.1` | Without a prefix length, an exact address match. Also matches host names ending in it, since an entry is read as a domain whenever the destination is a host name |

Entries are separated by commas, matched case-insensitively, and one trailing dot
is ignored on both the entry and the destination. Rule evaluation is unaffected:
a bypassed request is still checked against your rules, it just reaches the
destination directly.

Not supported:

- **Ports in entries.** `example.com:8080` matches nothing, because entries are
  compared against the destination's host name only. It does not fall back to
  matching `example.com`.
- **Globs, schemes and paths.** `*.example.com` and `https://example.com` match
  nothing. Use `example.com`, which already covers subdomains.
- **Matching resolved addresses.** A CIDR entry applies only when the destination
  itself is an IP literal; host names are never resolved to check them.

A mistyped CIDR (`10.0.0.0/8x`, `10.0.0.0/33`) is reported as a configuration
error at startup rather than silently ignored. Entries that simply cannot match,
such as the unsupported forms above, are ignored and logged at debug level.

`NO_PROXY` is only read when at least one of `HTTP_PROXY` / `HTTPS_PROXY` is set.

### Differences from curl

| Item | curl 8.14.1 | httpjail |
| --- | --- | --- |
| Variable precedence | `no_proxy`, then `NO_PROXY` | `NO_PROXY`, then `no_proxy`, consistent with the other proxy variables |
| Whitespace-only value | Counts as set, so the other spelling is not consulted | Counts as unset, falling through to the other spelling |
| Whitespace between entries | Stops parsing the list, silently discarding the rest | Separates entries, like a comma |
| `/0` prefix | Treated as an exact address match | Matches the whole address family |
| Mistyped CIDR | Silently ignored | Configuration error at startup |
| IPv6 prefix not a multiple of 8 | Inverted before curl 8.17.0 | Matches correctly, as curl 8.17.0 and later do |

## How it works

- **HTTPS destinations** are reached by issuing a `CONNECT` to the upstream
  proxy to obtain a raw TCP tunnel; httpjail then performs the destination TLS
  handshake over that tunnel. TLS is validated against Mozilla's webpki roots
  plus the httpjail CA, exactly as for a direct connection.
- **Plain HTTP destinations** are forwarded to the proxy in absolute-form, with
  the `Proxy-Authorization` header attached when credentials are configured. The
  header is never sent to a destination that `NO_PROXY` bypasses, nor to an HTTPS
  destination, whose request travels inside the tunnel to the origin server.
- Connection setup (the TCP connect, `CONNECT` exchange and destination TLS
  handshake) is bounded by a timeout. The established tunnel carries no timeout,
  so long-running connections such as WebSocket and gRPC keep working.

## Relationship to jailed process proxy variables

The proxy environment variables configure httpjail's own egress. In weak mode,
httpjail overwrites `HTTP_PROXY` and `HTTPS_PROXY` inside the jailed process to
point sandboxed processes at httpjail itself.

```
[ jailed process ] --> [ httpjail ] --HTTP_PROXY/HTTPS_PROXY--> [ corporate proxy ] --> internet
```

The jailed process talks to httpjail; the proxy env vars only affect the hop
from httpjail to the outside world.

None of the parent's proxy variables are included in the jailed process's own
environment. `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` are removed so
cooperating applications do not use the upstream proxy directly, and `NO_PROXY`
is replaced with the local addresses only. Inheriting `NO_PROXY` would let an
application connect straight to every destination it named, with no rule
evaluation at all. In weak mode httpjail then sets the proxy variables to its own
address.

Removing variables from the command's own environment is not credential
isolation. Neither weak nor strong mode creates a PID namespace or otherwise
guarantees that the command cannot inspect the httpjail process. Strong mode
isolates network access, but visibility of the parent process and permission to
read its environment depend on the platform, UID setup and other OS controls.
When running an untrusted command, use a credential-free proxy or a separate OS
or external credential boundary that prevents access to httpjail's environment.
