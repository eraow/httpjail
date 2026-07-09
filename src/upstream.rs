//! Forward httpjail's own re-originated requests through an upstream
//! (e.g. corporate) HTTP proxy.
//!
//! httpjail terminates the jailed process's traffic and then re-originates the
//! request towards the real destination. When httpjail itself has no direct
//! egress, that re-originated request must instead traverse an upstream proxy.
//!
//! To keep the dependency surface minimal this module does not use any HTTP
//! client crate for the proxy leg. It dials the proxy directly and drives the
//! exchange with hyper's low-level `client::conn` API (already part of the
//! project), so no additional crates are required. Depending on the destination
//! scheme it either:
//!
//! * issues a `CONNECT` to obtain a raw TCP tunnel for `https://` destinations
//!   and then performs the destination TLS handshake over that tunnel, or
//! * forwards the request in absolute-form to the proxy for `http://`
//!   destinations, attaching `Proxy-Authorization` when credentials are set.
//!
//! Following the streaming style used elsewhere in httpjail (see `proxy_tls.rs`)
//! every bounded read during setup is guarded by a timeout, while the
//! established tunnel itself is left unbounded so long-running connections
//! (WebSocket, gRPC, ...) keep working.

use anyhow::{Context as _, Result, anyhow, bail};
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper::Error as HyperError;
use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper::header::{HeaderValue, PROXY_AUTHORIZATION};
use hyper::{Request, Response, Uri};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};
use tokio_rustls::TlsConnector;
use tracing::debug;

/// Timeout for establishing the tunnel through the upstream proxy (TCP connect,
/// optional TLS to the proxy, the `CONNECT` exchange and the destination TLS
/// handshake). This bounds setup only; the resulting tunnel carries no timeout
/// so long-running connections keep working.
const PROXY_SETUP_TIMEOUT: Duration = Duration::from_secs(30);

/// Upper bound on the size of the upstream proxy's `CONNECT` response headers.
/// A well-behaved proxy answers with a short status line and a few headers.
const MAX_CONNECT_RESPONSE_BYTES: usize = 16 * 1024;

/// Object-safe combination of the async byte-stream traits we erase over so the
/// forwarder can hold either a plain TCP stream or a TLS stream (to the proxy or
/// the destination) behind a single type.
trait IoStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> IoStream for T {}

/// A heap-erased byte stream carrying the connection to the proxy (and, for
/// HTTPS destinations, the TLS layered on top of the tunnel).
type BoxedIo = Box<dyn IoStream>;

/// Parsed configuration for an upstream proxy.
#[derive(Clone, Debug)]
pub struct UpstreamProxy {
    /// Proxy host (DNS name or IP literal) to dial.
    host: String,
    /// Proxy port.
    port: u16,
    /// Whether the connection to the proxy itself is wrapped in TLS (an
    /// `https://` proxy URL).
    tls: bool,
    /// Pre-built `Proxy-Authorization` header value when credentials are given.
    auth: Option<HeaderValue>,
}

impl UpstreamProxy {
    /// Parse an upstream proxy specification such as `http://proxy.corp:3128`,
    /// `http://user:pass@proxy.corp:3128`, `https://proxy.corp:8443` or a bare
    /// `proxy.corp:3128` (the `http` scheme is then assumed).
    pub fn parse(spec: &str) -> Result<Self> {
        let spec = spec.trim();
        if spec.is_empty() {
            bail!("Upstream proxy specification is empty");
        }

        // Accept a bare `host:port` by assuming the http scheme.
        let (scheme, rest) = match spec.split_once("://") {
            Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
            None => ("http".to_string(), spec),
        };

        let tls = match scheme.as_str() {
            "http" => false,
            "https" => true,
            other => bail!("Unsupported upstream proxy scheme '{}': {}", other, spec),
        };

        // Drop any path/query/fragment component; only the authority is used.
        let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);

        // Split optional `userinfo@` from the `host:port` authority.
        let (userinfo, host_port) = match authority.rsplit_once('@') {
            Some((userinfo, host_port)) => (Some(userinfo), host_port),
            None => (None, authority),
        };

        let default_port = if tls { 443 } else { 80 };
        let (host, port) = parse_host_port(host_port, default_port)
            .with_context(|| format!("Invalid upstream proxy authority: {}", spec))?;

        let auth = match userinfo {
            Some(userinfo) => Some(build_basic_auth(userinfo)?),
            None => None,
        };

        Ok(UpstreamProxy {
            host,
            port,
            tls,
            auth,
        })
    }
}

/// Split a `host:port` authority into its parts, handling bracketed IPv6
/// literals (`[::1]:3128`). Falls back to `default_port` when no port is given.
fn parse_host_port(authority: &str, default_port: u16) -> Result<(String, u16)> {
    if let Some(rest) = authority.strip_prefix('[') {
        // Bracketed IPv6 literal: `[addr]` or `[addr]:port`.
        let (addr, after) = rest
            .split_once(']')
            .ok_or_else(|| anyhow!("unterminated IPv6 literal: {}", authority))?;
        let port = match after.strip_prefix(':') {
            Some(port) => port.parse().context("invalid port")?,
            None if after.is_empty() => default_port,
            None => bail!("unexpected characters after IPv6 literal: {}", authority),
        };
        return Ok((addr.to_string(), port));
    }

    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, port.parse().context("invalid port")?),
        None => (authority, default_port),
    };

    if host.is_empty() {
        bail!("missing host: {}", authority);
    }
    Ok((host.to_string(), port))
}

/// Build a `Proxy-Authorization: Basic ...` header value from `user:pass`
/// userinfo, percent-decoding each component first.
fn build_basic_auth(userinfo: &str) -> Result<HeaderValue> {
    let (user, pass) = match userinfo.split_once(':') {
        Some((user, pass)) => (user, pass),
        None => (userinfo, ""),
    };
    let token =
        base64_encode(format!("{}:{}", percent_decode(user), percent_decode(pass)).as_bytes());
    HeaderValue::from_str(&format!("Basic {}", token))
        .context("Invalid characters in upstream proxy credentials")
}

/// Forwards prepared requests through a configured [`UpstreamProxy`].
///
/// A fresh connection to the proxy is established per request. This mirrors the
/// project's preference for simple, streaming forwarding and matches the minimal
/// pooling used by the direct client.
pub struct ProxyForwarder {
    proxy: UpstreamProxy,
    /// TLS configuration used both for connecting to an `https://` proxy and for
    /// the destination TLS handshake performed over a `CONNECT` tunnel. It
    /// trusts webpki roots plus the httpjail CA (or is the dangerous
    /// no-verification config in testing).
    tls_config: Arc<rustls::ClientConfig>,
}

impl ProxyForwarder {
    pub fn new(proxy: UpstreamProxy, tls_config: Arc<rustls::ClientConfig>) -> Self {
        ProxyForwarder { proxy, tls_config }
    }

    /// Forward a prepared request upstream through the proxy and return the
    /// response. No timeout is applied to the request itself so that
    /// long-running connections keep working; only connection setup is bounded.
    pub async fn request(
        &self,
        req: Request<BoxBody<Bytes, HyperError>>,
    ) -> Result<Response<Incoming>> {
        let uri = req.uri().clone();
        let is_https = uri.scheme_str() == Some("https");
        let host = uri
            .host()
            .ok_or_else(|| anyhow!("Upstream request has no host: {}", uri))?
            .to_string();
        let port = uri.port_u16().unwrap_or(if is_https { 443 } else { 80 });

        // Dial the proxy and optionally wrap the connection in TLS.
        let stream = self.connect_to_proxy().await?;

        if is_https {
            let mut stream = stream;
            establish_connect_tunnel(&mut stream, &host, port, self.proxy.auth.as_ref())
                .await
                .with_context(|| {
                    format!("CONNECT to {}:{} via upstream proxy failed", host, port)
                })?;

            // Layer the destination TLS on top of the transparent tunnel and
            // send the request in origin-form, exactly as for a direct
            // connection to the destination.
            let tls = self.destination_tls(stream, &host).await?;
            let req = to_origin_form(req)?;
            send_over(Box::new(tls) as BoxedIo, req).await
        } else {
            // Plain HTTP: the proxy forwards absolute-form requests, so keep the
            // request URI absolute and carry credentials on the request itself.
            let mut req = req;
            if let Some(auth) = &self.proxy.auth {
                req.headers_mut().insert(PROXY_AUTHORIZATION, auth.clone());
            }
            send_over(stream, req).await
        }
    }

    /// Establish the TCP (and, for an `https://` proxy, TLS) connection to the
    /// proxy itself.
    async fn connect_to_proxy(&self) -> Result<BoxedIo> {
        let tcp = match timeout(
            PROXY_SETUP_TIMEOUT,
            TcpStream::connect((self.proxy.host.as_str(), self.proxy.port)),
        )
        .await
        {
            Ok(result) => result.with_context(|| {
                format!(
                    "Failed to connect to upstream proxy {}:{}",
                    self.proxy.host, self.proxy.port
                )
            })?,
            Err(_) => bail!("Timeout connecting to upstream proxy"),
        };
        // Disable Nagle to keep the CONNECT exchange snappy.
        let _ = tcp.set_nodelay(true);

        if self.proxy.tls {
            let tls = self
                .destination_tls(Box::new(tcp) as BoxedIo, &self.proxy.host)
                .await?;
            Ok(Box::new(tls) as BoxedIo)
        } else {
            Ok(Box::new(tcp) as BoxedIo)
        }
    }

    /// Perform a TLS handshake over `stream` using `server_name` for SNI and
    /// certificate validation. Used both for an `https://` proxy and for the
    /// destination reached through a `CONNECT` tunnel.
    async fn destination_tls(
        &self,
        stream: BoxedIo,
        server_name: &str,
    ) -> Result<tokio_rustls::client::TlsStream<BoxedIo>> {
        let connector = TlsConnector::from(Arc::clone(&self.tls_config));
        let name = ServerName::try_from(server_name.to_string())
            .map_err(|_| anyhow!("Invalid host for TLS SNI: {}", server_name))?;
        match timeout(PROXY_SETUP_TIMEOUT, connector.connect(name, stream)).await {
            Ok(result) => {
                result.with_context(|| format!("TLS handshake with {} failed", server_name))
            }
            Err(_) => bail!("Timeout during TLS handshake with {}", server_name),
        }
    }
}

/// Send `req` over an already-established byte stream using hyper's low-level
/// HTTP/1 client connection, spawning the connection driver so the response
/// body streams. Upgrades are enabled to support WebSocket and similar.
async fn send_over(
    io: BoxedIo,
    req: Request<BoxBody<Bytes, HyperError>>,
) -> Result<Response<Incoming>> {
    let (mut sender, conn) = http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(false)
        .handshake(TokioIo::new(io))
        .await
        .context("Failed to establish HTTP connection over upstream proxy")?;

    tokio::spawn(async move {
        if let Err(e) = conn.with_upgrades().await {
            debug!("Upstream proxy connection closed with error: {}", e);
        }
    });

    sender
        .send_request(req)
        .await
        .context("Failed to send request through upstream proxy")
}

/// Rewrite a request so its URI is origin-form (path and query only). Used for
/// requests sent directly to the destination over a `CONNECT` tunnel, where the
/// authority is conveyed by the `Host` header rather than the request line.
fn to_origin_form(
    req: Request<BoxBody<Bytes, HyperError>>,
) -> Result<Request<BoxBody<Bytes, HyperError>>> {
    let (mut parts, body) = req.into_parts();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    parts.uri = path_and_query
        .parse::<Uri>()
        .context("Failed to build origin-form request URI")?;
    Ok(Request::from_parts(parts, body))
}

/// Send a `CONNECT` request to the upstream proxy and validate its response,
/// leaving `stream` positioned at the start of the tunnel payload on success.
async fn establish_connect_tunnel<S>(
    stream: &mut S,
    host: &str,
    port: u16,
    auth: Option<&HeaderValue>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut request = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
    if let Some(value) = auth {
        let value = value
            .to_str()
            .context("Proxy-Authorization contains non-ASCII bytes")?;
        request.push_str("Proxy-Authorization: ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");

    match timeout(PROXY_SETUP_TIMEOUT, stream.write_all(request.as_bytes())).await {
        Ok(result) => result.context("Failed to write CONNECT request")?,
        Err(_) => bail!("Timeout writing CONNECT request to upstream proxy"),
    }
    match timeout(PROXY_SETUP_TIMEOUT, stream.flush()).await {
        Ok(result) => result.context("Failed to flush CONNECT request")?,
        Err(_) => bail!("Timeout flushing CONNECT request to upstream proxy"),
    }

    let status = match timeout(PROXY_SETUP_TIMEOUT, read_connect_status(stream)).await {
        Ok(result) => result?,
        Err(_) => bail!("Timeout reading CONNECT response from upstream proxy"),
    };

    if !(200..300).contains(&status) {
        bail!(
            "Upstream proxy refused CONNECT to {}:{} with status {}",
            host,
            port,
            status
        );
    }

    debug!(
        "Established CONNECT tunnel to {}:{} via upstream proxy",
        host, port
    );
    Ok(())
}

/// Read the proxy's `CONNECT` response up to the end of its headers and return
/// the HTTP status code. Reads are bounded by [`MAX_CONNECT_RESPONSE_BYTES`] to
/// avoid consuming tunnel payload and to bound memory.
async fn read_connect_status<S>(stream: &mut S) -> Result<u16>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            bail!("Upstream proxy closed connection during CONNECT");
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > MAX_CONNECT_RESPONSE_BYTES {
            bail!("Upstream proxy CONNECT response exceeded size limit");
        }
    }

    // Parse the status code from the first line, e.g.
    // `HTTP/1.1 200 Connection established`.
    let head = std::str::from_utf8(&buf).context("Non-UTF8 CONNECT response")?;
    let first_line = head.lines().next().unwrap_or("");
    first_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| anyhow!("Malformed CONNECT status line: {:?}", first_line))
}

/// Minimal RFC 4648 base64 encoder (standard alphabet, with padding). Used only
/// to build the `Proxy-Authorization: Basic ...` credential token, avoiding a
/// dedicated base64 dependency.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((triple >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((triple >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(triple & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Decode `%XX` percent-escapes in the userinfo portion of a proxy URL. Any
/// malformed escape is left verbatim.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"user:pass"), "dXNlcjpwYXNz");
    }

    #[test]
    fn parse_plain_proxy() {
        let p = UpstreamProxy::parse("http://proxy.corp:3128").unwrap();
        assert_eq!(p.host, "proxy.corp");
        assert_eq!(p.port, 3128);
        assert!(!p.tls);
        assert!(p.auth.is_none());
    }

    #[test]
    fn parse_bare_hostport_defaults_to_http() {
        let p = UpstreamProxy::parse("proxy.corp:8080").unwrap();
        assert_eq!(p.host, "proxy.corp");
        assert_eq!(p.port, 8080);
        assert!(!p.tls);
    }

    #[test]
    fn parse_https_proxy_default_port() {
        let p = UpstreamProxy::parse("https://proxy.corp").unwrap();
        assert!(p.tls);
        assert_eq!(p.port, 443);
    }

    #[test]
    fn parse_ipv6_literal_with_port() {
        let p = UpstreamProxy::parse("http://[::1]:3128").unwrap();
        assert_eq!(p.host, "::1");
        assert_eq!(p.port, 3128);
    }

    #[test]
    fn parse_proxy_with_credentials() {
        let p = UpstreamProxy::parse("http://alice:s3cr3t@proxy.corp:3128").unwrap();
        // base64("alice:s3cr3t")
        assert_eq!(p.auth.unwrap().to_str().unwrap(), "Basic YWxpY2U6czNjcjN0");
    }

    #[test]
    fn parse_credentials_are_percent_decoded() {
        // "p@ss:word" encoded in the userinfo.
        let p = UpstreamProxy::parse("http://user:p%40ss%3Aword@proxy.corp:3128").unwrap();
        assert_eq!(
            p.auth.unwrap().to_str().unwrap(),
            format!("Basic {}", base64_encode(b"user:p@ss:word"))
        );
    }

    #[test]
    fn reject_unknown_scheme() {
        assert!(UpstreamProxy::parse("ftp://proxy.corp:21").is_err());
    }

    #[test]
    fn reject_empty_spec() {
        assert!(UpstreamProxy::parse("   ").is_err());
    }

    /// Drive the proxy side of an in-memory duplex: read request headers up to
    /// the blank line, then reply with `response`. Returns the request text.
    async fn fake_proxy(mut end: tokio::io::DuplexStream, response: &'static [u8]) -> String {
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let n = end.read(&mut byte).await.unwrap();
            if n == 0 {
                break;
            }
            buf.push(byte[0]);
            if buf.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        end.write_all(response).await.unwrap();
        end.flush().await.unwrap();
        String::from_utf8_lossy(&buf).into_owned()
    }

    #[tokio::test]
    async fn connect_tunnel_sends_request_and_accepts_2xx() {
        let (mut client_end, proxy_end) = tokio::io::duplex(1024);
        let proxy = tokio::spawn(fake_proxy(
            proxy_end,
            b"HTTP/1.1 200 Connection established\r\n\r\n",
        ));

        let auth = HeaderValue::from_static("Basic dXNlcjpwYXNz");
        establish_connect_tunnel(&mut client_end, "example.com", 443, Some(&auth))
            .await
            .unwrap();

        let request = proxy.await.unwrap();
        assert!(request.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
        assert!(request.contains("Host: example.com:443\r\n"));
        assert!(request.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));
    }

    #[tokio::test]
    async fn connect_tunnel_rejects_non_2xx() {
        let (mut client_end, proxy_end) = tokio::io::duplex(1024);
        tokio::spawn(fake_proxy(proxy_end, b"HTTP/1.1 403 Forbidden\r\n\r\n"));

        let err = establish_connect_tunnel(&mut client_end, "blocked.test", 443, None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("403"), "unexpected error: {}", err);
    }
}
