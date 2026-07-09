//! Forward httpjail's own re-originated requests through an upstream
//! (e.g. corporate) HTTP proxy.
//!
//! httpjail terminates the jailed process's traffic and then re-originates the
//! request towards the real destination. When httpjail itself has no direct
//! egress, that re-originated request must instead traverse an upstream proxy.
//!
//! This is implemented as a hyper *connector* ([`ProxyConnector`]) so that the
//! same high-level `hyper_util` `Client` used for direct egress can be reused
//! unchanged: connection pooling, request serialization and (for HTTPS) the
//! destination TLS handshake are all handled by hyper's own machinery. The
//! connector only decides how the underlying byte stream is obtained:
//!
//! * for `https://` destinations it issues a `CONNECT` to the proxy to obtain a
//!   raw TCP tunnel; the surrounding `hyper_rustls::HttpsConnector` then performs
//!   the destination TLS handshake over that tunnel, and
//! * for `http://` destinations it returns the proxy connection marked as
//!   proxied, so hyper emits the request in absolute-form for the proxy to
//!   forward.
//!
//! Following the streaming style used elsewhere in httpjail (see `proxy_tls.rs`)
//! every bounded read during setup is guarded by a timeout, while the
//! established tunnel itself is left unbounded so long-running connections
//! (WebSocket, gRPC, ...) keep working.

use anyhow::{Context as _, Result, anyhow, bail};
use hyper::Uri;
use hyper::header::HeaderValue;
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper_util::client::legacy::connect::{Connected, Connection, HttpConnector};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Duration, timeout};
use tokio_rustls::TlsConnector;
use tower_service::Service;
use tracing::debug;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Timeout for establishing the tunnel through the upstream proxy (TCP connect,
/// optional TLS to the proxy and the `CONNECT` exchange). This bounds setup
/// only; the resulting tunnel carries no timeout so long-running connections
/// keep working.
const PROXY_SETUP_TIMEOUT: Duration = Duration::from_secs(30);

/// Upper bound on the size of the upstream proxy's `CONNECT` response headers.
/// A well-behaved proxy answers with a short status line and a few headers.
const MAX_CONNECT_RESPONSE_BYTES: usize = 16 * 1024;

/// Object-safe combination of the async byte-stream traits we erase over so the
/// connector can hold either a plain TCP stream or a TLS stream (when the proxy
/// itself is reached over `https://`) behind a single type.
trait IoStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> IoStream for T {}

/// A heap-erased byte stream carrying the connection to the proxy.
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

    /// The `Proxy-Authorization` header value, if credentials were supplied.
    ///
    /// Needed by the plain-HTTP forwarding path, where the header travels on the
    /// forwarded request itself rather than on a `CONNECT`.
    pub fn http_auth(&self) -> Option<HeaderValue> {
        self.auth.clone()
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

/// A hyper connector that routes outbound connections through an
/// [`UpstreamProxy`].
///
/// It is intended to be used as the inner connector of a
/// `hyper_rustls::HttpsConnector`: this connector yields a raw byte stream (the
/// proxy connection for HTTP, or a `CONNECT` tunnel for HTTPS) and the
/// surrounding HTTPS connector layers the destination TLS on top when needed.
#[derive(Clone)]
pub struct ProxyConnector {
    /// Used solely to dial the proxy's `host:port` (never the destination).
    http: HttpConnector,
    proxy: Arc<UpstreamProxy>,
    /// TLS configuration used only when the proxy itself is `https://`.
    proxy_tls: Arc<rustls::ClientConfig>,
}

impl ProxyConnector {
    pub fn new(proxy: UpstreamProxy, proxy_tls: Arc<rustls::ClientConfig>) -> Self {
        let mut http = HttpConnector::new();
        // The proxy is addressed via an http(s) URL; allow non-http schemes so
        // the connector does not reject the dial target.
        http.enforce_http(false);
        http.set_happy_eyeballs_timeout(Some(Duration::from_millis(250)));
        ProxyConnector {
            http,
            proxy: Arc::new(proxy),
            proxy_tls,
        }
    }
}

impl Service<Uri> for ProxyConnector {
    type Response = ProxyStream;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<ProxyStream, BoxError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.http.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let mut http = self.http.clone();
        let proxy = Arc::clone(&self.proxy);
        let proxy_tls = Arc::clone(&self.proxy_tls);

        Box::pin(async move {
            // Dial the proxy (TCP). The destination scheme is irrelevant here;
            // we always connect to the proxy's host:port.
            let proxy_uri: Uri = format!("http://{}:{}", proxy.host, proxy.port).parse()?;
            let tcp = http.call(proxy_uri).await?.into_inner();
            let _ = tcp.set_nodelay(true);

            // Optionally negotiate TLS with the proxy itself.
            let mut stream: BoxedIo = if proxy.tls {
                let name = ServerName::try_from(proxy.host.clone()).map_err(|_| {
                    BoxError::from(format!("Invalid proxy host for TLS SNI: {}", proxy.host))
                })?;
                let connector = TlsConnector::from(Arc::clone(&proxy_tls));
                let tls = match timeout(PROXY_SETUP_TIMEOUT, connector.connect(name, tcp)).await {
                    Ok(result) => result?,
                    Err(_) => return Err(timed_out("during TLS handshake with upstream proxy")),
                };
                Box::new(tls)
            } else {
                Box::new(tcp)
            };

            let proxied = if dst.scheme_str() == Some("https") {
                let host = dst.host().ok_or_else(|| {
                    BoxError::from(format!("CONNECT target has no host: {}", dst))
                })?;
                let port = dst.port_u16().unwrap_or(443);
                establish_connect_tunnel(&mut stream, host, port, proxy.auth.as_ref())
                    .await
                    .map_err(|e| -> BoxError { e.into() })?;
                // The tunnel is transparent end-to-end; destination TLS is
                // layered on top by the surrounding HttpsConnector and the
                // request is sent in origin-form, so do not mark it proxied.
                false
            } else {
                // Plain HTTP: the proxy forwards absolute-form requests. Mark the
                // connection proxied so hyper emits absolute-form request lines.
                true
            };

            Ok(ProxyStream::new(stream, proxied))
        })
    }
}

/// Build a timeout error for the upstream proxy setup phase.
fn timed_out(phase: &str) -> BoxError {
    format!("Timeout {} with upstream proxy", phase).into()
}

/// The connector's response: a byte stream plus the proxied flag that hyper
/// consults to decide between absolute-form and origin-form request lines.
pub struct ProxyStream {
    io: TokioIo<BoxedIo>,
    proxied: bool,
}

impl ProxyStream {
    fn new(io: BoxedIo, proxied: bool) -> Self {
        ProxyStream {
            io: TokioIo::new(io),
            proxied,
        }
    }
}

impl Connection for ProxyStream {
    fn connected(&self) -> Connected {
        Connected::new().proxy(self.proxied)
    }
}

impl Read for ProxyStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_read(cx, buf)
    }
}

impl Write for ProxyStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write_vectored(cx, bufs)
    }
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
    // Bracket IPv6 literals in the request-target and Host header.
    let target = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };

    let mut request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
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
    async fn connect_tunnel_brackets_ipv6_literal() {
        let (mut client_end, proxy_end) = tokio::io::duplex(1024);
        let proxy = tokio::spawn(fake_proxy(
            proxy_end,
            b"HTTP/1.1 200 Connection established\r\n\r\n",
        ));

        establish_connect_tunnel(&mut client_end, "::1", 443, None)
            .await
            .unwrap();

        let request = proxy.await.unwrap();
        assert!(request.starts_with("CONNECT [::1]:443 HTTP/1.1\r\n"));
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
