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
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hyper::Uri;
use hyper::header::HeaderValue;
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper_util::client::legacy::connect::{Connected, Connection, HttpConnector};
use hyper_util::rt::TokioIo;
use percent_encoding::percent_decode_str;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};
use tower_service::Service;
use tracing::debug;
use url::{Host, Url};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Timeout for establishing the tunnel through the upstream proxy (TCP connect
/// and the `CONNECT` exchange). This bounds setup only; the resulting tunnel
/// carries no timeout so long-running connections keep working.
const PROXY_SETUP_TIMEOUT: Duration = Duration::from_secs(30);

/// Upper bound on the size of the upstream proxy's `CONNECT` response headers.
/// A well-behaved proxy answers with a short status line and a few headers.
const MAX_CONNECT_RESPONSE_BYTES: usize = 16 * 1024;

/// Parsed configuration for an upstream proxy.
#[derive(Clone, Debug)]
pub struct UpstreamProxy {
    /// Proxy host (DNS name or IP literal) to dial.
    host: String,
    /// Proxy port.
    port: u16,
    /// Pre-built `Proxy-Authorization` header value when credentials are given.
    auth: Option<HeaderValue>,
}

/// Upstream proxy configuration resolved from the proxy environment.
#[derive(Clone, Debug)]
pub struct UpstreamProxies {
    http: Option<UpstreamProxy>,
    https: Option<UpstreamProxy>,
}

impl UpstreamProxies {
    /// Resolve httpjail's own egress proxy settings from the proxy environment.
    pub fn from_env() -> Result<Option<Self>> {
        let http = proxy_from_env("HTTP_PROXY", "http_proxy")?;
        let https = proxy_from_env("HTTPS_PROXY", "https_proxy")?;
        Ok(Self::from_proxies(http, https))
    }

    fn proxy_for_uri(&self, uri: &Uri) -> Option<&UpstreamProxy> {
        match uri.scheme_str() {
            Some("http") => self.http.as_ref(),
            Some("https") => self.https.as_ref(),
            _ => None,
        }
    }

    pub(crate) fn http_auth(&self) -> Option<HeaderValue> {
        self.http.as_ref().and_then(UpstreamProxy::http_auth)
    }

    pub(crate) fn all(proxy: UpstreamProxy) -> Self {
        Self {
            http: Some(proxy.clone()),
            https: Some(proxy),
        }
    }

    fn from_proxies(http: Option<UpstreamProxy>, https: Option<UpstreamProxy>) -> Option<Self> {
        if http.is_none() && https.is_none() {
            return None;
        }
        Some(Self { http, https })
    }

    #[cfg(test)]
    fn from_specs(http: Option<&str>, https: Option<&str>) -> Result<Option<Self>> {
        let http = parse_optional_proxy_spec("HTTP_PROXY", http)?;
        let https = parse_optional_proxy_spec("HTTPS_PROXY", https)?;
        Ok(Self::from_proxies(http, https))
    }
}

fn proxy_from_env(primary: &str, fallback: &str) -> Result<Option<UpstreamProxy>> {
    for name in [primary, fallback] {
        if let Ok(value) = std::env::var(name) {
            let proxy = parse_optional_proxy_spec(name, Some(&value))?;
            if proxy.is_some() {
                return Ok(proxy);
            }
        }
    }
    Ok(None)
}

fn parse_optional_proxy_spec(name: &str, spec: Option<&str>) -> Result<Option<UpstreamProxy>> {
    let Some(spec) = spec.map(str::trim).filter(|spec| !spec.is_empty()) else {
        return Ok(None);
    };
    UpstreamProxy::parse(spec)
        .map(Some)
        .with_context(|| format!("Failed to parse {name}"))
}

impl UpstreamProxy {
    /// Parse an upstream proxy specification such as `http://proxy.corp:3128`,
    /// `http://user:pass@proxy.corp:3128` or a bare `proxy.corp:3128` (the
    /// `http` scheme is then assumed).
    ///
    /// Reaching the proxy itself over TLS (an `https://` proxy URL) is not
    /// supported; HTTPS *destinations* are tunneled through a plain HTTP proxy
    /// with `CONNECT`.
    pub fn parse(spec: &str) -> Result<Self> {
        let spec = spec.trim();
        if spec.is_empty() {
            bail!("Upstream proxy specification is empty");
        }
        let redacted_spec = redact_proxy_spec(spec);
        let normalized = if spec.contains("://") {
            spec.to_string()
        } else {
            format!("http://{spec}")
        };

        let url = Url::parse(&normalized)
            .with_context(|| format!("Invalid upstream proxy URL: {}", redacted_spec))?;

        match url.scheme() {
            "http" => {}
            "https" => bail!(
                "Connecting to an upstream proxy over TLS is not supported: {}. \
                 Use an 'http://' proxy URL; HTTPS destinations are still \
                 tunneled through it with CONNECT.",
                redacted_spec
            ),
            other => bail!(
                "Unsupported upstream proxy scheme '{}': {}",
                other,
                redacted_spec
            ),
        }

        let host = match url.host() {
            Some(Host::Domain(host)) => host.to_string(),
            Some(Host::Ipv4(host)) => host.to_string(),
            Some(Host::Ipv6(host)) => host.to_string(),
            None => bail!("Invalid upstream proxy authority: {}", redacted_spec),
        };

        let port = url
            .port_or_known_default()
            .ok_or_else(|| anyhow!("Invalid upstream proxy authority: {}", redacted_spec))?;

        let auth = if !url.username().is_empty() || url.password().is_some() {
            Some(build_basic_auth(url.username(), url.password())?)
        } else {
            None
        };

        Ok(UpstreamProxy { host, port, auth })
    }

    /// The `Proxy-Authorization` header value, if credentials were supplied.
    ///
    /// Needed by the plain-HTTP forwarding path, where the header travels on the
    /// forwarded request itself rather than on a `CONNECT`.
    pub fn http_auth(&self) -> Option<HeaderValue> {
        self.auth.clone()
    }
}

/// Redact userinfo from a proxy URL-like string before it is logged or included
/// in an error message.
pub fn redact_proxy_spec(spec: &str) -> String {
    let spec = spec.trim();
    let (prefix, rest) = match spec.split_once("://") {
        Some((scheme, rest)) => (format!("{scheme}://"), rest),
        None => (String::new(), spec),
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, suffix) = rest.split_at(authority_end);
    let Some((_, host_port)) = authority.rsplit_once('@') else {
        return spec.to_string();
    };
    format!("{prefix}<redacted>@{host_port}{suffix}")
}

/// Build a `Proxy-Authorization: Basic ...` header value from `user:pass`
/// userinfo, percent-decoding each component first.
fn build_basic_auth(user: &str, pass: Option<&str>) -> Result<HeaderValue> {
    let user = percent_decode_str(user).decode_utf8_lossy();
    let pass = percent_decode_str(pass.unwrap_or("")).decode_utf8_lossy();
    let token = STANDARD.encode(format!("{user}:{pass}"));
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
    proxies: Arc<UpstreamProxies>,
}

impl ProxyConnector {
    pub fn new(proxy: UpstreamProxy) -> Self {
        Self::with_config(UpstreamProxies::all(proxy))
    }

    pub fn with_config(proxies: UpstreamProxies) -> Self {
        let mut http = HttpConnector::new();
        // The proxy is addressed via an http(s) URL; allow non-http schemes so
        // the connector does not reject the dial target.
        http.enforce_http(false);
        http.set_happy_eyeballs_timeout(Some(Duration::from_millis(250)));
        ProxyConnector {
            http,
            proxies: Arc::new(proxies),
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
        let proxy = self.proxies.proxy_for_uri(&dst).cloned();

        Box::pin(async move {
            let Some(proxy) = proxy else {
                let tcp = match timeout(PROXY_SETUP_TIMEOUT, http.call(dst.clone())).await {
                    Ok(result) => result?.into_inner(),
                    Err(_) => return Err(timed_out("connecting directly to destination")),
                };
                let _ = tcp.set_nodelay(true);
                return Ok(ProxyStream::new(tcp, false));
            };

            // Dial the proxy (TCP). The destination scheme is irrelevant here;
            // we always connect to the proxy's host:port.
            let proxy_uri: Uri =
                format!("http://{}", host_port_authority(&proxy.host, proxy.port)).parse()?;
            let mut stream = match timeout(PROXY_SETUP_TIMEOUT, http.call(proxy_uri)).await {
                Ok(result) => result?.into_inner(),
                Err(_) => return Err(timed_out("connecting to upstream proxy")),
            };
            let _ = stream.set_nodelay(true);

            let proxied = if dst.scheme_str() == Some("https") {
                let host = uri_host(&dst).ok_or_else(|| {
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
    io: TokioIo<TcpStream>,
    proxied: bool,
}

impl ProxyStream {
    fn new(io: TcpStream, proxied: bool) -> Self {
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
    let target = host_port_authority(host, port);

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

/// The destination host as a bare host name or IP literal.
///
/// [`Uri::host`] keeps the square brackets that URI syntax requires around an
/// IPv6 literal (`https://[::1]/` yields `[::1]`), so the brackets are stripped
/// here to obtain the host itself. [`host_port_authority`] adds them back when
/// the host is used in an authority position.
fn uri_host(uri: &Uri) -> Option<&str> {
    uri.host().map(|host| {
        host.strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host)
    })
}

/// Format a host and port for use as an HTTP authority, bracketing IPv6
/// literals as required by URI syntax. `host` must be a bare host (see
/// [`uri_host`]); an already-bracketed literal would be bracketed twice.
fn host_port_authority(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plain_proxy() {
        let p = UpstreamProxy::parse("http://proxy.corp:3128").unwrap();
        assert_eq!(p.host, "proxy.corp");
        assert_eq!(p.port, 3128);
        assert!(p.auth.is_none());
    }

    #[test]
    fn parse_proxy_ignores_path_query_and_fragment() {
        let p = UpstreamProxy::parse("http://proxy.corp:3128/path?ignored=true#frag").unwrap();
        assert_eq!(p.host, "proxy.corp");
        assert_eq!(p.port, 3128);
    }

    #[test]
    fn parse_bare_hostport_defaults_to_http() {
        let p = UpstreamProxy::parse("proxy.corp:8080").unwrap();
        assert_eq!(p.host, "proxy.corp");
        assert_eq!(p.port, 8080);
    }

    /// Reaching the proxy itself over TLS is not supported; the error must say
    /// so rather than silently treating the proxy as plain HTTP.
    #[test]
    fn reject_tls_proxy_scheme() {
        let err = UpstreamProxy::parse("https://proxy.corp:8443").unwrap_err();
        assert!(
            err.to_string().contains("over TLS is not supported"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn parse_ipv6_literal_with_port() {
        let p = UpstreamProxy::parse("http://[::1]:3128").unwrap();
        assert_eq!(p.host, "::1");
        assert_eq!(p.port, 3128);
    }

    #[test]
    fn host_port_authority_brackets_ipv6_literal() {
        assert_eq!(host_port_authority("::1", 3128), "[::1]:3128");
        assert_eq!(host_port_authority("proxy.corp", 3128), "proxy.corp:3128");
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
            "Basic dXNlcjpwQHNzOndvcmQ="
        );
    }

    #[test]
    fn redact_proxy_spec_removes_userinfo() {
        assert_eq!(
            redact_proxy_spec("http://user:secret@proxy.corp:3128/path"),
            "http://<redacted>@proxy.corp:3128/path"
        );
        assert_eq!(
            redact_proxy_spec("user:secret@proxy.corp:3128"),
            "<redacted>@proxy.corp:3128"
        );
        assert_eq!(
            redact_proxy_spec("http://proxy.corp:3128"),
            "http://proxy.corp:3128"
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

    #[test]
    fn proxy_config_uses_specs_by_scheme() {
        let proxies = UpstreamProxies::from_specs(
            Some("http://http-proxy.corp:3128"),
            Some("http://https-proxy.corp:8443"),
        )
        .unwrap()
        .unwrap();

        let http_uri: Uri = "http://example.com/".parse().unwrap();
        let https_uri: Uri = "https://example.com/".parse().unwrap();

        assert_eq!(
            proxies
                .proxy_for_uri(&http_uri)
                .map(|proxy| proxy.host.as_str()),
            Some("http-proxy.corp")
        );
        assert_eq!(
            proxies
                .proxy_for_uri(&https_uri)
                .map(|proxy| proxy.host.as_str()),
            Some("https-proxy.corp")
        );
    }

    #[test]
    fn proxy_config_ignores_empty_specs() {
        let proxies = UpstreamProxies::from_specs(Some("  "), None).unwrap();
        assert!(proxies.is_none());
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

    /// An IPv6 literal destination must reach the proxy as `[::1]:443`, taking
    /// the host from the destination `Uri` exactly as the connector does.
    /// `Uri::host()` returns the literal already bracketed, so feeding it
    /// straight into the authority would produce `[[::1]]:443`.
    #[tokio::test]
    async fn connect_tunnel_brackets_ipv6_literal_from_uri() {
        let (mut client_end, proxy_end) = tokio::io::duplex(1024);
        let proxy = tokio::spawn(fake_proxy(
            proxy_end,
            b"HTTP/1.1 200 Connection established\r\n\r\n",
        ));

        let dst: Uri = "https://[::1]/".parse().unwrap();
        let host = uri_host(&dst).unwrap();
        assert_eq!(host, "::1");

        establish_connect_tunnel(&mut client_end, host, dst.port_u16().unwrap_or(443), None)
            .await
            .unwrap();

        let request = proxy.await.unwrap();
        assert!(
            request.starts_with("CONNECT [::1]:443 HTTP/1.1\r\n"),
            "unexpected request: {request}"
        );
        assert!(request.contains("Host: [::1]:443\r\n"));
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
