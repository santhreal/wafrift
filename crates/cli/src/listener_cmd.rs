//! `wafrift listener`: out-of-band callback receiver for blind /
//! stored vulnerability oracles.
//!
//! Some classes of vulnerability never echo a verdict on the *same*
//! response that triggered them:
//!
//! - **Blind SQLi (time-based)**: the difference is latency, not body.
//! - **Stored XSS**: the script executes when a *different* user
//!   loads the page, hours later.
//! - **Blind SSRF**: the server-side fetch hits a host we control;
//!   the original response is just a generic 200/500.
//! - **Out-of-band command injection**: `nslookup attacker.example`
//!   reaches our DNS, not the HTTP response.
//!
//! For each of these the oracle is an **external side-channel**: a
//! callback that arrives at infrastructure WE own, tagged with a
//! unique token that lets us correlate it back to the scan request
//! that planted it. This module is the callback receiver.
//!
//! Workflow:
//!
//! ```text
//!  wafrift listener --bind 0.0.0.0:9000              # start listener
//!  wafrift scan --target T --payload "<...?token=ABCD...>"
//!  (target's backend fetches http://listener.host:9000/ABCD)
//!  listener logs the callback → operator correlates → blind hit
//! ```
//!
//! Design notes (the load-bearing ones):
//!
//! - **Tokens are 128-bit, base32-encoded, collision-resistant.**
//!   Random 16 bytes from `rand::thread_rng`; base32-no-padding so the
//!   token is URL-safe without encoding (the typical embed point is a
//!   URL path or query string). 128 bits is the same security floor
//!   as a UUIDv4.
//! - **The HTTP server is intentionally minimal.** Any GET / POST /
//!   PUT / etc. on `/<token-or-anything>` counts as a callback; the
//!   server records `(timestamp, method, path, source_ip, headers,
//!   body_prefix)` and never executes anything. Body capped at
//!   8 KiB (a callback that ships an exfil >8K is a different
//!   problem).
//! - **No HTTPS by default.** The listener runs HTTP, operators
//!   front it with their own TLS-terminating reverse proxy or
//!   Cloudflare tunnel when they need encryption. Shipping a self-
//!   signed cert that no target will trust is worse than no TLS at
//!   all.
//! - **Bind to 127.0.0.1 by default.** Public-facing listeners are
//!   an authorisation footgun. The operator has to type `--bind
//!   0.0.0.0:PORT` to expose the listener, that explicit step is
//!   the consent gate.
//! - **Token-to-request correlation is the caller's problem.** This
//!   module gives you the token, the embed point is up to the
//!   scanner. Future work integrates this directly into `scan` so
//!   the operator runs one command end-to-end; today it's a
//!   building block.

use clap::Args;
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;

#[derive(Args, Debug)]
pub(crate) struct ListenerArgs {
    /// Address to bind the callback receiver to. Defaults to
    /// loopback, public exposure (`0.0.0.0:PORT`) is an explicit
    /// opt-in so an operator does not accidentally stand up a
    /// world-readable side-channel.
    #[arg(long, default_value = "127.0.0.1:9000")]
    pub bind: String,

    /// Number of tokens to pre-mint on startup (printed to stdout
    /// so the operator can copy them into payloads). Each token
    /// is independent (a callback on any of them is logged).
    #[arg(long, default_value_t = 4)]
    pub tokens: u32,

    /// Output format: `text` prints a human stream; `json` emits one
    /// NDJSON line per callback so the listener pipes cleanly into
    /// `jq`, `tee`, or a downstream log collector.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,

    /// Cap on the body bytes recorded per callback. Anything beyond
    /// is truncated (with a `truncated_bytes` counter in the JSON).
    /// 8 KiB by default, generous for the typical "ping" payload,
    /// hostile for exfil-style abuse.
    #[arg(long, default_value_t = 8 * 1024)]
    pub max_body_bytes: usize,

    /// HTTP read timeout per connection (seconds). Closes lingering
    /// connections that send headers but never the body.
    #[arg(long, default_value_t = 10)]
    pub read_timeout_secs: u64,

    /// IPv4 address to return in DNS A-record responses. Defaults to
    /// `127.0.0.1`. Set to the server's public IP when running
    /// a production interactsh-compat listener.
    #[arg(long, value_name = "IP", default_value = "127.0.0.1")]
    pub server_ip: String,
}

/// One observed inbound HTTP request, the smallest unit of evidence
/// for an OOB callback. Serialised verbatim into NDJSON when
/// `--format json` is selected.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Callback {
    /// Unix timestamp (seconds) the callback was received.
    pub received_at: u64,
    /// Source IP:port of the inbound connection. Parsed via
    /// `TcpStream::peer_addr`; useful when the listener is fronted by
    /// a proxy that doesn't rewrite `X-Forwarded-For` cleanly.
    pub source: String,
    /// HTTP method as the inbound client sent it (uppercased).
    pub method: String,
    /// Request path (`/foo?bar=baz` form, including query string).
    pub path: String,
    /// Token extracted from the path / query string if it matches one
    /// of the pre-minted tokens, else `None`. The token-match logic
    /// is conservative: only an exact substring match against the
    /// registered token set counts, it never tries to fuzzy-match
    /// or normalise URL-encoded forms.
    pub matched_token: Option<String>,
    /// Inbound request headers (lowercased keys for stable diffing).
    pub headers: Vec<(String, String)>,
    /// Body bytes (UTF-8-lossy decoded, capped at `max_body_bytes`).
    pub body_preview: String,
    /// How many body bytes were dropped past the cap.
    pub body_truncated_bytes: usize,
}

/// In-memory registry shared between the HTTP accept loop and the
/// caller. Holds the set of valid tokens + the running callback log.
//
// `dead_code` is silenced because this is a binary crate: `cargo build`
// only sees the call sites in `run_listener` + the tests, which exercise
// every public method, but rustc's reachability analysis on `--bin`
// targets does not always connect them. The library surface IS used.
/// Hard cap on the listener's callback log. Past this, the
/// OLDEST callback gets dropped (FIFO eviction) so the listener
/// can run for an unbounded duration without RAM growth. 100k
/// callbacks is roughly 100 MiB at the typical ~1 KiB payload
/// shape, generous for an authentic pentest run, but bounded so
/// a flood doesn't ramp into a DoS.
pub(crate) const MAX_CALLBACK_LOG: usize = 100_000;

#[derive(Debug, Default)]
pub(crate) struct Registry {
    tokens: RwLock<HashMap<String, ()>>,
    // VecDeque (not Vec) so the FIFO eviction at the MAX_CALLBACK_LOG
    // cap is O(1) via pop_front() instead of O(n) via Vec::remove(0).
    // Critical under the exact DoS scenario the cap defends against
    // token-replay flood, where holding the write-guard for an O(n)
    // shift of up to 100 000 entries would starve every concurrent
    // /_wafrift/check poll from the scan engine. Per perf-hunt N02.
    callbacks: RwLock<std::collections::VecDeque<Callback>>,
}

impl Registry {
    /// New empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-mint `n` random tokens and return them in registration order.
    pub async fn mint(&self, n: u32) -> Vec<String> {
        let mut out = Vec::with_capacity(n as usize);
        let mut tokens = self.tokens.write().await;
        for _ in 0..n {
            let tok = generate_token();
            tokens.insert(tok.clone(), ());
            out.push(tok);
        }
        out
    }

    /// Register an already-generated token. Test-only: production
    /// callers always go through [`Registry::mint`] for randomness.
    /// Gated so the production binary surface does not advertise an
    /// API with no production consumer (LAW 1 (no dead public API)).
    #[cfg(test)]
    pub async fn register(&self, token: impl Into<String>) {
        self.tokens.write().await.insert(token.into(), ());
    }

    /// Snapshot of currently registered tokens, test-only mirror of
    /// the value [`Registry::mint`] already returns. Gated #[cfg(test)]
    /// for the same reason as [`Registry::register`].
    #[cfg(test)]
    pub async fn known_tokens(&self) -> Vec<String> {
        self.tokens.read().await.keys().cloned().collect()
    }

    /// Snapshot of all recorded callbacks. Used in production by the
    /// `/_wafrift/check/<token>` management endpoint to answer the
    /// scan-side oracle's poll, "has this token been received yet?"
    pub async fn callbacks(&self) -> Vec<Callback> {
        // Materialize the VecDeque snapshot into a Vec so callers keep
        // their existing API, the internal storage type changed for
        // O(1) eviction but the wire/IPC contract is unchanged.
        self.callbacks.read().await.iter().cloned().collect()
    }

    /// Count of callbacks that matched a registered token. Test-only
    /// summary, production callers iterate [`Registry::callbacks`]
    /// directly. Gated #[cfg(test)] for the same reason as
    /// [`Registry::register`].
    #[cfg(test)]
    pub async fn matched_count(&self) -> usize {
        self.callbacks
            .read()
            .await
            .iter()
            .filter(|c| c.matched_token.is_some())
            .count()
    }

    /// Look for the first registered token that appears as a
    /// substring of `s`. Returns the matched token, not the location.
    /// Conservative: no URL-decoding, no case folding, the caller
    /// chose the token alphabet (base32) so it survives unmolested
    /// through every reasonable transport.
    pub async fn match_token_in(&self, s: &str) -> Option<String> {
        let tokens = self.tokens.read().await;
        tokens.keys().find(|t| s.contains(t.as_str())).cloned()
    }

    /// Append one observed callback. The matched_token field is
    /// populated by the listener loop before push (so the registry
    /// stays a pure store).
    ///
    /// Cap: the log holds at most [`MAX_CALLBACK_LOG`] entries. When
    /// the cap is hit, the OLDEST callback is dropped. The cap is a
    /// DoS defence (an attacker that learns ONE valid token (e.g).
    /// by observing a real callback) could otherwise flood the
    /// listener with requests carrying that token and balloon RAM.
    async fn push(&self, cb: Callback) {
        let mut cbs = self.callbacks.write().await;
        if cbs.len() >= MAX_CALLBACK_LOG {
            // O(1) FIFO eviction (see VecDeque rationale on the field).
            cbs.pop_front();
        }
        cbs.push_back(cb);
    }
}

// `generate_token` + `base32_encode` live in `crate::callback_token`
//: shared with `crate::scan` so the receiver (listener) and the
// sender (scan's payload substitution) use one source of truth for
// the token format. Re-export at the local path (pub(crate) so the
// inner-crate visibility matches the source, outer pub use here
// would widen visibility beyond what callback_token::generate_token
// intends) so existing listener-only call sites keep compiling.
pub(crate) use crate::callback_token::generate_token;

/// Entry point for `wafrift listener`. Blocks until SIGINT / SIGTERM.
///
/// # Errors
///
/// Returns `ExitCode::from(1)` if the bind address is malformed or
/// the socket cannot be opened.
pub(crate) fn run_listener(args: ListenerArgs) -> ExitCode {
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("{} tokio runtime: {e}", "error:".red());
            return ExitCode::from(1);
        }
    };
    rt.block_on(async move {
        // R44 fix (dogfood pass 4): pre-fix tokens were printed
        // BEFORE the bind attempt, so when the port was busy the
        // operator had already copy-pasted four useless token
        // strings into their payloads before the "address in use"
        // error surfaced. Bind FIRST; mint and print tokens only
        // after the socket is open and the listener is ready to
        // receive callbacks.
        let addr: SocketAddr = match args.bind.parse() {
            Ok(a) => a,
            Err(e) => {
                // R50 tail3 (CLAUDE.md §10 COHERENCE): malformed
                // --bind value is an INPUT error, not an I/O
                // failure. Exit 2 matches the documented exit-code
                // table (pass-11 META).
                eprintln!("{} bind {} parse: {e}", "error:".red(), args.bind);
                return ExitCode::from(2);
            }
        };
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("{} bind {addr}: {e}", "error:".red());
                return ExitCode::from(1);
            }
        };

        let registry = Arc::new(Registry::new());
        let minted = registry.mint(args.tokens).await;

        // Print the minted tokens so the operator can copy them into
        // payloads. In json mode emit one JSON object describing the
        // listener's startup state so downstream consumers know which
        // tokens are valid.
        if args.format == "json" {
            let startup = serde_json::json!({
                "kind": "listener_started",
                "bind": args.bind,
                "tokens": minted,
            });
            println!("{startup}");
        } else {
            println!(
                "{} {}",
                "[wafrift listener]".bold().cyan(),
                format!("listening on {}", args.bind).bright_black()
            );
            for t in &minted {
                println!("  {} {}", "token:".green(), t.bold());
            }
            println!(
                "  {}",
                "(embed any of the above in your payload; callbacks log below)".bright_black()
            );
        }

        let format = args.format.clone();
        let max_body = args.max_body_bytes;
        let read_timeout = Duration::from_secs(args.read_timeout_secs);
        loop {
            let (sock, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("{} accept: {e}", "warn:".yellow());
                    continue;
                }
            };
            let registry_c = registry.clone();
            let format_c = format.clone();
            tokio::spawn(async move {
                let cb = match handle_conn(sock, peer, &registry_c, max_body, read_timeout).await {
                    Ok(Some(cb)) => cb,
                    Ok(None) | Err(_) => return,
                };
                render_callback(&cb, &format_c);
                registry_c.push(cb).await;
            });
        }
    })
}

fn render_callback(cb: &Callback, format: &str) {
    if format == "json" {
        if let Ok(line) = serde_json::to_string(cb) {
            println!("{line}");
        }
    } else {
        let tag = cb
            .matched_token
            .as_deref()
            .map(|t| format!("[token={}]", t))
            .unwrap_or_else(|| "[unknown]".to_string());
        println!(
            "{} {} {} {} {} {}",
            "callback:".bright_green(),
            cb.received_at,
            cb.source,
            cb.method.yellow(),
            cb.path.bright_white(),
            tag.cyan()
        );
    }
}

/// Read one HTTP request off the socket and translate to a Callback.
/// Handles malformed requests by returning Err, the connection is
/// closed and the listener loop moves on.
///
/// Returns `Ok(None)` when the request was handled as a MANAGEMENT
/// API hit (the path begins with `/_wafrift/`), those are answered
/// inline with their own JSON response and intentionally NOT
/// recorded in the registry's callbacks log (otherwise the operator
/// polling the API would pollute their own evidence stream).
async fn handle_conn(
    mut sock: tokio::net::TcpStream,
    peer: SocketAddr,
    registry: &Registry,
    max_body: usize,
    read_timeout: Duration,
) -> Result<Option<Callback>, String> {
    let mut buf = vec![0u8; 16 * 1024];
    // Cap total bytes read so a malicious client cannot keep us in
    // an infinite read loop without ever sending the header
    // terminator. 64 KiB is more than enough for any header section.
    let mut total_read = 0_usize;
    let mut found: Option<(usize, usize)> = None;
    let header_cap = 64 * 1024;
    while found.is_none() {
        let read_fut = sock.read(&mut buf[total_read..]);
        let n = tokio::time::timeout(read_timeout, read_fut)
            .await
            .map_err(|_| "timeout reading headers".to_string())?
            .map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("EOF before headers complete".into());
        }
        total_read += n;
        if let Some(loc) = find_double_crlf(&buf[..total_read]) {
            found = Some(loc);
            break;
        }
        if total_read >= header_cap {
            return Err("header too large".into());
        }
        if total_read == buf.len() {
            buf.resize(buf.len() * 2, 0);
        }
    }
    let (header_end, header_terminator_len) = found.expect("loop exited only when found");
    let head =
        std::str::from_utf8(&buf[..header_end]).map_err(|e| format!("non-utf8 headers: {e}"))?;
    let mut lines = head.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| "missing request line".to_string())?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_ascii_uppercase();
    let path = parts.next().unwrap_or("").to_string();

    let mut headers: Vec<(String, String)> = Vec::new();
    let mut content_length: usize = 0;
    // F101: pre-fix every `Content-Length:` header overwrote the
    // value, so a hostile client sending `Content-Length: 100\r\n
    // Content-Length: 0` set the listener to read 0 body bytes and
    // interpret the real body as the NEXT request, log-injection
    // attack on the callback registry via classic request smuggling.
    // Take the FIRST value; ignore subsequent duplicates (RFC 7230
    // §3.3.2 forbids them outright).
    let mut content_length_seen = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let k_lc = k.trim().to_ascii_lowercase();
            let v_trim = v.trim().to_string();
            if k_lc == "content-length" && !content_length_seen {
                // F-LISTENER-CL-01: parse_or_0 was a request-smuggling
                // vector. A hostile client sending `Content-Length: abc`
                // would silently set content_length=0; the listener would
                // then read zero body bytes and treat the actual body as
                // the next request's headers, classic CL desync. Reject
                // malformed CL with an actionable error so the connection
                // is closed before any framing damage.
                content_length = v_trim
                    .parse::<usize>()
                    .map_err(|e| format!("malformed Content-Length {v_trim:?}: {e}"))?;
                content_length_seen = true;
            }
            headers.push((k_lc, v_trim));
        }
    }

    // Body = (bytes already in buf past the header terminator) + the rest.
    // `header_terminator_len` is 4 for \r\n\r\n, 2 for \n\n, computed
    // alongside `header_end` so non-CRLF clients don't lose body bytes.
    let body_start = header_end + header_terminator_len;
    let already_have = total_read.saturating_sub(body_start);
    let mut body_truncated = 0_usize;
    let mut body = Vec::with_capacity(content_length.min(max_body));
    let take = already_have.min(max_body);
    body.extend_from_slice(&buf[body_start..body_start + take]);
    let mut remaining = content_length.saturating_sub(already_have);
    while remaining > 0 {
        let mut chunk = vec![0u8; remaining.min(16 * 1024)];
        let read_fut = sock.read(&mut chunk);
        let n = tokio::time::timeout(read_timeout, read_fut)
            .await
            .map_err(|_| "timeout reading body".to_string())?
            .map_err(|e| format!("read body: {e}"))?;
        if n == 0 {
            break;
        }
        let want = max_body.saturating_sub(body.len());
        if want > 0 {
            let take = n.min(want);
            body.extend_from_slice(&chunk[..take]);
            body_truncated += n.saturating_sub(take);
        } else {
            body_truncated += n;
        }
        remaining = remaining.saturating_sub(n);
    }
    body_truncated += already_have.saturating_sub(take);

    // Management API: paths under `/_wafrift/` get answered inline
    // and NOT recorded as callbacks. The check endpoint lets a
    // scan-side caller (or the operator with curl) ask "has this
    // token been received yet?" without spawning a polling proxy.
    if let Some(rest) = path.strip_prefix("/_wafrift/check/") {
        // Trim any trailing query string / slash; token alphabet is
        // alnum only so anything past it is noise.
        let token = rest
            .split(&['/', '?', '#'][..])
            .next()
            .unwrap_or("")
            .to_string();
        let received = registry
            .callbacks()
            .await
            .iter()
            .any(|cb| cb.matched_token.as_deref() == Some(token.as_str()));
        let body = serde_json::json!({
            "received": received,
            "token": token,
        })
        .to_string();
        let status = if received { "200 OK" } else { "404 Not Found" };
        let resp = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = sock.write_all(resp.as_bytes()).await;
        let _ = sock.shutdown().await;
        return Ok(None);
    }

    // Reply with a tiny 200 so the upstream client gets a clean close.
    let _ = sock
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await;
    let _ = sock.shutdown().await;

    let received_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Token match: the token may appear in the path, in a header
    // value, or in the body, search all three. We do not URL-decode
    // because the token alphabet is base32 (alphanumeric only) which
    // is already URL-safe; if a target encodes the token anyway it
    // means the URL-decoded path string is what matters, which is
    // what the inbound `path` already is (it's the raw request-line
    // path, no decoding done by the listener).
    let mut matched_token = registry.match_token_in(&path).await;
    if matched_token.is_none() {
        for (_, v) in &headers {
            if let Some(t) = registry.match_token_in(v).await {
                matched_token = Some(t);
                break;
            }
        }
    }
    if matched_token.is_none() {
        let body_str = String::from_utf8_lossy(&body);
        matched_token = registry.match_token_in(&body_str).await;
    }

    Ok(Some(Callback {
        received_at,
        source: peer.to_string(),
        method,
        path,
        matched_token,
        headers,
        body_preview: String::from_utf8_lossy(&body).into_owned(),
        body_truncated_bytes: body_truncated,
    }))
}

/// Locate the end-of-headers double-CRLF (or bare-LF tolerated form).
/// Returns `Some((offset, terminator_len))` so the caller knows where
/// the body starts: `body_start = offset + terminator_len`. The
/// terminator_len is 4 for the canonical `\r\n\r\n` and 2 for the
/// `\n\n` form some scripted clients (curl with `--data-raw`,
/// hand-rolled Python `urllib`) emit. Returning a fixed `4` for the
/// `\n\n` case would silently truncate the first 2 bytes of every
/// body from non-CRLF clients.
fn find_double_crlf(buf: &[u8]) -> Option<(usize, usize)> {
    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        return Some((pos, 4));
    }
    if let Some(pos) = buf.windows(2).position(|w| w == b"\n\n") {
        return Some((pos, 2));
    }
    None
}

#[cfg(test)]
#[path = "listener_cmd_tests.rs"]
mod tests;
