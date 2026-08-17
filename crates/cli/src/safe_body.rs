//! Decompression-bomb defence (bounded response-body reader).
//!
//! ## The threat
//!
//! Wafrift fires probes at potentially-hostile WAFs and origins. The
//! reqwest build wafrift uses ships the `gzip` and `brotli` features,
//! which means reqwest AUTOMATICALLY decompresses every response
//! body when the server sets `Content-Encoding: gzip` or `br`.
//! Reqwest does NOT cap the decompressed size.
//!
//! A hostile target, including any WAF under test that decides to
//! retaliate against the scanner, can serve a ~1 KB gzipped response
//! that expands to many gigabytes ("zip bomb"). Without a cap, wafrift
//! exhausts memory and crashes. For a pentester running wafrift on a
//! laptop in front of a customer, that is a remote DoS triggered by a
//! single response header.
//!
//! ## The defence
//!
//! [`read_bounded`] consumes the response as a chunked stream and
//! aborts as soon as the running total exceeds `max_bytes`. The cap
//! applies to the DECOMPRESSED stream, reqwest's gzip / brotli
//! decoders sit BEHIND the bytes_stream chain, so what we count is
//! what the rule engine would see.
//!
//! The default cap [`DEFAULT_MAX_RESPONSE_BYTES`] is 8 MiB, much
//! larger than any legitimate WAF block page, JSON envelope, or
//! HTML response, but small enough to fit in a laptop's headroom
//! many times over.
//!
//! ## Where this gets used
//!
//! Every site that called `.bytes().await` or `.text().await`
//! against an operator-supplied target. Internal call sites that
//! talk to known-trusted services (e.g. the operator's own wafrift
//! listener) may use the larger [`HEADROOM_MAX_RESPONSE_BYTES`].
//!
//! [`read_bounded_text_file`] and [`read_bounded_text_stdin`] replace
//! `std::fs::read_to_string` at every site that accepts operator-supplied
//! file paths. The reason: `read_to_string(path)` has no size cap AND
//! opens a TOCTOU race, a symlink swap between `stat()` and `open()`
//! can bypass a separate size check. These functions open + read in one
//! fd with a hard byte cap, closing both gaps at once.
//!
//! **Rule**: NEVER call `std::fs::read_to_string(path)` or `File::open`
//! + unbounded `read_to_string` on any path derived from operator input
//! (`--raw-request`, `--paths-file`, config files, gene bank). Always
//! use `read_bounded_text_file` with an appropriate cap constant.
//!
//! ## Invariants
//!
//! - The cap is checked BEFORE each chunk is appended. The
//!   allocator never gets a chance to over-allocate based on a
//!   bomb's Content-Length lie.
//! - On overrun we return an `Err`; the caller MUST treat that as
//!   "target tried to bomb us" and abort the probe (never retry).
//! - A network read error returns a different `Err` variant so
//!   callers can distinguish bomb defence from transient I/O.
//! - The function consumes the [`reqwest::Response`] so the
//!   connection is released cleanly on early-abort.

use futures_util::StreamExt;
use reqwest::Response;
use std::fmt;

/// Default size cap for an arbitrary target's response body
/// 8 MiB. Bigger than any legitimate WAF block page or JSON API
/// envelope, smaller than any laptop's free RAM by orders of
/// magnitude.
pub(crate) const DEFAULT_MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Larger cap for responses from operator-controlled services
/// (e.g. their own `wafrift listener`). Still bounded, even a
/// trusted service can have a bug.
///
/// §7: the value is the workspace-canonical
/// [`wafrift_types::MAX_RESPONSE_BODY_BYTES`] (shared with transport's
/// response cap + encoding's decompression-bomb cap). Local name kept.
pub(crate) const HEADROOM_MAX_RESPONSE_BYTES: usize = wafrift_types::MAX_RESPONSE_BODY_BYTES;

/// Outcome of [`read_bounded`].
#[derive(Debug)]
pub(crate) enum ReadError {
    /// Decompressed stream exceeded `max_bytes`. Caller should
    /// treat as hostile target (never retry).
    Overrun {
        cap_bytes: usize,
        observed_bytes: usize,
    },
    /// Network / decompression failure mid-stream.
    Transport(String),
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // N12 fix (dogfood R29 cohort): phrasing was HTTP-centric
            // ("response body") even though this enum is also used
            // for file/stdin reads. Operators reading a wordlist
            // error message that said "response body read failed"
            // were confused. The new phrasing is medium-agnostic.
            Self::Overrun {
                cap_bytes,
                observed_bytes,
            } => write!(
                f,
                "input exceeded {cap_bytes}-byte cap ({observed_bytes} bytes \
                 seen so far), bounded-read defence aborted the read \
                 (decompression-bomb or oversized stream)"
            ),
            Self::Transport(e) => write!(f, "read failed: {e}"),
        }
    }
}

impl std::error::Error for ReadError {}

/// Read the response body as bytes, aborting if the running total
/// exceeds `max_bytes`. The cap is checked AGAINST the
/// decompressed stream, gzip / brotli decoders run upstream of
/// us, so this is what the WAF / origin actually emitted post-
/// decompress.
pub(crate) async fn read_bounded(resp: Response, max_bytes: usize) -> Result<Vec<u8>, ReadError> {
    let mut acc: Vec<u8> = Vec::with_capacity(64 * 1024); // small initial; grows
    let mut stream = resp.bytes_stream();
    while let Some(item) = stream.next().await {
        let chunk = item.map_err(|e| ReadError::Transport(e.to_string()))?;
        if acc.len().saturating_add(chunk.len()) > max_bytes {
            return Err(ReadError::Overrun {
                cap_bytes: max_bytes,
                observed_bytes: acc.len() + chunk.len(),
            });
        }
        acc.extend_from_slice(&chunk);
    }
    Ok(acc)
}

/// String view of the bounded body. Returns `Ok` with the decoded
/// UTF-8 (lossy, replacement chars for any invalid bytes, same
/// shape reqwest's `.text()` returns).
pub(crate) async fn read_bounded_text(
    resp: Response,
    max_bytes: usize,
) -> Result<String, ReadError> {
    let bytes = read_bounded(resp, max_bytes).await?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Serialize a response's status line and header block to bytes, so the
/// reflection fingerprinter can observe input echoed into **headers**
/// (`Location` on a redirect, `Set-Cookie`, custom `X-` headers), not only the
/// body. Many origins decode/normalize a parameter and place the result in a
/// header (a 302 `Location` echoing `?q=`, a cookie round-trip), which a
/// body-only scan would miss and mis-report as "no reflection".
///
/// Bounded at [`HEADER_SCAN_CAP`]: real header blocks are a few KiB; the cap
/// stops a pathological header flood from unbounding the probe. Names and values
/// are emitted verbatim as the origin sent them, the value is what may carry
/// the normalized reflection the fold check looks for.
pub(crate) const HEADER_SCAN_CAP: usize = 64 * 1024;

pub(crate) fn header_bytes(resp: &Response) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 * 1024);
    out.extend_from_slice(format!("HTTP {}\r\n", resp.status().as_u16()).as_bytes());
    for (name, value) in resp.headers() {
        if out.len() >= HEADER_SCAN_CAP {
            break;
        }
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.truncate(HEADER_SCAN_CAP);
    out
}

/// Sane cap for OPERATOR-supplied input files (curl-format paste,
/// session-init file, gene-bank import). These are tiny in
/// practice, a "Copy as cURL" Burp paste is < 16 KiB; a session
/// init file is a single HTTP request. 1 MiB is generous and
/// catches `--curl-file /dev/zero` operator typos AND symlink
/// traps.
pub(crate) const MAX_OPERATOR_INPUT_BYTES: usize = 1024 * 1024;

/// Read `reader` to EOF in 64 KiB chunks, aborting the moment the
/// running total would exceed `max_bytes`. This is the SINGLE
/// OOM-guard loop behind every bounded file/stdin reader in the crate
/// (and `compress`'s input path), callers own the open/lock and any
/// caller-specific error phrasing, while the cap enforcement lives
/// here exactly once. Pre-dedup the same 64 KiB-chunk + `saturating_add`
/// loop was copy-pasted five times; a future tightening (smaller
/// chunk, stricter overrun semantics) would have had to land in all
/// five and would inevitably miss one (CLAUDE.md §7).
pub(crate) fn read_bounded_from<R: std::io::Read>(
    mut reader: R,
    max_bytes: usize,
) -> Result<Vec<u8>, ReadError> {
    let mut buf: Vec<u8> = Vec::with_capacity(8 * 1024);
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let n = reader
            .read(&mut chunk)
            .map_err(|e| ReadError::Transport(e.to_string()))?;
        if n == 0 {
            break;
        }
        if buf.len().saturating_add(n) > max_bytes {
            return Err(ReadError::Overrun {
                cap_bytes: max_bytes,
                observed_bytes: buf.len() + n,
            });
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(buf)
}

/// Bounded `read_to_string`-equivalent for operator-supplied
/// files. Replaces every `std::fs::read_to_string(path)?` site
/// that was vulnerable to OOM on a `/dev/zero` typo / hostile
/// symlink / multi-GB file.
pub(crate) fn read_bounded_text_file(
    path: &std::path::Path,
    max_bytes: usize,
) -> Result<String, ReadError> {
    let f = std::fs::File::open(path)
        .map_err(|e| ReadError::Transport(format!("open {}: {e}", path.display())))?;
    let buf = read_bounded_from(f, max_bytes)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Bounded stdin reader for operator-piped curl-format pastes.
pub(crate) fn read_bounded_text_stdin(max_bytes: usize) -> Result<String, ReadError> {
    let buf = read_bounded_from(std::io::stdin().lock(), max_bytes)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Bounded stdin reader that preserves raw bytes (no UTF-8 lossy
/// conversion). Use when downstream code needs to inspect the
/// payload at byte level (e.g. BOM stripping, binary tampering)
/// before turning it into a string.
pub(crate) fn read_bounded_stdin_bytes(max_bytes: usize) -> Result<Vec<u8>, ReadError> {
    read_bounded_from(std::io::stdin().lock(), max_bytes)
}

/// Shared cap for `.wafrift/gene-bank.json` and any other persisted
/// gene-bank file. Banks accumulate proven winners across hosts but
/// remain compact JSON, even a year of heavy use stays well under
/// the cap. 64 MiB catches `/dev/zero`, hostile symlinks, and
/// runaway-generated files.
pub(crate) const GENE_BANK_FILE_MAX_BYTES: usize = 64 * 1024 * 1024;

#[cfg(test)]
#[path = "safe_body_tests.rs"]
mod tests;
