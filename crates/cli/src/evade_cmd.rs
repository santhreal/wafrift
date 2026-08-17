//! `wafrift evade`: offline payload mutation + encoding.
//!
//! Three input modes (mutually exclusive at the clap layer): `--payload`,
//! `--payload-b64`, `--stdin`. The base64 + stdin forms exist
//! specifically for binary-safe payloads: `argv` truncates at the
//! first NUL byte before our process sees it, so a control-byte
//! payload via `--payload $'\x00\x01\x02'` arrives empty. The
//! `resolve_payload` function names this explicitly in its error
//! string so the operator never wonders why their literal vanished.

use clap::Args;
use colored::Colorize;
use serde_json::json;
use std::io;
use std::path::PathBuf;
use std::process::ExitCode;
use wafrift_grammar::grammar;

/// Payload from stdin caps at 16 MiB, large enough for any
/// real-world attack payload (megabyte multipart uploads, big binary
/// blobs) but small enough to catch `cat /dev/zero | wafrift evade`
/// accidents and process-replacement attacks where stdin is wired to
/// an attacker-controlled stream.
const EVADE_STDIN_PAYLOAD_MAX_BYTES: usize = 16 * 1024 * 1024;

/// Decoded-payload cap for `wafrift evade`. Single source of truth so
/// `resolve_payload` can pre-gate `--payload-b64` length before
/// allocating the decoded buffer, and the post-decode check in
/// `run_evade` enforces the same number. See `run_evade` for the
/// dogfood evidence (17 GB RSS from 64 KiB random input).
pub(crate) const EVADE_PAYLOAD_MAX_BYTES: usize = 16 * 1024;

use crate::Level;
use crate::explain::ExplainTrace;
use crate::helpers::{
    build_variants_explained, confidence_badge, max_mutations_for_level, payload_type_label,
    strategy_pool,
};
use crate::target_context::TargetContext;
use crate::technique_filter::TechniqueFilter;

#[derive(Args, Debug)]
pub(crate) struct EvadeArgs {
    /// Payload to mutate and encode. Mutually exclusive with `--stdin`
    /// and `--payload-b64`.
    #[arg(
        long,
        conflicts_with_all = ["stdin", "payload_b64"],
        required_unless_present_any = ["stdin", "payload_b64"]
    )]
    pub payload: Option<String>,

    /// Base64-encoded payload, for bytes a shell cannot pass on argv.
    /// `--payload $'\x00\x01\x02'` is silently truncated at the first
    /// NUL by the OS (argv is NUL-terminated C strings), so binary /
    /// control-byte payloads MUST come in out-of-band: base64 here, or
    /// raw bytes via `--stdin`. Decoded bytes are interpreted as UTF-8
    /// (lossless for control/extended characters; the engine is text).
    #[arg(long, value_name = "BASE64", conflicts_with_all = ["payload", "stdin"])]
    pub payload_b64: Option<String>,

    /// Read the payload from stdin instead of `--payload`. Useful for
    /// piping (`echo 'X' | wafrift evade --stdin ...`) and the only
    /// binary-safe path for payloads containing NUL/control bytes.
    /// Refuses to run on an interactive terminal so it doesn't hang
    /// silently.
    #[arg(long)]
    pub stdin: bool,

    /// Output format: `text` (default, colored summary), `json` (a
    /// SINGLE top-level object, consistent with every other
    /// command, parseable as `jq .variants[]`), or `jsonl` (one JSON
    /// object per line, the legacy stream form, useful for piping
    /// large variant counts into a downstream consumer that reads
    /// line-by-line).  The legacy `--quiet` flag aliases to `json`
    /// (wrapped object); pre-2026-05 scripts that expected NDJSON
    /// on `--quiet` need to switch to `--format jsonl`.
    #[arg(long, default_value = "text", value_parser = ["text", "json", "jsonl"])]
    pub format: String,

    /// Evasion intensity. Approximate variant counts on an XSS
    /// payload to set expectations: light ~12, medium ~58, heavy
    /// ~1500. Heavy may emit 100x the variants of light and a
    /// proportionally larger JSON blob, choose based on the
    /// rate-limit budget of the downstream `wafrift scan` if you
    /// plan to feed these variants into a live target.
    #[arg(long, value_enum, default_value_t = Level::Medium)]
    pub level: Level,

    /// Apply encoding only, without grammar-aware mutations.
    /// (Shorthand for `--exclude grammar`.)
    #[arg(long)]
    pub encoding_only: bool,

    /// Restrict to listed technique paths (comma-separated; e.g.
    /// `encoding/url,grammar`). Run `wafrift techniques list` for paths.
    /// Explicit selection here overrides `--level` for which strategies
    /// are eligible (the level still bounds variant count).
    #[arg(long, num_args = 1.., value_delimiter = ',')]
    pub only: Vec<String>,

    /// Drop listed technique paths (comma-separated; e.g.
    /// `encoding/url/triple,smuggling`).
    #[arg(long, num_args = 1.., value_delimiter = ',')]
    pub exclude: Vec<String>,

    /// Where the payload will be INJECTED, the HTTP channel, not the
    /// attack class. Allowed values: `header`, `body`, `query-param`,
    /// `cookie`. Attack class (xss / sql / cmdi / ssrf etc.) is inferred
    /// from the payload itself by the grammar engine; do not pass it
    /// here. Mnemonic: "an XSS payload going in a query param" →
    /// `--target-context query-param`. Encoding strategies whose
    /// output is unusable in the chosen channel are skipped (visible
    /// with --explain).
    #[arg(long, value_enum)]
    pub target_context: Option<TargetContext>,

    /// Show per-technique trace: which strategies ran, which were
    /// skipped, and why.
    #[arg(long)]
    pub explain: bool,

    /// Write output to a file instead of stdout.
    #[arg(long, short)]
    pub output: Option<PathBuf>,

    /// Allow `--output` to overwrite an existing file. Default
    /// is to refuse so two back-to-back evades cannot silently
    /// clobber the first run's result. R44 fix (dogfood pass 4).
    #[arg(long, default_value_t = false)]
    pub force_overwrite: bool,
}

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn run_evade(args: EvadeArgs, quiet: bool) -> ExitCode {
    // `--quiet` and `--format json` BOTH select machine-readable
    // output.  Either spelling now produces the wrapped form
    // (single top-level object with a `variants` array), that's
    // the workspace-wide JSON-shape contract every other command
    // already honours.  The legacy NDJSON form is reachable via
    // the explicit `--format jsonl` (added 2026-05 by dogfood pass
    // 4).
    let quiet = quiet || args.format == "json" || args.format == "jsonl";
    // R44 fix (dogfood pass 4): pre-fix `--output PATH` with the
    // default text format silently ignored -o, emitted the colored
    // text body to stdout, and exited 0 with NO file written. The
    // text branch was println-based throughout and never consulted
    // args.output. Reject the combination explicitly so the
    // operator switches to a machine-readable format or drops -o.
    if args.output.is_some() && args.format == "text" {
        eprintln!(
            "{} --output / -o requires `--format json` or `--format jsonl`. \
             Text-mode output carries ANSI color codes that are unsafe to \
             persist (they would appear as escape sequences in the file). \
             Re-run with `--format json -o {} ` or drop -o to print to stdout.",
            "Input error:".red().bold(),
            args.output
                .as_ref()
                .map_or("<path>".to_string(), |p| p.display().to_string()),
        );
        return ExitCode::from(2);
    }
    // R44 fix (dogfood pass 4): pre-fix `-o existing.json` overwrote
    // the existing file with zero warning. Two back-to-back evades
    // with the same output path silently clobbered the first
    // result. Warn at the start of run if the file exists so the
    // operator notices before re-launching scan; --force-overwrite
    // opts back into the legacy behaviour.
    if let Some(ref path) = args.output
        && let Err(msg) = crate::helpers::confirm_output_overwrite_safe(path, args.force_overwrite)
    {
        eprintln!("{} {msg}", "Output error:".red().bold());
        return ExitCode::from(2);
    }
    let payload = match resolve_payload(&args) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("{} {msg}", "Input error:".red().bold());
            return ExitCode::from(2);
        }
    };
    // Mutation engine generates O(payload_size × variants) bytes;
    // 64 KiB random input still produced 17 GB RSS in dogfooding
    // (the per-byte permutation explosion is super-linear). Real
    // attack payloads are kilobytes at most. XSS one-liners
    // (~256 bytes), SQL tautologies (~64 bytes), command-injection
    // chains (~1 KiB). 16 KiB is generous for any legitimate
    // payload AND keeps RSS under 1 GB in the worst case observed.
    // Cap lives module-level (`EVADE_PAYLOAD_MAX_BYTES`) so the
    // base64 input path can pre-gate before allocating the decode.
    if payload.len() > EVADE_PAYLOAD_MAX_BYTES {
        eprintln!(
            "{} payload is {} bytes; the mutation engine fans out per-byte and \
             accidentally piping a wordlist or large body OOMs the process. Cap is \
             {} bytes ({} KiB). Use `wafrift scan` for path-level testing of large \
             inputs, or split the payload into the actual attack vector.",
            "Input error:".red().bold(),
            payload.len(),
            EVADE_PAYLOAD_MAX_BYTES,
            EVADE_PAYLOAD_MAX_BYTES / 1024,
        );
        return ExitCode::from(2);
    }

    let filter = match TechniqueFilter::parse(&args.only, &args.exclude) {
        Ok(f) => f,
        Err(msg) => {
            eprintln!("{} {msg}", "Filter error:".red().bold());
            return ExitCode::from(2);
        }
    };
    let payload_type = grammar::classify(&payload);
    let pool = strategy_pool(args.level, !args.only.is_empty());
    let strategies = filter.filter_strategies(pool);
    let max_mutations = max_mutations_for_level(args.level);
    let encoding_only = args.encoding_only || !filter.grammar_enabled();

    let mut trace = args.explain.then(ExplainTrace::default);
    let mut variants = build_variants_explained(
        &payload,
        payload_type,
        encoding_only,
        &strategies,
        max_mutations,
        args.target_context,
        trace.as_mut(),
    );

    // Tamper variants are a SEPARATE variant axis from the encoding
    // `Strategy` enum.  They get applied opt-in here whenever the
    // operator selected one or more `tamper/...` paths via `--only`
    // (or `tamper` as a bare family).  This closes the long-standing
    // wiring gap where the tamper registry existed but no `evade`
    // surface invoked it, leaving the new frontier 2026 tampers
    // (zero_width_inject, postgres_dollar_quote, etc.) effectively
    // unreachable from the offline mutator.  Tampers in the default
    // (no `--only`) flow are deliberately left to `wafrift scan` so
    // the default evade output doesn't balloon from 12 to 31 variants
    // and surprise existing scripts.
    let any_tamper_selector = args
        .only
        .iter()
        .flat_map(|s| s.split(','))
        .map(str::trim)
        .any(|sel| sel == "tamper" || sel.starts_with("tamper/"));
    if any_tamper_selector {
        let tamper_registry = wafrift_encoding::tamper::TamperRegistry::with_defaults();
        // Tamper context resolution: prefer the operator-supplied
        // `--target-context` when set (body / header / query / etc.)
        //: that's what carrier-aware tampers like ct_starvation
        // need. Fall back to the payload-class label (sql / xss /
        // etc.) when no target context was provided, preserving
        // the historical default for tampers that key on payload
        // shape (e.g. mxss_namespace_wrap on XSS).
        //
        // Pre-fix (dogfood 2026-05): ct_starvation never fired
        // because the context passed in was always the payload-
        // class string ("SQL Injection" / "Unknown") which
        // ct_starvation's body/form/json/multipart match never
        // hits (every variant was Idempotent-skipped).
        let context_str: Option<&str> = match args.target_context {
            Some(tc) => Some(tc.label()),
            None => {
                let label = payload_type_label(payload_type);
                if label.is_empty() { None } else { Some(label) }
            }
        };
        let mut seen_tamper_payloads: std::collections::HashSet<String> =
            variants.iter().map(|v| v.payload.clone()).collect();
        for &tamper_name in wafrift_encoding::tamper::all_tamper_names() {
            let path = format!("tamper/{tamper_name}");
            if !filter.allows_path(&path) {
                continue;
            }
            let Some(strat) = tamper_registry.get(tamper_name) else {
                continue;
            };
            let mutated = strat.tamper(&payload, context_str);
            // Record the tamper outcome in the explain trace
            // operator running `--explain` must see whether a
            // selected tamper actually fired or was a no-op /
            // duplicate on this specific payload.
            if mutated == payload {
                if let Some(ref mut t) = trace {
                    t.record_tamper(tamper_name, crate::explain::TamperOutcome::Idempotent);
                }
                continue;
            }
            if !seen_tamper_payloads.insert(mutated.clone()) {
                if let Some(ref mut t) = trace {
                    t.record_tamper(
                        tamper_name,
                        crate::explain::TamperOutcome::DuplicateOfExisting,
                    );
                }
                continue;
            }
            if let Some(ref mut t) = trace {
                t.record_tamper(tamper_name, crate::explain::TamperOutcome::Applied);
            }
            variants.push(crate::helpers::Variant {
                payload: mutated,
                techniques: vec![format!("tamper:{tamper_name}")],
                confidence: strat.aggressiveness().clamp(0.05, 0.95),
            });
        }
    }

    if variants.is_empty() {
        // Empty variant set is a LEGITIMATE outcome, operator
        // selected a tamper that doesn't apply to this payload
        // shape (e.g. `--only tamper/postgres_dollar_quote` on a
        // payload with no `'`).  Exit 0 with an empty array so
        // CI pipelines that treat non-zero as error don't break
        // on a no-op.  Found via dogfood pass 4 (2026-05).
        if quiet {
            let mut body = json!({
                "variants": serde_json::Value::Array(Vec::new()),
                "note": "no variants generated, selected techniques produced no transform on this payload",
                "payload_type": payload_type_label(payload_type),
            });
            if let Some(t) = trace.as_ref() {
                body["explain"] = t.to_json()["explain"].clone();
            }
            if let Some(ref path) = args.output {
                if let Err(e) = std::fs::write(path, format!("{body}\n")) {
                    eprintln!("failed to write evade output to {}: {e}", path.display());
                }
            } else {
                println!("{body}");
            }
        } else {
            eprintln!(
                "{}",
                "No variants generated for the supplied payload."
                    .yellow()
                    .bold()
            );
            if let Some(ctx) = args.target_context {
                eprintln!(
                    "  Target context: {}, strategies whose output is unusable here were skipped.",
                    ctx.label()
                );
            }
            if !args.only.is_empty() && !args.explain {
                eprintln!(
                    "  Hint: re-run with --explain to see which techniques were considered and why each was skipped."
                );
            }
            if let Some(t) = trace.as_ref() {
                t.print_text();
            }
        }
        // Exit 0 (no variants is a legitimate outcome, not an error).
        return ExitCode::SUCCESS;
    }

    // Output format resolution:
    //   --format jsonl       → NDJSON (one object per line, plus
    //                          optional trailing explain object).
    //                          Streaming-friendly for large runs.
    //   --format json        → SINGLE top-level object with a
    //                          `variants` array.  Consistent with
    //                          every other wafrift command: `jq
    //                          .variants[]` works.  Default for
    //                          the `--quiet` legacy alias.
    //   --quiet              → alias for `--format json` (wrapped).
    //   --format text (default) → human-readable colorised output.
    //
    // The previous behaviour emitted NDJSON on both `--format json`
    // and `--quiet`, breaking `jq .field` consumers and making
    // evade the only command that disagreed with the workspace's
    // JSON-shape contract.  Found via dogfood pass 4 (2026-05).
    let emit_jsonl = args.format == "jsonl";
    let emit_json_obj = !emit_jsonl && quiet;
    if emit_jsonl || emit_json_obj {
        let mut buf = String::new();
        if emit_json_obj {
            // Wrapped form: one top-level object containing the
            // variants array plus the optional explain block.
            let variant_objs: Vec<_> = variants
                .iter()
                .map(|variant| {
                    // Round to 2 dp to suppress floating-point noise
                    // (e.g. 0.93 stored as 0.9299999999999999 in f64).
                    let conf = (variant.confidence * 100.0).round() / 100.0;
                    json!({
                        "payload": variant.payload,
                        "techniques": variant.techniques,
                        "confidence": conf,
                    })
                })
                .collect();
            // schema_version + wafrift_version for downstream parsers
            // (per perf-hunt F28). Schema version bumps when a field
            // is removed or renamed, pure additive changes leave it
            // unchanged. Pinned at 1 today; integration tests assert
            // these keys exist so a regression that drops them lights
            // up at PR time.
            // R53 pass-15 §8-A (CLAUDE.md §11 UTILIZATION): include
            // a per-invocation timestamp. Pre-fix five concurrent
            // `wafrift evade` invocations with the same payload
            // produced structurally identical JSON envelopes;
            // dedup / triage / audit tooling collapsed them.
            // generated_at_unix_ms is additive (no schema bump
            // needed (schema_version bumps only on remove/rename)).
            let generated_at_unix_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            let mut top = json!({
                "schema_version": 1u32,
                "wafrift_version": env!("CARGO_PKG_VERSION"),
                "generated_at_unix_ms": generated_at_unix_ms,
                "variants": variant_objs,
            });
            if let Some(t) = trace.as_ref() {
                let explain = t.to_json();
                top["explain"] = explain["explain"].clone();
            }
            let rendered = top.to_string();
            if args.output.is_some() {
                buf.push_str(&rendered);
                buf.push('\n');
            } else {
                println!("{rendered}");
            }
        } else {
            // Legacy NDJSON form: one object per line.
            for variant in &variants {
                let conf = (variant.confidence * 100.0).round() / 100.0;
                let obj = json!({
                    "payload": variant.payload,
                    "techniques": variant.techniques,
                    "confidence": conf,
                });
                if args.output.is_some() {
                    buf.push_str(&obj.to_string());
                    buf.push('\n');
                } else {
                    println!("{obj}");
                }
            }
            if let Some(t) = trace.as_ref() {
                let explain_obj = t.to_json();
                if args.output.is_some() {
                    buf.push_str(&explain_obj.to_string());
                    buf.push('\n');
                } else {
                    println!("{explain_obj}");
                }
            }
        }
        if let Some(ref path) = args.output {
            if let Err(e) = std::fs::write(path, &buf) {
                eprintln!("failed to write evade output to {}: {e}", path.display());
                return ExitCode::from(1);
            }
            eprintln!("evade results written to {}", path.display());
        }
    } else {
        println!(
            "{} {}",
            "Payload Type:".bold().cyan(),
            payload_type_label(payload_type).bold()
        );
        println!(
            "{} {}",
            "Encoding Level:".bold().cyan(),
            format!("{:?}", args.level).to_lowercase().yellow()
        );
        if let Some(ctx) = args.target_context {
            println!(
                "{} {}",
                "Target Context:".bold().cyan(),
                ctx.label().yellow()
            );
        }

        for (index, variant) in variants.iter().enumerate() {
            println!(
                "\n{} {} {}",
                "Variant".bold().green(),
                format!("#{}", index + 1).bold().green(),
                confidence_badge(variant.confidence)
            );
            println!(
                "{} {}",
                "Techniques:".bold().cyan(),
                variant.techniques.join(" -> ").yellow()
            );
            // Escape non-printable ASCII control bytes so tampers
            // like `bell_separator` (BEL 0x07), `null_byte` (NUL),
            // and the zero-width Unicode injectors don't render as
            // invisible characters in the operator's terminal
            // the terminal silently swallows BEL / NUL / NULL and
            // the operator can't tell the tamper fired.  This is
            // the "byte-level visibility" requirement called out
            // in the 2026-05 dogfood pass.
            println!(
                "{} {}",
                "Payload:".bold().cyan(),
                visualize_invisible_bytes(&variant.payload).bright_white()
            );
        }

        // Top-N tail summary: when the variant set is large enough
        // to fill more than one terminal screen (>= 8 variants),
        // surface the top 5 by confidence + the technique frequency
        // breakdown. This is a UX dogfood gap, operators reading
        // a 30-variant emit want to know "which 5 should I try
        // first?" without re-scrolling the whole list. Suppressed
        // for short emits where the body is already a glanceable
        // summary.
        if variants.len() >= 8 {
            print_top_n_summary(&variants);
        }

        if let Some(t) = trace.as_ref() {
            t.print_text();
        }
    }

    ExitCode::SUCCESS
}

/// Trailing tail printed after the per-variant body in text mode.
/// Pure wrapper: builds the string via [`top_n_summary_text`] (which
/// is unit-testable) and prints it. Behind the >=8 variant threshold
/// in the caller so short emits stay quiet.
fn print_top_n_summary(variants: &[crate::helpers::Variant]) {
    print!("{}", top_n_summary_text(variants));
}

/// Build the top-N summary tail as a single string. Two blocks:
///   - Top 5 variants by confidence (the "try these first" list).
///   - Technique-chain frequency (helps the operator spot which
///     mutator family the engine leaned on).
///
/// Pure (no stdout I/O), so unit tests can assert on the rendered
/// content directly. Each line is terminated by `\n`.
fn top_n_summary_text(variants: &[crate::helpers::Variant]) -> String {
    use std::collections::BTreeMap;
    use std::fmt::Write as _;
    const TOP_N: usize = 5;
    let mut out = String::new();
    out.push('\n');
    let _ = writeln!(
        out,
        "{}",
        "─── Summary (top-5 by confidence) ───"
            .bold()
            .bright_black()
    );
    let mut ranked: Vec<(usize, &crate::helpers::Variant)> = variants.iter().enumerate().collect();
    // Stable-sort by descending confidence; ties keep input order.
    ranked.sort_by(|a, b| {
        b.1.confidence
            .partial_cmp(&a.1.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    for (orig_idx, v) in ranked.iter().take(TOP_N) {
        let _ = writeln!(
            out,
            "  #{:<3} conf {:.2}  {}",
            orig_idx + 1,
            v.confidence,
            v.techniques.join(" -> ").yellow()
        );
    }
    // Technique-chain frequency. The chain (joined) is the bucket
    // key because two variants reaching the same end state via
    // different mutators are usually equivalent in practice; if you
    // care about per-mutator frequency, --explain has the per-call
    // counters.
    let mut freq: BTreeMap<String, usize> = BTreeMap::new();
    for v in variants {
        *freq.entry(v.techniques.join(" -> ")).or_insert(0) += 1;
    }
    if freq.len() > 1 {
        out.push('\n');
        let _ = writeln!(
            out,
            "{}",
            "─── Technique frequency ───".bold().bright_black()
        );
        let mut chain_counts: Vec<(&String, &usize)> = freq.iter().collect();
        chain_counts.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
        for (chain, n) in chain_counts.iter().take(TOP_N) {
            let _ = writeln!(out, "  {:>3}×  {}", n, chain.yellow());
        }
    }
    out
}

/// Resolve the evade payload from `--payload`, `--payload-b64`, or
/// `--stdin`. Clap's `required_unless_present_any` + `conflicts_with`
/// guarantees exactly one source at the CLI layer; this validates and
/// decodes the value.
///
/// Binary-safety: `--stdin` is read as raw bytes (not
/// `read_to_string`, which hard-errors on the first invalid UTF-8 byte
/// and so could never accept a binary payload) and `--payload-b64`
/// carries arbitrary bytes past the shell's NUL-terminated argv. Both
/// are lossily decoded to UTF-8 because the mutation/encoding engine
/// is text, control bytes (`\x00`–`\x1f`) survive losslessly; only
/// genuinely invalid UTF-8 sequences become U+FFFD.
fn resolve_payload(args: &EvadeArgs) -> Result<String, String> {
    use base64::Engine as _;

    if let Some(b64) = &args.payload_b64 {
        let trimmed = b64.trim();
        if trimmed.is_empty() {
            return Err("--payload-b64 is empty".to_string());
        }
        // R55 pass-17 I3 (CLAUDE.md §15 AUDIT / unbounded reads):
        // base64 inflates 3 bytes → 4 chars, so a `--payload-b64` of
        // ~22 KiB is the largest input that can decode to within the
        // 16 KiB payload cap. Reject earlier inputs BEFORE the
        // allocator materialises the decoded buffer, a 1 GiB base64
        // arg used to fully decode to ~750 MiB before the post-decode
        // check at the top of `run_evade` rejected it. Slack of +64
        // covers padding chars and stray whitespace inside the string.
        const B64_MAX_LEN: usize = (EVADE_PAYLOAD_MAX_BYTES * 4) / 3 + 64;
        if trimmed.len() > B64_MAX_LEN {
            return Err(format!(
                "--payload-b64 is {} bytes encoded; the decoded payload would exceed the {} byte cap",
                trimmed.len(),
                EVADE_PAYLOAD_MAX_BYTES,
            ));
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(trimmed)
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(trimmed))
            .map_err(|e| format!("--payload-b64 is not valid base64: {e}"))?;
        if bytes.is_empty() {
            return Err("--payload-b64 decoded to zero bytes".to_string());
        }
        return Ok(String::from_utf8_lossy(&bytes).into_owned());
    }

    if args.stdin {
        use std::io::IsTerminal;
        if io::stdin().is_terminal() {
            return Err(
                "--stdin requires a pipe (e.g. `echo 'X' | wafrift evade --stdin ...`); refusing to wait on an interactive terminal".to_string(),
            );
        }
        let mut buf = crate::safe_body::read_bounded_stdin_bytes(EVADE_STDIN_PAYLOAD_MAX_BYTES)
            .map_err(|e| format!("failed to read payload from stdin: {e}"))?;
        // PowerShell silently prepends a UTF-8 BOM (`\xEF\xBB\xBF`)
        // to piped output by default. `Write-Output "x" | wafrift
        // evade --stdin` arrives as `\u{FEFF}x`, which then carries
        // through every tamper output as an invisible prefix. Strip
        // the BOM unconditionally so PowerShell + cmd + bash + zsh
        // pipes all converge on the same bytes.
        if buf.starts_with(b"\xef\xbb\xbf") {
            buf.drain(0..3);
        }
        // Strip a single trailing newline (the `echo 'x' |` case) without
        // mangling embedded control bytes in a deliberate binary payload.
        if buf.last() == Some(&b'\n') {
            buf.pop();
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }
        }
        if buf.is_empty() {
            return Err("stdin produced an empty payload".to_string());
        }
        return Ok(String::from_utf8_lossy(&buf).into_owned());
    }

    let raw = args.payload.clone().ok_or_else(|| {
        "no payload supplied (use --payload, --payload-b64, or --stdin)".to_string()
    })?;
    if raw.is_empty() {
        // The overwhelmingly common cause of an *empty* `--payload`
        // value is a shell binary literal: `--payload $'\x00\x01\x02'`.
        // execve(2) passes argv as NUL-terminated C strings, so the
        // kernel truncates the argument at the first NUL *before* the
        // process ever sees it (wafrift receives "", not the bytes).
        // No amount of in-process parsing can recover them; the only
        // fix is an out-of-band channel. Say so, with the exact
        // commands.
        return Err("--payload is empty. If you passed binary/NUL bytes (e.g. \
             $'\\x00\\x01\\x02'), the shell truncated the argument at the \
             first NUL byte before wafrift could see it, argv cannot \
             carry NULs. Use a binary-safe channel instead:\n  \
             printf '\\x00\\x01\\x02' | wafrift evade --stdin ...\n  \
             wafrift evade --payload-b64 \"$(printf '\\x00\\x01\\x02' | base64)\" ..."
            .to_string());
    }
    Ok(raw)
}

/// Render a payload string with non-printable / invisible Unicode
/// codepoints escaped to their `\xNN` or `\u{NNNN}` form so the
/// operator can SEE what byte-level transform a tamper applied.
/// Terminals silently swallow BEL (`\x07`), NUL (`\x00`), and the
/// zero-width Unicode injectors (`\u{200B}` etc.); without this
/// the operator can't tell whether the transform fired.
///
/// Only ASCII printable + tab + standard whitespace pass through
/// verbatim.  Everything else gets the explicit hex / unicode
/// escape form.  JSON output is unaffected (serde escapes these
/// automatically); this helper is for the text-mode `evade`
/// printer only.
pub(crate) fn visualize_invisible_bytes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            // ASCII printable + tab + newline + carriage-return
            // pass through verbatim.  Newline preservation matters
            // for multi-line payloads (XSS HTML templates etc).
            '\t' | '\n' | '\r' => out.push(ch),
            c if (' '..='~').contains(&c) => out.push(c),
            // Common Unicode control / zero-width / format chars
            // get the explicit `\u{...}` form so the operator
            // sees the transform.
            '\u{200B}' => out.push_str("\\u{200B}"),
            '\u{200C}' => out.push_str("\\u{200C}"),
            '\u{200D}' => out.push_str("\\u{200D}"),
            '\u{FEFF}' => out.push_str("\\u{FEFF}"),
            c if (c as u32) < 0x20 || c as u32 == 0x7F => {
                out.push_str(&format!("\\x{:02X}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
#[path = "evade_cmd_tests.rs"]
mod tests;
