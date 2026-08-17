//! `wafrift oneshot`: the one-shot demo command.
//!
//! Runs `detect` -> `fingerprint` -> `bypass-probe` against a single
//! target, with an optional `scan` phase when `--payload` is given,
//! and stitches the results into one polished markdown writeup. The
//! pitch: a stakeholder asks "what does wafrift do?", you answer with
//! one command and hand them the markdown.
//!
//! Design notes:
//!
//! - Every phase is **best-effort**: a network blip in one phase
//!   doesn't kill the others. The report calls out which phases ran,
//!   which were skipped, and which errored.
//! - Output is deterministic ordering (detect, fingerprint,
//!   bypass-probe, scan) so two runs against the same target produce
//!   comparable diffs.
//! - No new evasion logic lives here, it composes the existing
//!   `waf_detect`, `bypass_probe`, and `scan` paths so the demo can
//!   never drift from real wafrift behaviour. Anything the demo
//!   reports is something the operator could verify with the
//!   underlying subcommand.
//! - Bounded by default: scan caps at 30 variants and bypass-probe
//!   uses the same sensible default concurrency as the standalone
//!   command. The demo must be fast or no one runs it twice.

use clap::Args;
use colored::Colorize;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;
use wafrift_detect::waf_detect;
use wafrift_encoding::auth_bypass::AUTH_BYPASS_PROBE_COUNT;

use crate::bypass_probe::{BypassProbeArgs, run_bypass_probe};
use crate::detect_cmd::{fetch_differential, fetch_for_detect, infra_markers};
use crate::helpers::shell_single_quote;

/// Max divergences / variants rendered per section in the full
/// markdown writeup. Pre-R49 (CLAUDE.md §7 DEDUPLICATION) two
/// per-block `const RENDER_CAP` declarations drifted; one canonical
/// source now.
const RENDER_CAP: usize = 25;

#[derive(Args, Debug)]
pub(crate) struct OneshotArgs {
    /// Target URL (the surface to probe end-to-end).
    pub target: String,

    /// Payload to mutate and fire through the scan phase. When omitted,
    /// the scan phase is skipped and the report contains only detect /
    /// fingerprint / bypass-probe.
    #[arg(long)]
    pub payload: Option<String>,

    /// Parameter name for the scan phase. Ignored when `--payload` is
    /// not given.
    #[arg(long, default_value = "q")]
    pub param: String,

    /// Path to a file of one URL path per line for the bypass-probe
    /// phase to sweep (defaults to single-URL mode).
    #[arg(long)]
    pub paths_file: Option<String>,

    /// Write the rendered markdown report to this file in addition to
    /// stdout. Conventional name: `depth-<host>-<date>.md`.
    #[arg(long, short)]
    pub output: Option<PathBuf>,

    /// HTTP timeout in seconds for each phase. NOTE on total runtime: the
    /// bypass-probe phase fires its full sweep (~270 probes) at
    /// `--concurrency` parallelism, so worst-case wall-clock ≈
    /// probes × `--timeout-secs` ÷ `--concurrency` when a target stalls or
    /// rate-limits (e.g. 270 × 12 ÷ 8 ≈ 400s). To bound a slow run: lower
    /// `--timeout-secs`, raise `--concurrency`, or pass
    /// `--skip-bypass-probe`.
    #[arg(long, default_value_t = 12)]
    pub timeout_secs: u64,

    /// Skip TLS cert verification (lab targets only).
    #[arg(long)]
    pub insecure: bool,

    /// Skip the bypass-probe phase. Useful when the target's rate
    /// limiter makes the full auth/path/method sweep noisy.
    #[arg(long)]
    pub skip_bypass_probe: bool,

    /// Skip the scan phase even if `--payload` is given.
    #[arg(long)]
    pub skip_scan: bool,

    /// Hard cap on the variant set fired by the scan phase. Passed
    /// through to `wafrift scan --variants-cap N`; the lower-
    /// confidence tail is dropped first. Also tunes `--level`
    /// (≤15 → light, ≤25 → medium, otherwise heavy) so smaller
    /// values run the lighter build pipeline. Default 30 keeps the
    /// demo command fast; raise for a deeper sweep.
    #[arg(long, default_value_t = 30)]
    pub scan_variants: usize,

    /// Inter-request delay (ms) for both bypass-probe and scan, the
    /// shared politeness knob.
    #[arg(long, default_value_t = 25)]
    pub delay_ms: u64,

    /// Concurrent in-flight probes for the bypass-probe phase.
    #[arg(long, default_value_t = 8)]
    pub concurrency: usize,

    /// Output format: `markdown` (default) renders the full writeup;
    /// `text` collapses to a terminal-friendly summary; `json` emits
    /// the structured report for CI consumers.
    #[arg(long, default_value = "markdown", value_parser = ["markdown", "text", "json"])]
    pub format: String,
}

/// Aggregated per-phase results (the input to the renderer).
#[derive(Debug, Default, serde::Serialize)]
struct OneshotReport {
    target: String,
    started_at: String,
    /// Total wall-clock elapsed for the whole run, in milliseconds.
    elapsed_ms: u128,
    detect: PhaseDetect,
    fingerprint: PhaseFingerprint,
    bypass_probe: PhaseBypassProbe,
    scan: PhaseScan,
}

#[derive(Debug, Default, serde::Serialize)]
struct PhaseDetect {
    ran: bool,
    error: Option<String>,
    baseline_status: Option<u16>,
    baseline_body_len: Option<usize>,
    detected: Vec<DetectedWaf>,
    /// Differential-probe verdict when the static-signature corpus
    /// came back empty: `Some(reason)` when a benign vs attack
    /// probe diverged enough to infer a WAF, `None` otherwise.
    /// Skipped entirely when the static corpus DID identify a WAF
    /// (no need to double-fire).
    differential: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct DetectedWaf {
    name: String,
    confidence: f64,
    indicators: Vec<String>,
}

#[derive(Debug, Default, serde::Serialize)]
struct PhaseFingerprint {
    ran: bool,
    markers: Vec<(String, String)>,
}

#[derive(Debug, Default, serde::Serialize)]
struct PhaseBypassProbe {
    ran: bool,
    skipped_reason: Option<String>,
    error: Option<String>,
    /// Rendered text output of the underlying `bypass-probe` command
    ///: embedded verbatim into the markdown report so the writeup is
    /// self-contained.
    raw_text: Option<String>,
    /// Structured findings drained from the `bypass-probe --format
    /// json --output <tmp>` capture. Empty when the phase was
    /// skipped, errored, or genuinely found no divergences. Each
    /// entry has the divergence-bearing fields the renderer needs:
    /// family/label/severity/status/curl. Mirrors what the operator
    /// would see in JSON mode of `wafrift bypass-probe`.
    divergences: Vec<DivergenceSummary>,
    /// Per-URL counters carried over from the JSON capture so the
    /// markdown section 3 can show a one-liner like "10/191 probes
    /// flagged" without the operator scrolling.
    total_probes: Option<u64>,
    total_divergences: Option<u64>,
}

/// One bypass-probe finding row. Matches the shape `bypass_probe.rs`
/// emits per-divergence under `--format json`. Narrow on purpose
/// the demo report keeps the executive view; full details live in
/// the underlying JSON capture.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DivergenceSummary {
    /// Probe family: `headers`, `paths`, `methods`.
    family: String,
    /// Specific probe label within the family.
    label: String,
    /// Probe description (human-readable).
    #[serde(default)]
    description: String,
    /// Baseline HTTP status code.
    baseline_status: u16,
    /// Probe response HTTP status code.
    probe_status: u16,
    /// Body-length delta in percent vs baseline.
    body_delta_pct: f64,
    /// Curl reproducer for this specific probe.
    curl_cmd: String,
    /// Severity guess: `LOW` / `MEDIUM` / `HIGH`.
    severity: String,
}

#[derive(Debug, Default, serde::Serialize)]
struct PhaseScan {
    ran: bool,
    skipped_reason: Option<String>,
    error: Option<String>,
    payload: Option<String>,
    param: Option<String>,
    /// Operator-pasteable re-run command, emitted into the markdown so
    /// the reader can reproduce the inline scan independently. Distinct
    /// from `bypass_variants` below, which carries the actual findings
    /// produced by the inline scan that ran during this `oneshot`.
    raw_text: Option<String>,
    /// Structured fields populated by the inline scan subprocess. All
    /// `Option`s because the scan may have errored, been skipped, or
    /// returned partial output; the markdown renderer guards on
    /// presence before emitting the table.
    waf_name: Option<String>,
    /// `total_variants` from the scan JSON, this is `total_fired`
    /// across ALL scan phases (explore + exploit + multi-vector +
    /// header-obf + intel loop), NOT the initial variant pool size.
    /// Misleading-looking but kept to mirror the scan JSON's
    /// historical field name; the renderer labels it correctly
    /// as "Total requests fired" + adds a separate "Explore pool"
    /// row populated from `explore_variants`.
    total_variants: Option<u64>,
    /// `explore_variants` from the scan JSON, the initial variant
    /// pool size, which `--scan-variants` / `--variants-cap` bounds.
    /// This is the number the operator EXPECTS to see when they
    /// pass `--scan-variants 5`.
    explore_variants: Option<u64>,
    bypassed: Option<u64>,
    blocked: Option<u64>,
    errors: Option<u64>,
    bypass_rate_pct: Option<f64>,
    /// Primary WAF-bypass verdict from scan JSON (`waf_bypass` object).
    waf_bypass_verdict: Option<String>,
    waf_in_play: Option<bool>,
    bypass_confirmed: Option<u64>,
    waf_bypass_headline: Option<String>,
    effective_url: Option<String>,
    effective_param: Option<String>,
    injection_delivery: Option<String>,
    scan_exit_code: Option<i32>,
    elapsed_ms: Option<f64>,
    /// The bypass-variant findings, deserialised verbatim from the
    /// inline scan's JSON output. Empty when the scan ran but found
    /// no bypasses. The renderer treats empty-vs-absent identically.
    bypass_variants: Vec<BypassVariantSummary>,
}

/// One row of the bypass-variants table embedded in the markdown
/// report. Mirrors the shape emitted by `scan` under `--format json`
/// (see `scan/mod.rs` ~line 1897). Kept narrow on purpose: the demo
/// report is the operator-facing summary, not a full scan record
/// extra fields belong in the underlying scan JSON.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct BypassVariantSummary {
    variant: u64,
    payload: String,
    techniques: Vec<String>,
    confidence: f64,
    /// Populated only when the inline scan ran with `--auto-distill`
    /// (which depth does NOT do today, but downstream tooling that
    /// constructs a `OneshotReport` directly may set).
    #[serde(default)]
    minimal_payload: Option<String>,
    /// Operator-pasteable curl reproducer emitted by scan itself.
    /// When present, the markdown renderer prefers this over a
    /// re-synthesised one, keeps the report consistent with what
    /// the scan JSON exports, and preserves repro accuracy for the
    /// raw-runner shape where the reproducer has full
    /// method/header/body context the renderer can't reconstruct.
    #[serde(default)]
    repro_curl: Option<String>,
    /// Distilled-minimum repro_curl, populated when both
    /// `--auto-distill` ran AND the minimum bypass survived.
    #[serde(default)]
    minimal_repro_curl: Option<String>,
}

/// Entry point.
///
/// # Errors
/// Returns a non-zero `ExitCode` only for terminal failures, bad CLI
/// input or an unwritable `--output` path. Per-phase errors are
/// surfaced in the report itself, not propagated as an exit code,
/// because the demo's value is showing **what wafrift saw**, including
/// "we tried this and the target threw a 503."
pub(crate) fn run_oneshot(mut args: OneshotArgs) -> ExitCode {
    args.target = crate::helpers::normalize_target_url(&args.target);
    // R45 6-I1 fix (dogfood pass 6): validate --output's parent
    // directory BEFORE running the 4-phase pipeline. Pre-fix the
    // operator ran ~1.6 s of live probes against the target only
    // to hit "No such file or directory" when the final write
    // happened. Stat the parent up front so the error surfaces
    // before any network I/O.
    if let Some(ref out) = args.output
        && let Some(parent) = out.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        eprintln!(
            "error: --output {} parent directory does not exist. \
             Create it first or pick a different path. Refusing to \
             run the 4-phase pipeline only to fail at the final write.",
            out.display()
        );
        return ExitCode::from(2);
    }
    let start = Instant::now();
    let started_at = unix_now_iso8601();
    let mut report = OneshotReport {
        target: args.target.clone(),
        started_at,
        ..Default::default()
    };

    // Phase 1: detect (baseline GET, fingerprint the WAF).
    eprintln!("{} GET {}", "[1/4] detect:".bright_black(), args.target);
    let (status, headers, body) =
        match fetch_for_detect(&args.target, args.timeout_secs, args.insecure) {
            Ok(v) => v,
            Err(e) => {
                report.detect.error = Some(e.clone());
                eprintln!("       {} {}", "error:".red(), e);
                // Mark downstream phases as not-reached so the renderer
                // surfaces explicit "Not reached, detect phase failed"
                // notes instead of emitting bare section headers with
                // no body. Pre-fix the markdown was a parade of empty
                // section 2/3/4 headers that read like rendering bugs.
                let why = "detect phase failed, phases 2–4 not reached".to_string();
                report.bypass_probe.skipped_reason = Some(why.clone());
                report.scan.skipped_reason = Some(why);
                report.elapsed_ms = start.elapsed().as_millis();
                return emit(report, args).unwrap_or(ExitCode::from(1));
            }
        };
    report.detect.ran = true;
    report.detect.baseline_status = Some(status);
    report.detect.baseline_body_len = Some(body.len());

    let detected = waf_detect::detect(status, &headers, &body);
    for d in &detected {
        report.detect.detected.push(DetectedWaf {
            name: d.name.clone(),
            confidence: d.confidence,
            indicators: d.indicators.clone(),
        });
    }
    if detected.is_empty() {
        eprintln!(
            "       baseline HTTP {status}, {} bytes; no WAF confidently identified",
            body.len()
        );
        // Static-signature corpus came back empty. Auto-run the
        // differential probe, depth is the one-shot demo
        // command, the operator expects it to do the right thing
        // without flags. The differential probe sends an attack-
        // shaped string (per Authorisation note at the bottom of
        // the report), so it's documented and surfaced loudly.
        match fetch_differential(&args.target, args.timeout_secs, args.insecure) {
            Ok(Some(ev)) => {
                eprintln!(
                    "       {} {}",
                    "differential probe: WAF INFERRED".bright_green(),
                    ev.reasons.join("; ").yellow()
                );
                report.detect.differential = Some(format!(
                    "WAF inferred via differential probe: {}",
                    ev.reasons.join("; ")
                ));
            }
            Ok(None) => {
                eprintln!(
                    "       {} differential probe: no significant divergence",
                    "(also)".bright_black()
                );
            }
            Err(e) => {
                eprintln!("       {} differential probe error: {e}", "warn:".yellow());
            }
        }
    } else {
        let summary: Vec<_> = detected
            .iter()
            .map(|d| format!("{} ({:.0}%)", d.name, d.confidence * 100.0))
            .collect();
        eprintln!(
            "       baseline HTTP {status}, {} bytes; WAF(s): {}",
            body.len(),
            summary.join(", ")
        );
    }

    // Phase 2: fingerprint, surface infra markers (CDN, server, etc.)
    eprintln!(
        "{} reading infra markers",
        "[2/4] fingerprint:".bright_black()
    );
    report.fingerprint.ran = true;
    report.fingerprint.markers = infra_markers(&headers);
    if report.fingerprint.markers.is_empty() {
        eprintln!("       no infrastructure markers visible");
    } else {
        eprintln!(
            "       {} marker(s): {}",
            report.fingerprint.markers.len(),
            report
                .fingerprint
                .markers
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    // Phase 3: bypass-probe.
    if args.skip_bypass_probe {
        report.bypass_probe.skipped_reason = Some("--skip-bypass-probe set".into());
        eprintln!(
            "{} skipped (--skip-bypass-probe set)",
            "[3/4] bypass-probe:".bright_black()
        );
    } else {
        eprintln!(
            "{} {AUTH_BYPASS_PROBE_COUNT}+ probe auth/path/method sweep against {}",
            "[3/4] bypass-probe:".bright_black(),
            args.target
        );
        // Capture the JSON output to a tmpfile so the full
        // markdown can embed structured divergences (pre-fix the
        // probe streamed text to the terminal and ONLY the re-run
        // command landed in the markdown, section 3 was unusable
        // as a client deliverable). Same pattern as the scan phase.
        let bp_tmp = crate::helpers::secure_tmp_path("wafrift-oneshot-bp", "json");
        let bp_args = BypassProbeArgs {
            url: args.target.clone(),
            paths_file: args.paths_file.clone(),
            timeout_secs: args.timeout_secs,
            delay_ms: args.delay_ms,
            concurrency: args.concurrency.max(1),
            insecure: args.insecure,
            // JSON + --output for structured capture; bypass-probe
            // still emits per-result text to stderr in this mode so
            // the operator's terminal isn't silent during the sweep.
            format: "json".into(),
            output: Some(bp_tmp.clone()),
            skip_headers: false,
            skip_paths: false,
            skip_methods: false,
            body_diff_threshold_pct: 10.0,
            min_severity: "low".into(),
            // Quiet suppresses the per-probe progress bar, we keep
            // the summary eprintlns that surface "X/N probes diverged"
            // since those are operator-load-bearing.
            quiet: false,
        };
        report.bypass_probe.ran = true;
        report.bypass_probe.raw_text = Some(format!(
            "wafrift bypass-probe {target} \\\n    --format json \\\n    --concurrency 8 \\\n    --delay-ms 25 --output bypass-probe.json",
            target = args.target,
        ));
        match run_bypass_probe(bp_args) {
            Ok(()) => {
                // Drain the captured JSON into structured findings.
                match std::fs::read_to_string(&bp_tmp) {
                    Ok(body) => match serde_json::from_str::<serde_json::Value>(&body) {
                        Ok(v) => apply_bypass_probe_json(&mut report.bypass_probe, &v),
                        Err(e) => {
                            report.bypass_probe.error =
                                Some(format!("parse bypass-probe JSON: {e}"));
                        }
                    },
                    Err(e) => {
                        report.bypass_probe.error = Some(format!(
                            "read bypass-probe JSON from {}: {e}",
                            bp_tmp.display()
                        ));
                    }
                }
            }
            Err(e) => {
                report.bypass_probe.error = Some(e.clone());
                eprintln!("       {} {}", "error:".red(), e);
            }
        }
        let _ = std::fs::remove_file(&bp_tmp);
    }

    // Phase 4: scan (only when --payload was given).
    match (&args.payload, args.skip_scan) {
        (None, _) => {
            report.scan.skipped_reason = Some("no --payload given".into());
            eprintln!(
                "{} skipped (no --payload given)",
                "[4/4] scan:".bright_black()
            );
        }
        (Some(_), true) => {
            report.scan.skipped_reason = Some("--skip-scan set".into());
            eprintln!("{} skipped (--skip-scan set)", "[4/4] scan:".bright_black());
        }
        (Some(payload), false) => {
            report.scan.payload = Some(payload.clone());
            report.scan.param = Some(args.param.clone());
            // Map operator-supplied scan_variants to the closest
            // `--level` setting (light/medium/heavy), AND pass it
            // through as the actual `--variants-cap` so the initial
            // variant pool is bounded. The level mapping still
            // matters because it selects which encoding strategies
            // get tried in the first place; the cap then trims the
            // tail of the resulting pool.
            let level = scan_level_for_variants(args.scan_variants);
            eprintln!(
                "{} firing up to ~{} variants of `{}` at param `{}` (--level {level})",
                "[4/4] scan:".bright_black(),
                args.scan_variants,
                truncate(payload, 40),
                args.param,
            );
            // Inline scan, for-real this time. The previous cut
            // embedded only a copy-paste re-run command and called it
            // a day; the markdown report had zero actual findings,
            // which made the deliverable useless to a client. We now
            // shell out to our own binary (current_exe), drive scan
            // with --format json --output <tmp>, and parse the
            // bypass_variants back into structured fields the
            // markdown renderer emits as a table.
            //
            // Subprocess (rather than calling scan::run_scan
            // directly) for three reasons:
            //   1. scan owns a tokio runtime, gene-bank file locks,
            //      and a learning-cache background task; embedding
            //      it would couple depth to scan's internal
            //      state machine.
            //   2. The CLI surface IS our contract (LAW 2), so
            //      shelling out can't break out from under us
            //      without breaking every other downstream caller.
            //   3. Process isolation: if scan crashes the full
            //      command still produces a partial markdown.
            report.scan.ran = true;
            report.scan.raw_text = Some(format!(
                "wafrift scan --target {target} \\\n    --param {param} \\\n    --payload {payload:?} \\\n    --level {level} \\\n    --delay-ms {delay} \\\n    --format json --output oneshot-scan.json",
                target = args.target,
                param = args.param,
                payload = payload,
                level = level,
                delay = args.delay_ms,
            ));
            // Scale the exploit-chain cap to the scan_variants knob
            // so a "fast demo" invocation doesn't quietly fire
            // hundreds of extra exploit-chain requests via scan's
            // default --exploit-cap 500. The 4× multiplier keeps
            // the exploit chain meaningful (deeper than the explore
            // pool) without ballooning wall-clock against permissive
            // targets. Floor of 10 so scan_variants=1 still has a
            // chance to chain a few bypasses.
            let exploit_cap = (args.scan_variants.saturating_mul(4)).max(10);
            match run_inline_scan(InlineScanArgs {
                target: &args.target,
                payload,
                param: &args.param,
                level,
                delay_ms: args.delay_ms,
                timeout_secs: args.timeout_secs,
                insecure: args.insecure,
                variants_cap: args.scan_variants,
                exploit_cap,
            }) {
                Ok(scan_json) => {
                    report.scan.scan_exit_code = scan_json
                        .get("_oneshot_scan_exit")
                        .and_then(|x| x.as_i64())
                        .map(|c| c as i32);
                    apply_scan_json(&mut report.scan, &scan_json);
                }
                Err(e) => {
                    eprintln!("       {} {}", "error:".red(), e);
                    report.scan.error = Some(e);
                }
            }
        }
    }

    report.elapsed_ms = start.elapsed().as_millis();
    emit(report, args).unwrap_or(ExitCode::from(1))
}

/// Arguments to `run_inline_scan`: kept narrow on purpose. Every
/// field maps 1:1 onto a `wafrift scan` CLI flag so the subprocess
/// invocation is auditable: if the operator can't tell which scan
/// invocation depth fired, the report stops being reproducible.
struct InlineScanArgs<'a> {
    target: &'a str,
    payload: &'a str,
    param: &'a str,
    level: &'static str,
    delay_ms: u64,
    timeout_secs: u64,
    insecure: bool,
    /// Hard cap on the initial variant set, passed through to
    /// `wafrift scan --variants-cap N`. Mirrors
    /// `OneshotArgs::scan_variants` so the operator-facing flag
    /// actually bounds the scan now (it was historically advisory).
    variants_cap: usize,
    /// Cap on the exploit-chain phase fires. Scaled to
    /// `scan_variants` (≈4× the initial pool) so a small
    /// `--scan-variants 5` doesn't quietly fire 500 extra exploit-
    /// chain requests via the scan default, which the dogfood pass
    /// caught producing 200+ second runs against permissive targets
    /// despite the small cap.
    exploit_cap: usize,
}

/// Shell out to `wafrift scan` (via `current_exe`) with `--format
/// json --output <tmp>`, then read + parse the JSON back. Returns the
/// raw `serde_json::Value` so `apply_scan_json` can pluck the fields
/// it needs without forcing every caller to re-define the scan output
/// schema. The tmp file is removed on success AND failure paths so
/// repeated depth runs don't leak files into `$TMPDIR`.
fn run_inline_scan(a: InlineScanArgs<'_>) -> Result<serde_json::Value, String> {
    let exe = std::env::current_exe().map_err(|e| format!("locate own binary: {e}"))?;
    // Unique-per-process tmp path; collisions across concurrent
    // `oneshot` runs on the same host would otherwise corrupt the
    // JSON capture. Nanos guard against the edge case of two PID-1
    // hosts (containers) racing.
    let tmp = crate::helpers::secure_tmp_path("wafrift-oneshot-scan", "json");

    let mut cmd = std::process::Command::new(&exe);
    cmd.arg("scan")
        .arg(a.target)
        .arg("--payload")
        .arg(a.payload)
        .arg("--param")
        .arg(a.param)
        .arg("--level")
        .arg(a.level)
        .arg("--delay-ms")
        .arg(a.delay_ms.to_string())
        .arg("--timeout-secs")
        .arg(a.timeout_secs.to_string())
        .arg("--variants-cap")
        .arg(a.variants_cap.to_string())
        .arg("--exploit-cap")
        .arg(a.exploit_cap.to_string())
        .arg("--format")
        .arg("json")
        .arg("--output")
        .arg(&tmp)
        .arg("--quiet");
    if a.insecure {
        cmd.arg("--insecure");
    }

    let status = cmd.status().map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("spawn `wafrift scan`: {e}")
    })?;
    // Exit 5 = aborted because the target rate-limited us. Treat as
    // recoverable: the JSON file IS still written, so we read it and
    // surface a softer note in the markdown via the scan's own
    // `aborted_rate_limited` field. Anything else non-zero is fatal
    // for this phase.
    let exit_code = status.code().unwrap_or(-1);
    // 0 = bypass confirmed; 4 = WAF in play, none won; 5 = rate-limited partial;
    // 6 = no WAF on surface; 7 = timeout partial (all still emit JSON).
    if !status.success() && !matches!(exit_code, 4..=7) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!(
            "`wafrift scan` exited with status {exit_code} (no JSON captured)"
        ));
    }

    let body = std::fs::read_to_string(&tmp)
        .map_err(|e| format!("read scan JSON from {}: {e}", tmp.display()))?;
    let _ = std::fs::remove_file(&tmp);
    let mut v: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("parse scan JSON: {e}"))?;
    if let Some(obj) = v.as_object_mut() {
        obj.insert("_oneshot_scan_exit".into(), serde_json::json!(exit_code));
    }
    Ok(v)
}

/// Drain a scan JSON envelope (the shape emitted by `scan/mod.rs`
/// when `--format json` is set) into the full report's
/// `PhaseScan`. Tolerant of missing fields, the operator may run
/// depth against a future scan binary that adds fields, or a past
/// one that doesn't yet emit them; either way the report renders.
///
/// Handles both shapes scan emits:
///   - bare scan object (default `--format json`)
///   - `{"layer_report": {...}, "scan": {...}}` (with `--report-layers`)
///
/// The unwrap mirrors `report::ingest_scan_json` so a single change
/// to the scan shape doesn't have to be propagated to two readers.
fn apply_scan_json(phase: &mut PhaseScan, root: &serde_json::Value) {
    let v = root.get("scan").filter(|s| s.is_object()).unwrap_or(root);
    phase.waf_name = v.get("waf").and_then(|x| x.as_str()).map(str::to_string);
    phase.total_variants = v.get("total_variants").and_then(|x| x.as_u64());
    phase.explore_variants = v.get("explore_variants").and_then(|x| x.as_u64());
    phase.bypassed = v.get("bypassed").and_then(|x| x.as_u64());
    phase.blocked = v.get("blocked").and_then(|x| x.as_u64());
    phase.errors = v.get("errors").and_then(|x| x.as_u64());
    phase.bypass_rate_pct = v
        .get("bypass_rate_pct")
        .and_then(|x| if x.is_null() { None } else { x.as_f64() });
    phase.elapsed_ms = v.get("elapsed_ms").and_then(|x| x.as_f64());
    phase.injection_delivery = v
        .get("injection_delivery")
        .and_then(|x| x.as_str())
        .map(str::to_string);
    phase.effective_url = v
        .get("effective_url")
        .and_then(|x| x.as_str())
        .map(str::to_string);
    phase.effective_param = v
        .get("effective_param")
        .and_then(|x| x.as_str())
        .map(str::to_string);
    if let Some(wb) = v.get("waf_bypass") {
        phase.waf_bypass_verdict = wb
            .get("verdict")
            .and_then(|x| x.as_str())
            .map(str::to_string);
        phase.waf_in_play = wb.get("waf_in_play").and_then(|x| x.as_bool());
        phase.bypass_confirmed = wb.get("bypass_confirmed").and_then(|x| x.as_u64());
        phase.waf_bypass_headline = wb
            .get("headline")
            .and_then(|x| x.as_str())
            .map(str::to_string);
    }
    if let Some(arr) = v.get("bypass_variants").and_then(|x| x.as_array()) {
        phase.bypass_variants = arr
            .iter()
            .filter_map(|row| serde_json::from_value::<BypassVariantSummary>(row.clone()).ok())
            .collect();
    }
}

/// Drain a bypass-probe JSON envelope (the shape emitted by
/// `bypass_probe.rs` under `--format json`) into the full
/// report's `PhaseBypassProbe`. The JSON has shape
/// `{"results": [{"target":..., "divergences":[...], ...}]}`
/// we flatten across URL results so the renderer sees a single
/// divergence list. Tolerant of missing fields, same as the scan
/// drain.
fn apply_bypass_probe_json(phase: &mut PhaseBypassProbe, root: &serde_json::Value) {
    let mut total_probes: u64 = 0;
    let mut all_divergences: Vec<DivergenceSummary> = Vec::new();
    if let Some(results) = root.get("results").and_then(|x| x.as_array()) {
        for r in results {
            if let Some(p) = r.get("probes_fired").and_then(|x| x.as_u64()) {
                total_probes = total_probes.saturating_add(p);
            }
            if let Some(divs) = r.get("divergences").and_then(|x| x.as_array()) {
                for d in divs {
                    if let Ok(summary) = serde_json::from_value::<DivergenceSummary>(d.clone()) {
                        all_divergences.push(summary);
                    }
                }
            }
        }
    }
    phase.total_probes = (total_probes > 0).then_some(total_probes);
    phase.total_divergences = Some(all_divergences.len() as u64);
    phase.divergences = all_divergences;
}

/// Map operator-supplied `--scan-variants N` onto the closest
/// `--level` setting. Honest about being approximate (scan derives
/// variant count from `--level` × tamper set, with no operator cap).
/// Thresholds chosen to keep the historical default `--scan-variants
/// 30` → `--level heavy` mapping byte-for-byte while making smaller
/// values yield smaller campaigns.
fn scan_level_for_variants(n: usize) -> &'static str {
    if n <= 15 {
        "light"
    } else if n <= 25 {
        "medium"
    } else {
        "heavy"
    }
}

/// Pick a renderer based on `--format` and write to stdout + optional
/// `--output`. Returns the process exit code: 0 on success, 1 if the
/// output file could not be written.
fn emit(report: OneshotReport, args: OneshotArgs) -> Result<ExitCode, ExitCode> {
    let rendered = match args.format.as_str() {
        "json" => serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string()),
        "text" => render_text(&report),
        _ => render_markdown(&report),
    };
    println!("{rendered}");
    if let Some(path) = &args.output {
        std::fs::write(path, &rendered).map_err(|e| {
            eprintln!("{} write {}: {e}", "error:".red(), path.display());
            ExitCode::from(1)
        })?;
        eprintln!("{} {}", "wrote".bright_black(), path.display());
    }
    Ok(ExitCode::SUCCESS)
}

/// One-paragraph executive verdict embedded near the top of the
/// depth markdown. Reads off the per-phase counters and renders
/// a single skimmable sentence per axis (detection / bypass-probe /
/// scan). Pure, no side effects, no I/O, so the renderer stays
/// deterministic across runs and the rendering is easy to unit-test.
fn render_verdict_paragraph(r: &OneshotReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();

    // Detection axis.
    if let Some(diff) = r.detect.differential.as_ref() {
        let _ = write!(
            out,
            "**WAF detection:** present (differential-probe verdict; vendor not pinned. _{diff}_)\n\n"
        );
    } else if !r.detect.detected.is_empty() {
        let names: Vec<String> = r
            .detect
            .detected
            .iter()
            .map(|d| format!("{} ({:.0}%)", d.name, d.confidence * 100.0))
            .collect();
        let _ = write!(out, "**WAF detection:** {}\n\n", names.join(", "));
    } else if r.detect.error.is_some() {
        let _ = write!(out, "**WAF detection:** _phase errored_\n\n");
    } else if r.detect.ran {
        let _ = write!(
            out,
            "**WAF detection:** no WAF identified (origin appears direct)\n\n"
        );
    }

    // Bypass-probe axis.
    if r.bypass_probe.skipped_reason.is_some() {
        let _ = write!(out, "**Auth / path / method probe:** skipped\n\n");
    } else if r.bypass_probe.error.is_some() {
        let _ = write!(out, "**Auth / path / method probe:** _phase errored_\n\n");
    } else if r.bypass_probe.ran {
        let probes = r.bypass_probe.total_probes.unwrap_or(0);
        let divs = r.bypass_probe.total_divergences.unwrap_or(0);
        if divs == 0 {
            let _ = write!(
                out,
                "**Auth / path / method probe:** {probes} probes fired, no divergences from baseline\n\n"
            );
        } else {
            let highs = r
                .bypass_probe
                .divergences
                .iter()
                .filter(|d| d.severity.eq_ignore_ascii_case("HIGH"))
                .count();
            if highs > 0 {
                let _ = write!(
                    out,
                    "**Auth / path / method probe:** {probes} probes fired, **{divs} divergences** ({highs} HIGH severity, see section 3)\n\n"
                );
            } else {
                let _ = write!(
                    out,
                    "**Auth / path / method probe:** {probes} probes fired, **{divs} divergences** (see section 3)\n\n"
                );
            }
        }
    }

    // Scan axis.
    if r.scan.skipped_reason.is_some() {
        let _ = write!(
            out,
            "**Payload mutation scan:** skipped (pass `--payload` to run)\n\n"
        );
    } else if r.scan.error.is_some() {
        let _ = write!(out, "**Payload mutation scan:** _phase errored_\n\n");
    } else if r.scan.ran {
        if let Some(ref headline) = r.scan.waf_bypass_headline {
            let _ = write!(out, "**WAF evasion scan:** {headline}\n\n");
        } else {
            let bypassed = r.scan.bypassed.unwrap_or(0);
            let total = r.scan.total_variants.unwrap_or(0);
            if bypassed == 0 {
                let _ = write!(
                    out,
                    "**Payload mutation scan:** {total} variants fired, **0 bypasses** (WAF held)\n\n"
                );
            } else if let Some(rate) = r.scan.bypass_rate_pct {
                let _ = write!(
                    out,
                    "**Payload mutation scan:** {total} variants fired, **{bypassed} bypassed** ({rate:.1}%; see section 4)\n\n"
                );
            } else {
                let _ = write!(
                    out,
                    "**Payload mutation scan:** {total} variants fired, **{bypassed} bypassed** (see section 4)\n\n"
                );
            }
        }
    }

    // Trim trailing whitespace so the caller controls the final
    // newlines exactly (avoids double-blank lines in the markdown).
    out.trim_end().to_string()
}

fn render_markdown(r: &OneshotReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("# wafrift oneshot: {}\n\n", r.target));
    out.push_str(&format!(
        "Generated {} ({} ms wall-clock).\n\n",
        r.started_at, r.elapsed_ms
    ));

    // Executive verdict, one paragraph the reader can skim in 5
    // seconds. Surfaces the only three numbers that matter:
    //   - which WAF (if any)
    //   - how many bypass payloads found (scan phase)
    //   - how many auth/path/method probes diverged (bypass-probe)
    // Everything else is the per-phase deep-dive below.
    out.push_str("## Verdict at a glance\n\n");
    out.push_str(&render_verdict_paragraph(r));
    out.push_str("\n\n");

    // Detect.
    out.push_str("## 1. WAF detection\n\n");
    if let Some(err) = &r.detect.error {
        out.push_str(&format!(
            "Detection phase **errored**: `{err}`. The rest of the\n\
             report is partial, re-run after the target is reachable.\n\n"
        ));
    } else if r.detect.ran {
        out.push_str(&format!(
            "- Baseline: HTTP `{}` ({} bytes)\n",
            r.detect.baseline_status.unwrap_or(0),
            r.detect.baseline_body_len.unwrap_or(0)
        ));
        if r.detect.detected.is_empty() {
            // Two cases:
            //   1. Static rule corpus AND differential probe both
            //      empty → really nothing in front of the origin.
            //   2. Static rule corpus empty BUT differential probe
            //      fired → a WAF IS present, it just strips its
            //      vendor markers. Pre-fix the report opened with
            //      "**none confidently identified**" then immediately
            //      followed with the differential verdict, internally
            //      contradictory ("none" vs "is intercepting"). Lead
            //      with the differential verdict when we have one;
            //      fall back to the "nothing detected" line otherwise.
            if let Some(diff) = r.detect.differential.as_ref() {
                out.push_str(&format!(
                    "- **WAF inferred via differential probe**: {diff}\n"
                ));
                out.push_str("  Static-signature corpus did not match a named vendor, the WAF is intercepting attack-shaped requests via a generic block page that strips its own marker headers. Treat the verdict as 'protected'; the specific vendor is not pinned.\n\n");
            } else {
                out.push_str("- WAF: **none confidently identified** at the baseline. The target may be unprotected, behind a CDN that's not surfacing rule fires on benign GETs, or fingerprinted via response signals our 160+ rule corpus doesn't cover. The bypass-probe phase below still runs.\n\n");
            }
        } else {
            out.push_str("- WAF candidate(s):\n");
            for d in &r.detect.detected {
                out.push_str(&format!(
                    "  - **{}** ({}% confidence), indicators: {}\n",
                    d.name,
                    (d.confidence * 100.0).round() as u32,
                    d.indicators.join(", ")
                ));
            }
            out.push('\n');
        }
    }

    // Fingerprint.
    out.push_str("## 2. Infrastructure fingerprint\n\n");
    if !r.fingerprint.ran {
        // Phase never ran (typically because detect errored before
        // reaching it). Pre-fix the markdown said "No CDN / server
        // / cache markers surfaced…" which falsely implied a
        // connection was made (confusing on a dead-target report).
        if r.detect.error.is_some() {
            out.push_str("Not reached, detect phase failed.\n\n");
        } else {
            out.push_str("Not reached.\n\n");
        }
    } else if r.fingerprint.markers.is_empty() {
        out.push_str("No CDN / server / cache markers surfaced on the baseline response. The origin may be direct, or the markers may be stripped at the edge.\n\n");
    } else {
        out.push_str("| header | value |\n|---|---|\n");
        for (k, v) in &r.fingerprint.markers {
            out.push_str(&format!("| `{k}` | `{}` |\n", v.replace('|', "\\|")));
        }
        out.push('\n');
    }

    // Bypass-probe.
    out.push_str("## 3. Bypass probe (auth headers + path routing + method overrides)\n\n");
    if let Some(reason) = &r.bypass_probe.skipped_reason {
        out.push_str(&format!("Skipped: _{reason}_.\n\n"));
    } else if let Some(err) = &r.bypass_probe.error {
        out.push_str(&format!("Errored: `{err}`.\n\n"));
        if let Some(cmd) = &r.bypass_probe.raw_text {
            out.push_str(&format!("Reproduce / debug:\n\n```bash\n{cmd}\n```\n\n"));
        }
    } else if r.bypass_probe.ran {
        out.push_str(&format!(
            "Fires the full {AUTH_BYPASS_PROBE_COUNT}-probe auth-bypass set + path-routing-disagreement variants + 7 HTTP method overrides against the target, classifying each response vs the baseline.\n\n"
        ));

        // Summary counters.
        let any_counter =
            r.bypass_probe.total_probes.is_some() || r.bypass_probe.total_divergences.is_some();
        if any_counter {
            out.push_str("### Probe summary\n\n");
            out.push_str("| metric | value |\n|---|---|\n");
            if let Some(p) = r.bypass_probe.total_probes {
                out.push_str(&format!("| Probes fired | {p} |\n"));
            }
            if let Some(d) = r.bypass_probe.total_divergences {
                out.push_str(&format!("| Divergences | **{d}** |\n"));
            }
            out.push('\n');
        }

        // Concrete divergences, same render-cap pattern as scan
        // section 4. Operators raising the body-diff threshold (or
        // scanning a permissive target) can see hundreds; render
        // the strongest 25 and footer the rest.
        if r.bypass_probe.divergences.is_empty() {
            out.push_str(
                "No probes diverged from the baseline. The target's \
                 auth/path/method axes appear consistent, re-run with \
                 `--body-diff-threshold-pct 5` for a tighter sweep, or \
                 try the scan phase below to attack the payload axis.\n\n",
            );
        } else {
            // R49 (pass-11 I2, CLAUDE.md §7 DEDUPLICATION): inherits
            // from module-scope RENDER_CAP so the two render blocks
            // stay in lockstep without per-block redefinition.
            let total = r.bypass_probe.divergences.len();
            let shown = total.min(RENDER_CAP);
            out.push_str(&format!(
                "### Probe divergences ({} finding{})\n\n",
                total,
                if total == 1 { "" } else { "s" }
            ));
            if total > RENDER_CAP {
                out.push_str(&format!(
                    "_Showing top {shown} of {total} (ordered by scan output). \
                     Full set available in the JSON capture via the re-run \
                     command at the bottom of this section._\n\n"
                ));
            }
            // Group HIGH severity first, then MEDIUM, then LOW
            // pentest deliverable readers want the alarming findings
            // up top.
            let mut ranked: Vec<&DivergenceSummary> = r.bypass_probe.divergences.iter().collect();
            ranked.sort_by_key(|d| match d.severity.to_uppercase().as_str() {
                "HIGH" => 0,
                "MEDIUM" => 1,
                _ => 2,
            });
            for d in ranked.iter().take(RENDER_CAP) {
                out.push_str(&format!(
                    "#### `{}/{}` · severity {}\n\n",
                    d.family, d.label, d.severity
                ));
                if !d.description.is_empty() {
                    out.push_str(&format!("{}\n\n", d.description));
                }
                out.push_str(&format!(
                    "- Baseline HTTP {} → probe HTTP {} (body Δ {:.1}%)\n",
                    d.baseline_status, d.probe_status, d.body_delta_pct
                ));
                out.push_str(&format!(
                    "- **Reproduce:**\n\n```bash\n{}\n```\n\n",
                    d.curl_cmd
                ));
            }
        }

        // Footer with re-run command so operators can capture the
        // full JSON for their pentest report.
        if let Some(cmd) = &r.bypass_probe.raw_text {
            out.push_str("### Reproduce the inline sweep\n\n");
            out.push_str(&format!("```bash\n{cmd}\n```\n\n"));
        }
    }

    // Scan.
    out.push_str("## 4. Live scan (payload mutation)\n\n");
    if let Some(reason) = &r.scan.skipped_reason {
        out.push_str(&format!("Skipped: _{reason}_.\n\n"));
    } else if let Some(err) = &r.scan.error {
        out.push_str(&format!(
            "The inline scan errored: `{err}`. Re-run the scan command below \
             to surface the underlying failure.\n\n"
        ));
        if let Some(cmd) = &r.scan.raw_text {
            out.push_str(&format!("```bash\n{cmd}\n```\n\n"));
        }
    } else if r.scan.ran {
        out.push_str(
            "Mutation variants of the payload are fired at the target, classified by the multi-signal oracle (block / bypass / challenge / rate-limit), with server `Retry-After` honoured via jittered backoff.\n\n",
        );

        // Headline counters, emit the table only when AT LEAST
        // one counter is present. A scan binary that drained empty
        // (e.g. partial-output mid-crash) shouldn't render a
        // header-only table that reads as a bug; instead, the
        // section flows straight into the per-variant findings (or
        // the no-bypasses note).
        let any_counter = r.scan.waf_name.is_some()
            || r.scan.total_variants.is_some()
            || r.scan.explore_variants.is_some()
            || r.scan.bypassed.is_some()
            || r.scan.blocked.is_some()
            || r.scan.errors.is_some()
            || r.scan.bypass_rate_pct.is_some()
            || r.scan.elapsed_ms.is_some();
        if any_counter {
            out.push_str("### Scan summary\n\n");
            out.push_str("| metric | value |\n|---|---|\n");
            if let Some(w) = &r.scan.waf_name {
                out.push_str(&format!("| WAF (chosen) | `{w}` |\n"));
            }
            // The explore pool is the number the operator set via
            // `--scan-variants` (mapped to `--variants-cap`); call
            // it out FIRST so the reader sees the cap honoured. The
            // separate "Total requests fired" row below covers the
            // (much larger) sum across all scan phases, pre-fix
            // these two were collapsed into one mislabelled row
            // saying "Variants fired" but showing the post-phase
            // total, contradicting `--scan-variants N`.
            if let Some(e) = r.scan.explore_variants {
                out.push_str(&format!(
                    "| Explore pool (variants tried initially) | {e} |\n"
                ));
            }
            if let Some(t) = r.scan.total_variants {
                out.push_str(&format!(
                    "| Total requests fired (across all phases) | {t} |\n"
                ));
            }
            if let Some(b) = r.scan.bypassed {
                out.push_str(&format!("| Bypassed | **{b}** |\n"));
            }
            if let Some(b) = r.scan.blocked {
                out.push_str(&format!("| Blocked | {b} |\n"));
            }
            if let Some(e) = r.scan.errors {
                out.push_str(&format!("| Errors | {e} |\n"));
            }
            if let Some(rate) = r.scan.bypass_rate_pct {
                out.push_str(&format!("| Bypass rate | {rate:.1}% |\n"));
            }
            if let Some(ms) = r.scan.elapsed_ms {
                out.push_str(&format!("| Wall-clock | {:.1}s |\n", ms / 1000.0));
            }
            out.push('\n');
        }

        // Per-variant payload table, the actual deliverable. When
        // there are no bypasses, name that too (the absence of a
        // table would otherwise read as "scan never ran").
        if r.scan.bypass_variants.is_empty() {
            out.push_str(
                "No variants bypassed the WAF in this run. The target held against \
                 every encoding × tamper × grammar mutation in the `--level` \
                 envelope. Two follow-ups worth considering before declaring victory:\n\n\
                 - Raise `--scan-variants` (currently maps to a `--level` setting; \
                   try a wider sweep).\n\
                 - Run `wafrift bypass-probe` (Section 3 above) to attack the \
                   auth/path/method axis, which is orthogonal to payload mutation.\n\n",
            );
        } else {
            // Render cap: at -scan-variants 30 the bypass set is
            // bounded to ~30, but operators raising the cap (or
            // running against a permissive target) can wind up with
            // hundreds of "successful" bypasses, rendering all of
            // them turns the report into a 10000-line wall that
            // nobody reads. Cap the rendered table at 25 and add a
            // footer pointing at the JSON output for the full list.
            // R49 (pass-11 I2, CLAUDE.md §7 DEDUPLICATION): inherits
            // from module-scope RENDER_CAP so the two render blocks
            // stay in lockstep without per-block redefinition.
            let total = r.scan.bypass_variants.len();
            let shown = total.min(RENDER_CAP);
            out.push_str(&format!(
                "### Successful bypasses ({} variant{})\n\n",
                total,
                if total == 1 { "" } else { "s" }
            ));
            if total > RENDER_CAP {
                out.push_str(&format!(
                    "_Showing top {shown} of {total} (ordered by scan output). \
                     Full set available in the JSON output via the re-run \
                     command at the bottom of this section._\n\n"
                ));
            }
            for v in r.scan.bypass_variants.iter().take(RENDER_CAP) {
                out.push_str(&format!(
                    "#### Variant #{} · confidence {:.2}\n\n",
                    v.variant, v.confidence
                ));
                out.push_str(&format!(
                    "- **Techniques:** {}\n",
                    if v.techniques.is_empty() {
                        "_(none recorded)_".to_string()
                    } else {
                        v.techniques
                            .iter()
                            .map(|t| format!("`{t}`"))
                            .collect::<Vec<_>>()
                            .join(" → ")
                    }
                ));
                out.push_str(&format!(
                    "- **Payload** ({} bytes):\n\n```\n{}\n```\n",
                    v.payload.len(),
                    fence_escape(&v.payload)
                ));
                if let Some(min) = &v.minimal_payload {
                    out.push_str(&format!(
                        "- **Minimal payload** ({} bytes, via auto-distill):\n\n```\n{}\n```\n",
                        min.len(),
                        fence_escape(min)
                    ));
                }
                // Prefer the scan-supplied repro_curl when present
                // (it's wire-accurate for the raw-runner shape that
                // depth can't reconstruct from target+param);
                // fall back to URL-query synthesis otherwise. Both
                // paths route through `shell_single_quote` so the
                // escape is consistent.
                let repro = v.repro_curl.clone().unwrap_or_else(|| {
                    let param = r.scan.param.as_deref().unwrap_or("q");
                    format!(
                        "curl -G --data-urlencode {param}={shell} {target}",
                        shell = shell_single_quote(&v.payload),
                        target = shell_single_quote(&r.target),
                    )
                });
                out.push_str(&format!("- **Reproduce:**\n\n```bash\n{repro}\n```\n\n"));
                if let Some(min_repro) = &v.minimal_repro_curl {
                    out.push_str(&format!(
                        "- **Reproduce (minimum):**\n\n```bash\n{min_repro}\n```\n\n"
                    ));
                }
            }
        }

        // Always footer the section with the re-run command so the
        // operator can reproduce the inline scan independently.
        if let Some(cmd) = &r.scan.raw_text {
            out.push_str("### Reproduce the inline scan\n\n");
            out.push_str(&format!("```bash\n{cmd}\n```\n\n"));
        }
    }

    // Footer.
    out.push_str("## Reproduce this whole report\n\n");
    out.push_str("```bash\n");
    out.push_str(&format!(
        "wafrift oneshot {target}{payload}{paths_file} --output depth-report.md\n",
        target = r.target,
        payload = r
            .scan
            .payload
            .as_ref()
            .map(|p| format!(
                " --payload {:?} --param {}",
                p,
                r.scan.param.as_deref().unwrap_or("q")
            ))
            .unwrap_or_default(),
        paths_file = "", // paths_file isn't echoed; user has the file
    ));
    out.push_str("```\n\n");
    out.push_str(
        "**Authorisation**: wafrift only runs against systems you own \
         or have written authorisation to test. The bypass-probe and \
         scan phases above send genuinely exploitable strings; verify \
         scope before each engagement.\n",
    );
    out
}

fn render_text(r: &OneshotReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("=== wafrift oneshot: {} ===\n", r.target));
    out.push_str(&format!(
        "elapsed: {} ms · started: {}\n\n",
        r.elapsed_ms, r.started_at
    ));
    if let Some(s) = r.detect.baseline_status {
        out.push_str(&format!(
            "[1/4] detect: HTTP {s} ({} bytes); {} WAF candidate(s)\n",
            r.detect.baseline_body_len.unwrap_or(0),
            r.detect.detected.len()
        ));
        for d in &r.detect.detected {
            out.push_str(&format!(
                "      - {} ({}%)\n",
                d.name,
                (d.confidence * 100.0).round() as u32
            ));
        }
    } else if let Some(e) = &r.detect.error {
        out.push_str(&format!("[1/4] detect: ERROR {e}\n"));
    }
    out.push_str(&format!(
        "[2/4] fingerprint: {} infra marker(s)\n",
        r.fingerprint.markers.len()
    ));
    match (&r.bypass_probe.skipped_reason, &r.bypass_probe.error) {
        (Some(why), _) => out.push_str(&format!("[3/4] bypass-probe: skipped ({why})\n")),
        (_, Some(e)) => out.push_str(&format!("[3/4] bypass-probe: ERROR {e}\n")),
        _ => out.push_str("[3/4] bypass-probe: see stream above\n"),
    }
    match (&r.scan.skipped_reason, &r.scan.error, &r.scan.raw_text) {
        (Some(why), _, _) => out.push_str(&format!("[4/4] scan: skipped ({why})\n")),
        (_, Some(e), _) => out.push_str(&format!("[4/4] scan: ERROR {e}\n")),
        (_, _, Some(_)) => out.push_str("[4/4] scan: invocation embedded in markdown report\n"),
        _ => {}
    }
    out
}

/// A bypass payload that contains literal triple-backticks would
/// break the markdown code fence around it. The standard escape is
/// to wrap the fence in MORE backticks than the payload contains
/// computing the right delimiter is fiddly, so we take the simpler
/// path of inserting a zero-width space into the literal sequence
/// (the rendered text reads identically, but the fence parser no
/// longer terminates early). Idempotent: payloads without ``` are
/// returned unchanged.
fn fence_escape(s: &str) -> String {
    if s.contains("```") {
        s.replace("```", "`\u{200B}`\u{200B}`")
    } else {
        s.to_string()
    }
}

/// Delegates to the workspace-canonical [`crate::probe_classify::truncate`]
/// (byte-cap + char-boundary walk). Pre-consolidation this used a
/// char-count variant that could exceed the byte budget for multi-byte
/// code points; the byte-cap form is strictly tighter.
fn truncate(s: &str, n: usize) -> String {
    crate::probe_classify::truncate(s, n)
}

fn unix_now_iso8601() -> String {
    // Avoids pulling chrono just to format one timestamp. ISO-8601
    // basic form: YYYY-MM-DDTHH:MM:SSZ. Computed from SystemTime so it
    // works on hosts where the wall clock has been set sanely.
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Civil-date conversion (Howard Hinnant's algorithm, public domain).
    let (year, month, day) = civil_from_days(days as i64);
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    (year as i32, m as u32, d as u32)
}

#[cfg(test)]
#[path = "oneshot_tests.rs"]
mod tests;
