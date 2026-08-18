//! `wafrift hunt`: long-running autonomous bypass campaign.
//!
//! Repeatedly runs `bench-waf --evade` rounds against a target, rotating
//! mutators/strategies each round. Every confirmed bypass is saved to a
//! campaign JSON file at `~/.wafrift/hunt-<campaign-id>.json`. The campaign
//! survives Ctrl-C and can be resumed by re-running with the same
//! `--campaign-id`.
//!
//! ## Scheduling
//!
//! Tokio drives the outer scheduling loop. A round starts every
//! `--interval-secs` seconds (wall time); if a round takes longer than the
//! interval the next round starts immediately. The loop exits when:
//!
//! - `--max-duration-secs` wall time has elapsed, OR
//! - Ctrl-C is received (graceful, finishes the current in-flight round
//!   before persisting and exiting).
//!
//! ## Bypass corpus (consumed by `wafrift harvest`)
//!
//! Every round runs `bench-waf` with a per-target `--corpus-out` under
//! `~/.wafrift`, so a campaign accumulates the concrete winning payload +
//! response evidence for each confirmed bypass. `wafrift harvest` later
//! reads that corpus, re-verifies each candidate live, and writes
//! review-ready reports. `hunt` itself NEVER submits anything, filing is
//! a deliberate, one-at-a-time manual step via `wafrift submit`. (Auto-
//! submitting machine-generated reports at a bounty program is a ban risk,
//! so wafrift has no automatic or batch submission path.)
//!
//! ## CumulusFire preset (--target cumulusfire)
//!
//! Pre-fills `--base-url` with the CumulusFire testing endpoint and sets
//! the `--i-have-permission` reason to the pre-registered CF scope
//! identifier. Then `wafrift harvest --target cumulusfire` turns the
//! accumulated corpus into review-ready bounty reports.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use clap::Args;
use colored::Colorize;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use wafrift_strategy::drift_window::{BypassRateMonitor, ChangePointEvent};

// ─── Preset ──────────────────────────────────────────────────────────────────

/// Known target presets.
const CUMULUSFIRE_BASE_URL: &str = "https://waf.cumulusfire.net";
const CUMULUSFIRE_PERMISSION: &str =
    "CumulusFire public bug bounty scope, wafrift hunt --target cumulusfire";

/// Hunt round writes a `bench-waf --output` JSON to a tmp file then
/// reads it back. Even though the path is owned by wafrift, a tmpdir
/// race (other process replacing the tmp inode with a multi-GB
/// symlink between `run_bench_waf` returning and the read) can OOM
/// the process. 64 MiB matches bench-diff: enough for 10k+ cases,
/// not enough to OOM.
const HUNT_BENCH_OUTPUT_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Campaign state JSON in `~/.wafrift/hunt-<id>.json` is small (a
/// list of round counts + bypass list). 16 MiB catches any
/// runaway-write accident and hostile symlinks pointed at
/// arbitrary files.
const HUNT_CAMPAIGN_STATE_MAX_BYTES: usize = 16 * 1024 * 1024;

// ─── Campaign state ──────────────────────────────────────────────────────────

/// A single confirmed bypass recorded by the campaign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CampaignBypass {
    /// Wall-clock timestamp (Unix seconds) when the bypass was confirmed.
    pub discovered_at: u64,
    /// Round index in which this bypass was found.
    pub round: u64,
    /// Attack class (e.g. `sql`, `xss`).
    pub class: String,
    /// Bypass technique signature.
    pub technique: String,
    /// True if this bypass was submitted (or queued for submission) to H1.
    pub submitted: bool,
}

/// A change-point event detected by the CUSUM bypass-rate monitor (C-11).
///
/// Recorded when the online CUSUM detector fires, indicating a statistically
/// significant drop in bypass rate, likely caused by a WAF vendor rule update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ChangePointMarker {
    /// Wall-clock timestamp (Unix seconds) when the alarm fired.
    pub detected_at: u64,
    /// Round in which the alarm fired.
    pub round: u64,
    /// Windowed bypass rate at alarm time (fraction in `[0.0, 1.0]`).
    pub observed_rate: f64,
    /// Baseline bypass rate just before the alarm (fraction in `[0.0, 1.0]`).
    pub baseline_rate: f64,
    /// Absolute drop expressed in percentage points.
    pub drop_pp: f64,
}

/// Persisted campaign state.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct CampaignState {
    /// Stable campaign identifier (matches the filename stem).
    pub campaign_id: String,
    /// Target base URL.
    pub target_url: String,
    /// Wall-clock timestamp (Unix seconds) when the campaign started.
    pub started_at: u64,
    /// Total rounds completed.
    pub rounds_completed: u64,
    /// Total bypasses confirmed.
    pub total_bypasses: u64,
    /// Schema version for forward compat.
    pub schema_version: u32,
    /// All confirmed bypasses.
    pub bypasses: Vec<CampaignBypass>,
    /// Change-point events detected by the CUSUM bypass-rate monitor.
    /// Empty in campaigns run without `--change-point-alarm`.
    /// Added in schema_version 2; defaults to empty for v1 state files.
    #[serde(default)]
    pub change_points: Vec<ChangePointMarker>,
}

impl CampaignState {
    /// Schema version 2 adds `change_points` (C-11 CUSUM alarm log).
    /// v1 state files load cleanly via `#[serde(default)]` on the field.
    pub const SCHEMA_VERSION: u32 = 2;
}

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Args, Debug)]
pub(crate) struct HuntArgs {
    /// Base URL of the WAF target. Overridden by `--target cumulusfire`.
    #[arg(long)]
    pub base_url: Option<String>,

    /// Named target preset. Currently only `cumulusfire` is defined.
    /// Pre-fills `--base-url` and `--i-have-permission`.
    #[arg(long, value_name = "PRESET", value_parser = ["cumulusfire"])]
    pub target: Option<String>,

    /// Corpus directory (TOML files). Passed through to each bench-waf round.
    #[arg(long, default_value = "wafrift-bench/corpus")]
    pub corpus: PathBuf,

    /// Attack classes to include. Comma-separated. Default: all.
    #[arg(long, value_delimiter = ',')]
    pub class: Vec<String>,

    /// Evasion strategies, comma-separated.
    /// Default: `heavy,equiv-cegis` (same default as bench-waf).
    #[arg(long, value_delimiter = ',', default_value = "heavy,equiv-cegis")]
    pub strategies: Vec<String>,

    /// Known WAF class of the target (e.g. "Cloudflare Bot Management",
    /// "AWS Bot Control"). When it names an ML-backed WAF, the campaign
    /// adds the `ml-evasion` decision-boundary strategy to its rotation and
    /// passes the name through to each bench round. Omit for rule-based
    /// targets: `ml-evasion` would be a no-op there.
    #[arg(long)]
    pub waf_name: Option<String>,

    /// Variants per corpus case per strategy per round.
    #[arg(long, default_value_t = 5)]
    pub variants: usize,

    /// Inter-round interval (seconds). The next round starts this many
    /// seconds after the previous round BEGINS. If a round takes longer
    /// than the interval, the next round starts immediately (no backlog).
    #[arg(long, default_value_t = 60)]
    pub interval_secs: u64,

    /// Maximum campaign wall-clock duration (seconds). 0 = run forever
    /// until Ctrl-C. Default 0.
    #[arg(long, default_value_t = 0)]
    pub max_duration_secs: u64,

    /// Per-round variant budget (max variants to try across all cases in
    /// one round before stopping early). 0 = unlimited. Default 0.
    #[arg(long, default_value_t = 0)]
    pub round_budget: usize,

    /// Stable campaign identifier, used as the output filename stem
    /// (`~/.wafrift/hunt-<id>.json`). If a file for this id already
    /// exists, the campaign is resumed from where it left off.
    /// Default: a UUID generated from the current timestamp.
    #[arg(long)]
    pub campaign_id: Option<String>,

    /// Authorization statement for non-allowlisted targets. Required for
    /// any target outside localhost / RFC1918 / wafrift's built-in list
    /// (unless `--target cumulusfire` is used, which has a built-in reason).
    #[arg(long, value_name = "REASON")]
    pub i_have_permission: Option<String>,

    /// Delay between requests inside each round (ms).
    #[arg(long, default_value_t = 0)]
    pub delay_ms: u64,

    /// Enable CUSUM bypass-rate change-point alarm (C-11).
    ///
    /// When set, the campaign monitors the bypass rate online and emits a
    /// warning to stderr when a statistically significant drop is detected
    /// (indicating a likely WAF rule update). The alarm is also recorded in
    /// the campaign state file under `change_points`.
    #[arg(long, default_value_t = false)]
    pub change_point_alarm: bool,

    /// Sliding window size for the bypass-rate CUSUM detector (samples).
    ///
    /// Larger windows provide a smoother rate estimate but slower detection.
    /// Applies only when `--change-point-alarm` is set.
    #[arg(long, default_value_t = 50)]
    pub change_point_window: usize,

    /// CUSUM slack parameter k for the bypass-rate change-point detector.
    ///
    /// Controls the per-sample allowable drift before the CUSUM accumulates.
    /// Typical value: 0.5 × the minimum detectable rate drop (fraction).
    /// Applies only when `--change-point-alarm` is set.
    #[arg(long, default_value_t = 0.05)]
    pub change_point_k: f64,

    /// CUSUM decision threshold h for the bypass-rate change-point detector.
    ///
    /// The CUSUM accumulator must exceed this value before an alarm fires.
    /// Higher values = fewer false positives but slower detection.
    /// Applies only when `--change-point-alarm` is set.
    #[arg(long, default_value_t = 0.5)]
    pub change_point_h: f64,
}

// ─── Entry point ─────────────────────────────────────────────────────────────

pub(crate) fn run_hunt(args: HuntArgs) -> ExitCode {
    // §7 DEDUPLICATION: delegate to the canonical runtime helper.
    crate::helpers::block_on_with_runtime(run_hunt_async(args))
}

async fn run_hunt_async(mut args: HuntArgs) -> ExitCode {
    // Apply --target preset.
    if let Some(ref preset) = args.target.clone()
        && preset == "cumulusfire"
    {
        if args.base_url.is_none() {
            args.base_url = Some(CUMULUSFIRE_BASE_URL.to_string());
        }
        if args.i_have_permission.is_none() {
            args.i_have_permission = Some(CUMULUSFIRE_PERMISSION.to_string());
        }
    }

    // Paradigm-aware routing: if the operator names an ML-backed WAF
    // (AWS/Cloudflare/Akamai bot-management, Datadome), add the `ml-evasion`
    // decision-boundary strategy to the rotation, rule-decompilation
    // (equiv-cegis) is the wrong paradigm for a learned classifier.
    if let Some(wn) = &args.waf_name
        && wafrift_types::WafClass::from_waf_name(wn).is_ml_backed()
        && !args.strategies.iter().any(|s| s == "ml-evasion")
    {
        args.strategies.push("ml-evasion".to_string());
    }

    let base_url = match args.base_url.clone() {
        Some(u) => u,
        None => {
            // Fall back to WAFRIFT_BENCH_URL or default.
            std::env::var("WAFRIFT_BENCH_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:18081".to_string())
        }
    };

    let campaign_id = args.campaign_id.clone().unwrap_or_else(|| {
        // Stable ID from current wall time (seconds).
        let ts = crate::helpers::now_unix_secs();
        format!("{ts}")
    });
    if let Err(e) = validate_campaign_id(&campaign_id) {
        eprintln!("error: {e}");
        return ExitCode::from(2);
    }

    // N7 fix (dogfood R29 cohort): pre-fix hunt would launch with a
    // missing corpus path, fail per-round inside bench_waf with an
    // error buried in round-1 output, then proceed to "complete"
    // with exit 0. A CI smoke test (`wafrift hunt … --max-duration-
    // secs 30 && echo ok`) printed "ok" even though no round had
    // ever processed a case. Catch the missing-corpus state at the
    // top level BEFORE round 1 starts so the operator sees the
    // failure as a top-level error and the exit code reflects it.
    if !args.corpus.exists() {
        eprintln!(
            "error: corpus path {} does not exist. Default is `wafrift-bench/corpus` \
             relative to CWD; either `cd` into the wafrift repo root before running \
             hunt, or pass `--corpus PATH` explicitly. Hunt aborted before round 1 \
             so the failure is visible to CI.",
            args.corpus.display()
        );
        return ExitCode::from(2);
    }
    // R47 fix (dogfood pass 8 I3): pre-fix hunt would loop forever
    // on an empty corpus directory (every round failed with "no
    // cases found" inside bench_waf but the campaign continued).
    // Walk the corpus path once at startup; if zero .toml files
    // exist, abort with exit 2, a corpus-less hunt produces zero
    // signal by construction. Recursive walk matches bench_waf's
    // own corpus-loading rule.
    fn has_any_toml(path: &std::path::Path) -> bool {
        if path.is_file() {
            return path
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("toml"));
        }
        let Ok(entries) = std::fs::read_dir(path) else {
            return false;
        };
        for ent in entries.flatten() {
            if has_any_toml(&ent.path()) {
                return true;
            }
        }
        false
    }
    if !has_any_toml(&args.corpus) {
        eprintln!(
            "error: corpus path {} contains no `*.toml` files. An empty corpus \
             produces zero signal per round, the campaign would loop forever \
             burning rate-limit budget. Add at least one corpus TOML before \
             launching hunt.",
            args.corpus.display()
        );
        return ExitCode::from(2);
    }

    let state_path = campaign_state_path(&campaign_id);
    let state = load_or_init_state(&state_path, &campaign_id, &base_url);
    let state = Arc::new(Mutex::new(state));

    eprintln!(
        "{} campaign {} targeting {}",
        "[wafrift hunt]".bright_cyan().bold(),
        campaign_id.bright_white(),
        base_url.bright_yellow(),
    );
    // Ctrl-C → set shutdown flag and cancel the inner token.
    let shutdown = Arc::new(AtomicBool::new(false));
    let cancel = CancellationToken::new();
    {
        let shutdown = shutdown.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                eprintln!(
                    "\n{} Ctrl+C, finishing current round then saving…",
                    "⚠".yellow().bold()
                );
                shutdown.store(true, Ordering::SeqCst);
                cancel.cancel();
            }
        });
    }

    let campaign_start = crate::helpers::now_unix_secs();

    let max_duration = if args.max_duration_secs == 0 {
        None
    } else {
        Some(Duration::from_secs(args.max_duration_secs))
    };
    let interval = Duration::from_secs(args.interval_secs);

    let mut round: u64 = {
        let s = state.lock().await;
        s.rounds_completed
    };

    // C-11: CUSUM bypass-rate change-point monitor.
    // Constructed once and owned by the campaign loop; persists CUSUM
    // accumulator state across rounds so the detector integrates evidence
    // continuously rather than resetting every round.
    let mut cp_monitor = args.change_point_alarm.then(|| {
        BypassRateMonitor::new(
            args.change_point_window,
            args.change_point_k,
            args.change_point_h,
        )
    });

    // C-11: How many remaining rounds of exploration boost to pass to bench_waf.
    // Starts at 0; set to 10 when a change-point alarm fires, decremented
    // each round until it reaches 0 again.
    let mut pending_exploration_boost: u32 = 0;

    loop {
        if shutdown.load(Ordering::SeqCst) || cancel.is_cancelled() {
            break;
        }
        if let Some(max) = max_duration {
            let elapsed = crate::helpers::now_unix_secs().saturating_sub(campaign_start);
            if elapsed >= max.as_secs() {
                eprintln!(
                    "{} max-duration {}s reached, stopping.",
                    "[wafrift hunt]".bright_cyan(),
                    args.max_duration_secs
                );
                break;
            }
        }

        round += 1;
        let round_start = std::time::Instant::now();

        eprintln!(
            "{} round {}, strategies: {}",
            "[wafrift hunt]".bright_cyan(),
            round.to_string().bright_white(),
            args.strategies.join(",").dimmed(),
        );

        // Run one bench-waf round and collect any new bypasses.
        // Pass the pending exploration boost so evolutionary-search engines
        // created inside this round call on_change_point() and explore broadly.
        let boost_this_round = pending_exploration_boost;
        pending_exploration_boost = pending_exploration_boost.saturating_sub(1);
        let round_summary = run_one_round(&args, &base_url, round, boost_this_round).await;
        let new_bypasses = &round_summary.bypasses;

        // §13 dogfood round-2 DEFECT 6 (platform UX): a hunt round can run
        // for minutes inside run_one_round; pre-fix the operator saw the
        // "round N, strategies:" start line and then total silence until the
        // next round (or the wall-clock budget), with no signal the campaign
        // was making progress. Emit a per-round completion summary with the
        // elapsed time + fire/bypass counts so each round visibly closes.
        eprintln!(
            "{} round {} done in {:.1}s, fired {} variant(s), {} new verified bypass(es)",
            "[wafrift hunt]".bright_cyan(),
            round,
            round_start.elapsed().as_secs_f64(),
            round_summary.total_variants_sent,
            new_bypasses.len(),
        );

        // C-11: Feed per-variant bypass outcomes into the CUSUM monitor.
        // We synthesise individual observations from the aggregate counts:
        // `total_variants_bypassed` samples of `true` followed by
        // `total_variants_sent - total_variants_bypassed` samples of `false`.
        // This is statistically equivalent to the round's actual distribution
        // and keeps the CUSUM accumulator calibrated to attempt-level granularity
        // rather than round-level (1 observation/round = too coarse for CUSUM).
        let mut change_point_event: Option<ChangePointEvent> = None;
        if let Some(ref mut monitor) = cp_monitor {
            let sent = round_summary.total_variants_sent;
            let bypassed = round_summary.total_variants_bypassed.min(sent);
            let blocked = sent.saturating_sub(bypassed);

            // Feed bypassed attempts first (true), then blocked (false).
            for _ in 0..bypassed {
                monitor.observe(true);
            }
            for _ in 0..blocked {
                let evt = monitor.observe(false);
                if matches!(evt, ChangePointEvent::AlarmFired { .. }) {
                    // Record the first alarm in this round (subsequent ones
                    // in the same round are noise from baseline re-adaptation).
                    if change_point_event.is_none() {
                        change_point_event = Some(evt);
                    }
                }
            }

            // If no alarm fired on the blocked observations, check the last
            // bypassed observation pass as well (needed when ALL attempts bypass).
            if change_point_event.is_none() && bypassed > 0 {
                // Already called observe above; nothing more needed here.
            }
        }

        // Persist new bypasses.
        {
            let mut s = state.lock().await;
            s.rounds_completed = round;
            let now_ts = crate::helpers::now_unix_secs();
            for bp in new_bypasses {
                // Deduplicate by technique+class.
                let already = s.bypasses.iter().any(|existing| {
                    existing.technique == bp.technique && existing.class == bp.class
                });
                if !already {
                    s.bypasses.push(CampaignBypass {
                        discovered_at: now_ts,
                        round,
                        class: bp.class.clone(),
                        technique: bp.technique.clone(),
                        submitted: false,
                    });
                    s.total_bypasses += 1;
                }
            }

            // C-11: Record change-point alarm in campaign state and emit stderr warning.
            // Also activate an exploration boost for the next 10 bench rounds so
            // evolutionary-search engines discard their learned (now-invalidated)
            // strategy and explore the changed WAF landscape broadly.
            if let Some(ChangePointEvent::AlarmFired {
                observed_rate,
                baseline_rate,
                drop_pp,
            }) = change_point_event
            {
                eprintln!(
                    "  {} CHANGE POINT: bypass rate dropped from {:.0}% to {:.0}%. WAF rule update likely",
                    "⚠".yellow().bold(),
                    baseline_rate * 100.0,
                    observed_rate * 100.0,
                );
                s.change_points.push(ChangePointMarker {
                    detected_at: now_ts,
                    round,
                    observed_rate,
                    baseline_rate,
                    drop_pp,
                });
                // Activate exploration boost for the next 10 rounds.
                // The boost is passed to run_one_round → bench_waf → EvolutionEngine
                // so future bench rounds explore more broadly after the rule update.
                pending_exploration_boost = 10;
            }

            if let Err(e) = persist_state(&state_path, &s) {
                eprintln!("{} persist state: {e}", "error:".red());
            }

            eprintln!(
                "  round {} done, new bypasses: {}  total: {}",
                round,
                new_bypasses.len().to_string().bright_green(),
                s.total_bypasses.to_string().bright_green(),
            );
        }

        if shutdown.load(Ordering::SeqCst) || cancel.is_cancelled() {
            break;
        }

        // Wait for the next interval, honouring Ctrl-C.
        let elapsed = round_start.elapsed();
        if elapsed < interval {
            let remaining = interval - elapsed;
            tokio::select! {
                _ = tokio::time::sleep(remaining) => {}
                _ = cancel.cancelled() => { break; }
            }
        }
    }

    // Final persist.
    {
        let s = state.lock().await;
        if let Err(e) = persist_state(&state_path, &s) {
            eprintln!("{} final persist: {e}", "error:".red());
        }
        eprintln!(
            "{} campaign {} stopped. Total rounds: {}  Total bypasses: {}  State: {}",
            "[wafrift hunt]".bright_cyan().bold(),
            campaign_id.bright_white(),
            s.rounds_completed.to_string().bright_white(),
            s.total_bypasses.to_string().bright_green(),
            state_path.display().to_string().dimmed(),
        );
    }

    ExitCode::SUCCESS
}

// ─── Round runner ─────────────────────────────────────────────────────────────

/// A minimal bypass observation returned from a round.
struct RoundBypass {
    class: String,
    technique: String,
}

/// Summary counts returned from a bench-waf round, used by the CUSUM
/// bypass-rate monitor to feed per-attempt observations.
struct RoundSummary {
    bypasses: Vec<RoundBypass>,
    /// Total variant attempts sent in this round (across all corpus cases).
    total_variants_sent: u64,
    /// Total variants confirmed as bypasses in this round.
    total_variants_bypassed: u64,
}

/// Run one round of bench-waf evasion and collect newly confirmed bypasses.
///
/// We invoke the bench logic by constructing `BenchWafArgs` and passing it
/// directly to the bench runner rather than spawning a subprocess, this
/// keeps the campaign in-process and avoids serialization overhead.
///
/// Returns a [`RoundSummary`] containing the bypasses plus total variant
/// counts, which the CUSUM bypass-rate monitor uses to feed per-attempt
/// observations without requiring access to bench-waf's internal state.
///
/// `exploration_boost_rounds > 0` signals to evolutionary-search strategies
/// that a change-point alarm fired in the previous round and they should
/// explore more broadly (see `EvolutionEngine::on_change_point`).
async fn run_one_round(
    args: &HuntArgs,
    base_url: &str,
    round: u64,
    exploration_boost_rounds: u32,
) -> RoundSummary {
    use crate::bench_waf::{BenchWafArgs, run_bench_waf};

    // Persist every confirmed bypass's winning payload + response evidence
    // to a per-target rule-bypass corpus under ~/.wafrift, so a campaign
    // accumulates a re-verifiable, submittable bypass set across rounds
    // (consumed by `wafrift harvest`). Pre-fix hunt passed corpus_out:None,
    // discarding every winning payload the strategies found, only
    // technique tags survived in the campaign state, which can't
    // reconstruct the wire payload. The path is computed by the SINGLE
    // shared helper `harvest` also reads from, so the two can't diverge.
    let (corpus_path, coverage_path) = crate::hunt::corpus_recorder::default_corpus_paths(base_url);

    let bench_args = BenchWafArgs {
        base_url: Some(base_url.to_string()),
        corpus: args.corpus.clone(),
        class: args.class.clone(),
        evade: true, // hunt always evades
        variants: args.variants,
        strategies: rotate_strategies(&args.strategies, round),
        // Paradigm-aware routing: the campaign-level `--waf-name` flows to
        // each bench round so the `ml-evasion` strategy (added to the
        // rotation above when the WAF is ML-backed) routes through the
        // manifold-projected ML-evasion structural mutator.
        waf_name: args.waf_name.clone(),
        // hunt gates at the campaign level (--i-have-permission / cumulus
        // preset); its internal bench rounds don't re-gate, the CLI bench-waf
        // arm is what gates direct invocations.
        i_have_permission: None,
        oracle_gate: false, // no-op flag
        delay_ms: args.delay_ms,
        timeout_secs: 15,
        insecure: false,
        output: None, // we handle persistence ourselves
        // Overwrite REQUIRED: run_one_round pre-claims the per-round tmp
        // output path via O_CREAT|O_EXCL (the TOCTOU/symlink defense
        // below), so the file already exists when bench_waf opens it.
        // Without force_overwrite, bench_waf's no-clobber guard rejects
        // EVERY round's output ("already exists … --force-overwrite") and
        // the whole campaign records 0 bypasses. We own the freshly
        // claimed regular file, so overwriting it is correct + safe.
        force_overwrite: true,
        format: "json".into(),
        summary_only: true, // don't print per-case noise
        prove_execution: false,
        skip_healthcheck: true,
        adaptive_pause_after_errors: 50,
        adaptive_pause_secs: 2,
        validate_only: false,
        lineage_output: None,
        // Info-gain scheduling: hunt manages its own round budget via
        // exploration_boost_rounds + per-strategy rotation, so the
        // per-bench-waf scheduler stays off here. If a future tweak
        // ever wants hunt to feed the scheduler with cross-round
        // history, surface a HuntArgs flag and plumb it through.
        budget: None,
        history_file: None,
        history_merge: Vec::new(),
        fair_class: false,
        list_schedule: false,
        egress_socks5: Vec::new(),
        egress_http_proxy: Vec::new(),
        egress_tailscale_nodes: Vec::new(),
        egress_tailscale_socks_addr: crate::config::DEFAULT_TAILSCALE_SOCKS_ADDR.into(),
        egress_challenge_threshold: crate::config::DEFAULT_EGRESS_CHALLENGE_THRESHOLD,
        egress_cooldown_secs: crate::config::DEFAULT_EGRESS_COOLDOWN_SECS,
        mutator: "default".into(),
        seed: None,
        dilution_weight: 0.0,
        corpus_out: Some(corpus_path),
        coverage_out: Some(coverage_path),
        corpus_fingerprint: String::new(),
        ci_threshold: 0.0, // hunt doesn't use CI gating; pass-through default
        exploration_boost_rounds, // C-11: injected by hunt when CUSUM alarm fires
    };

    // Capture stdout temporarily to intercept the bench JSON output.
    // We run bench_waf on a thread (it has its own tokio runtime) and
    // collect the results via the JSON output path written to a temp file.
    //
    // The tmp filename includes the process PID + a nanosecond timestamp
    // to defeat the predictable-tmp-path symlink attack: pre-fix the
    // path was `/tmp/wafrift-hunt-round-{round}.json`, which an attacker
    // on a shared box could pre-create as `ln -s /etc/cron.d/evil <path>`
    // BEFORE hunt started, bench_waf's `fs::write` would then follow
    // the symlink and clobber the attacker-chosen target.
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let tmp = std::env::temp_dir().join(format!(
        "wafrift-hunt-round-{}-{nanos}-{round}.json",
        std::process::id()
    ));
    // Belt + braces: claim the inode atomically via O_CREAT|O_EXCL
    // BEFORE handing the path to bench_waf. If anything (including a
    // symlink) already sits at the path, this errors and we skip the
    // round, much safer than truncating a victim file. Once claimed,
    // bench_waf's fs::write (O_CREAT|O_TRUNC) reopens OUR regular
    // file and proceeds normally.
    if let Err(e) = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
    {
        eprintln!(
            "warn: hunt round {round} could not claim {} ({e}); skipping round",
            tmp.display()
        );
        return RoundSummary {
            bypasses: Vec::new(),
            total_variants_sent: 0,
            total_variants_bypassed: 0,
        };
    }
    let tmp_clone = tmp.clone();

    let bench_args_with_output = BenchWafArgs {
        output: Some(tmp_clone),
        summary_only: false, // need results array
        ..bench_args
    };

    let exit = tokio::task::spawn_blocking(move || run_bench_waf(bench_args_with_output))
        .await
        .unwrap_or(ExitCode::from(1));

    // Exit code 2 means zero bypasses (that's fine; read the file anyway).
    let _ = exit;

    // Parse the output file.
    let raw = match crate::safe_body::read_bounded_text_file(&tmp, HUNT_BENCH_OUTPUT_MAX_BYTES) {
        Ok(s) => s,
        Err(_) => {
            return RoundSummary {
                bypasses: Vec::new(),
                total_variants_sent: 0,
                total_variants_bypassed: 0,
            };
        }
    };
    let _ = std::fs::remove_file(&tmp);

    let json: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => {
            return RoundSummary {
                bypasses: Vec::new(),
                total_variants_sent: 0,
                total_variants_bypassed: 0,
            };
        }
    };

    // Extract top-level summary variant counts for the CUSUM monitor.
    let total_variants_sent = json
        .get("total_variants_sent")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let total_variants_bypassed = json
        .get("total_variants_bypassed")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    // Collect confirmed bypasses from the results array.
    let mut bypasses = Vec::new();
    if let Some(results) = json.get("results").and_then(|v| v.as_array()) {
        for result in results {
            let class = result
                .get("class")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            if let Some(evaded) = result.get("evaded").and_then(|v| v.as_object()) {
                let bypassed = evaded
                    .get("variants_bypassed")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                if bypassed > 0 {
                    if let Some(techs) = evaded.get("bypass_techniques").and_then(|v| v.as_array())
                    {
                        for t in techs {
                            if let Some(s) = t.as_str() {
                                bypasses.push(RoundBypass {
                                    class: class.clone(),
                                    technique: s.to_string(),
                                });
                            }
                        }
                    } else {
                        bypasses.push(RoundBypass {
                            class: class.clone(),
                            technique: "unknown".to_string(),
                        });
                    }
                }
            }
        }
    }
    RoundSummary {
        bypasses,
        total_variants_sent,
        total_variants_bypassed,
    }
}

/// Rotate strategy list each round, cycle through subsets to explore the
/// strategy space over many rounds rather than hammering the same set.
fn rotate_strategies(strategies: &[String], round: u64) -> Vec<String> {
    if strategies.len() <= 1 {
        return strategies.to_vec();
    }
    // Offset the strategy list by the round index (wrapping).
    let offset = (round as usize) % strategies.len();
    let mut rotated = strategies.to_vec();
    rotated.rotate_left(offset);
    // Use the first min(2, len) strategies for this round.
    let take = 2.min(rotated.len());
    rotated.truncate(take);
    rotated
}

// ─── Persistence ─────────────────────────────────────────────────────────────

/// Permit only safe filename chars in `--campaign-id`. Pre-fix the
/// id was interpolated raw into `hunt-{id}.json`, so an operator
/// passing `--campaign-id ../../tmp/pwn` (whether by mistake or in a
/// scripted pipeline) escaped `~/.wafrift/` and could overwrite
/// arbitrary user-writable files. The allowed alphabet is the
/// portable-filename set plus dash and dot.
fn validate_campaign_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("--campaign-id cannot be empty".to_string());
    }
    if id.len() > 128 {
        return Err(format!(
            "--campaign-id is {} chars; maximum is 128",
            id.len()
        ));
    }
    if id == "." || id == ".." {
        return Err(format!("--campaign-id '{id}' is reserved"));
    }
    if id.starts_with('-') {
        // Defends against a campaign-id that looks like a CLI flag if
        // the value ever flows back into a subprocess argv.
        return Err(format!("--campaign-id '{id}' cannot start with '-'"));
    }
    for ch in id.chars() {
        let ok = ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.';
        if !ok {
            return Err(format!(
                "--campaign-id '{id}' contains invalid character {ch:?}; \
                 allowed: [A-Za-z0-9_-.]"
            ));
        }
    }
    Ok(())
}

fn campaign_state_path(campaign_id: &str) -> PathBuf {
    // Caller MUST have already validated campaign_id via
    // validate_campaign_id; in release we still defence-in-depth by
    // accepting only the validator's alphabet via the format string
    // (any traversal char would already have been rejected upstream).
    let base = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".wafrift");
    let _ = std::fs::create_dir_all(&base);
    base.join(format!("hunt-{campaign_id}.json"))
}

fn load_or_init_state(
    path: &std::path::Path,
    campaign_id: &str,
    target_url: &str,
) -> CampaignState {
    if let Ok(raw) = crate::safe_body::read_bounded_text_file(path, HUNT_CAMPAIGN_STATE_MAX_BYTES)
        && let Ok(s) = serde_json::from_str::<CampaignState>(&raw)
    {
        eprintln!(
            "{} resuming campaign {} (round {}, {} bypasses so far)",
            "[wafrift hunt]".bright_cyan(),
            campaign_id.bright_white(),
            s.rounds_completed,
            s.total_bypasses
        );
        return s;
    }
    let started_at = crate::helpers::now_unix_secs();
    CampaignState {
        campaign_id: campaign_id.to_string(),
        target_url: target_url.to_string(),
        started_at,
        rounds_completed: 0,
        total_bypasses: 0,
        schema_version: CampaignState::SCHEMA_VERSION,
        bypasses: vec![],
        change_points: vec![],
    }
}

fn persist_state(path: &std::path::Path, state: &CampaignState) -> Result<(), String> {
    let json = serde_json::to_string_pretty(state).map_err(|e| e.to_string())?;
    // R49 tail (CLAUDE.md §7 DEDUPLICATION): use the canonical
    // wafrift_types::loaders::write_atomic helper instead of the
    // ad-hoc tmp+rename dance. Same semantics, one source of truth,
    // matches seed.rs / bank.rs callers. The helper also handles
    // parent-fsync for crash durability which the ad-hoc version
    // skipped.
    wafrift_types::loaders::write_atomic(path, json.as_bytes())
        .map_err(|e| format!("atomic write {}: {e}", path.display()))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "hunt_cmd_tests.rs"]
mod tests;
