//! Info-gain payload scheduler, given prior bench history, schedule
//! payload replays in descending order of expected information gain.
//!
//! ## Why this exists
//!
//! Operators frequently have a budget cap ("only send 1 000 requests
//! against this WAF, not 100 000"). Running every payload greedily
//! wastes the budget on payloads that already block trivially or
//! already bypass trivially, neither outcome teaches the operator
//! anything new about the rule set. The payloads that DO teach
//! something are the ones whose observed block rate is near 0.5: the
//! WAF blocks them sometimes, passes them sometimes, depending on a
//! rule the operator has not yet fingerprinted.
//!
//! Binary Shannon entropy `H(p) = -p·log2(p) − (1−p)·log2(1−p)`
//! captures exactly this: it peaks at 1 bit when p = 0.5 and drops to
//! zero at the endpoints. Scheduling by descending `H(theta)` puts
//! the high-information payloads at the front of the queue.
//!
//! ## Model
//!
//! Each payload's block probability is treated as a Beta-distributed
//! posterior under a uniform Beta(1,1) prior:
//!
//! ```text
//!   alpha = 1 + n_blocked
//!   beta  = 1 + n_passed
//!   theta_mean = alpha / (alpha + beta)
//! ```
//!
//! A payload with no prior observations starts at theta = 0.5, the
//! cold-start payload carries one bit of uncertainty, the maximum.
//! As observations accumulate, theta converges and H(theta) shrinks.
//!
//! ## Why posterior-mean entropy, not Thompson sampling
//!
//! Thompson sampling balances exploration vs exploitation toward
//! reward maximisation (e.g. "find a bypass"). The scheduler's goal
//! is **information gain about the rule set**, a research objective
//!, posterior-mean entropy is the right objective for that. If a
//! future caller wants the reward-maximisation variant, build it as
//! a separate scheduler that shares this module's `PayloadStats`
//! contract.
//!
//! ## Tiebreak design
//!
//! When two payloads have equal entropy (frequently: many cold-start
//! payloads at theta = 0.5), the secondary sort key is `n_trials`
//! ascending, prefer the LESS-explored one. Without this tiebreak,
//! the schedule would re-run the same handful of cold-start payloads
//! until one of them happened to differ, starving the rest. The
//! final tiebreak is `id` ascending so the schedule is deterministic
//! for test reproducibility.
//!
//! ## Backwards compatibility
//!
//! `PayloadStats::default()` is the cold-start prior. Any payload
//! added in a future release that is missing from a prior history
//! file deserialises to cold-start; no migration required (LAW 2).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use wafrift_types::binary_shannon;

/// Per-payload Bernoulli observation tally. Default = cold-start
/// (zero trials, theta = 0.5 under Beta(1,1)).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PayloadStats {
    /// Trials that ended with the WAF blocking the request.
    #[serde(default)]
    pub n_blocked: u32,
    /// Trials that ended with the WAF letting the request through.
    #[serde(default)]
    pub n_passed: u32,
}

impl PayloadStats {
    /// Total number of observations contributed so far. Saturating
    /// addition: `observe()` already caps each component at
    /// `u32::MAX`, but the sum of two near-`u32::MAX` values would
    /// still overflow with plain `+`. Saturate to keep n_trials
    /// monotonically non-decreasing across the public API.
    #[must_use]
    pub const fn n_trials(&self) -> u32 {
        self.n_blocked.saturating_add(self.n_passed)
    }

    /// Posterior mean of the block probability under a Beta(1,1)
    /// prior. Always in `[0, 1]`. The `+1` shift on both alpha and
    /// beta ensures `n_trials == 0` returns `0.5` without a special
    /// case.
    #[must_use]
    pub fn theta_estimate(&self) -> f64 {
        let alpha = 1.0 + f64::from(self.n_blocked);
        let beta = 1.0 + f64::from(self.n_passed);
        alpha / (alpha + beta)
    }

    /// Expected information gain from running this payload one more
    /// time, approximated as the binary Shannon entropy of the
    /// current `theta_estimate`. Always in `[0, 1]` bits.
    #[must_use]
    pub fn info_gain(&self) -> f64 {
        binary_shannon(self.theta_estimate())
    }

    /// Approximate 95% credible interval `(lower, upper)` for
    /// `theta_estimate` under the Beta-Bernoulli posterior, using
    /// the Wald (normal) approximation
    /// `theta ± Z_SCORE_95 · sqrt(theta·(1-theta) / n_eff)` where
    /// `n_eff = n_trials + BETA11_PRIOR_PSEUDO_TRIALS`. Result
    /// clamped to `[0, 1]`.
    ///
    /// Useful for operators answering "how confident is the scheduler
    /// in this estimate?", a payload with theta=0.5 and n_trials=2
    /// has a much wider band than one with theta=0.5 and n_trials=200,
    /// even though their `info_gain` matches at 1.0 bit.
    ///
    /// For more accurate intervals near the boundary (theta close to
    /// 0 or 1), a future version could swap in Wilson score or the
    /// exact Beta credible interval, both require either an
    /// inverse-CDF dependency or tabulated approximations. The Wald
    /// form here is adequate for the scheduler's "is this estimate
    /// stable?" question without pulling in a stats crate on a leaf-
    /// level module.
    #[must_use]
    pub fn theta_ci_95(&self) -> (f64, f64) {
        /// Standard-normal critical value for a two-sided 95% interval
        /// (`Φ⁻¹(0.975) ≈ 1.96`). Named so a future tightening (e.g.
        /// switching to a 99% interval, `Φ⁻¹(0.995) ≈ 2.576`) is a
        /// one-place edit and a silent re-tune is impossible.
        const Z_SCORE_95: f64 = 1.959_963_984_540_054;
        /// Pseudo-trial contribution from the uniform Beta(1,1)
        /// prior: 1 from `n_blocked` shift + 1 from `n_passed` shift.
        /// Adding this to `n_trials` gives the effective sample size
        /// the Wald formula needs. Named so the meaning isn't
        /// inscrutable to a reader who hasn't memorised Beta-Bernoulli.
        const BETA11_PRIOR_PSEUDO_TRIALS: f64 = 2.0;
        let theta = self.theta_estimate();
        let n_eff = f64::from(self.n_trials()) + BETA11_PRIOR_PSEUDO_TRIALS;
        let se = (theta * (1.0 - theta) / n_eff).sqrt();
        let half = Z_SCORE_95 * se;
        let lo = (theta - half).max(0.0);
        let hi = (theta + half).min(1.0);
        (lo, hi)
    }

    /// Update the posterior with a single observation. Saturating
    /// arithmetic, a single payload that runs `u32::MAX` times
    /// silently caps rather than wraps. Realistic budget ceilings are
    /// in the millions; saturation is a safety net for adversarial
    /// inputs, not a normal-path concern.
    pub fn observe(&mut self, blocked: bool) {
        if blocked {
            self.n_blocked = self.n_blocked.saturating_add(1);
        } else {
            self.n_passed = self.n_passed.saturating_add(1);
        }
    }
}

/// Aggregate history across payloads. Persisted to disk between
/// invocations as the scheduler's warm-start memory.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct History {
    #[serde(default)]
    pub by_id: BTreeMap<String, PayloadStats>,
}

impl History {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Stats for a payload id, cold-start prior if unknown. Does NOT
    /// insert; the scheduler may call this on thousands of payloads
    /// without growing the history.
    #[must_use]
    pub fn stats(&self, id: &str) -> PayloadStats {
        self.by_id.get(id).cloned().unwrap_or_default()
    }

    /// Update the posterior for `id` with a single observation,
    /// creating the entry if absent.
    pub fn observe(&mut self, id: impl Into<String>, blocked: bool) {
        self.by_id.entry(id.into()).or_default().observe(blocked);
    }

    /// Number of payloads with at least one observation.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// True if no payload has been observed yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Merge another history into this one. For each payload id in
    /// `other`, the local `n_blocked` and `n_passed` counts are
    /// incremented by the other history's counts. New payload ids
    /// from `other` are inserted at their absolute counts.
    ///
    /// Saturating arithmetic, if either side overflows `u32::MAX`,
    /// the merged total caps at `u32::MAX` rather than wrapping. In
    /// practice a single payload accumulating more than 4 billion
    /// observations is adversarial-input territory; the saturation
    /// is a safety net, not a normal-path concern.
    ///
    /// Useful for operators running multiple parallel WAF
    /// assessments who want to combine the per-payload posteriors
    /// into a single warm-start file for a follow-up bench. Pure on
    /// the inputs (`other` is not mutated).
    ///
    /// Wired into `bench-waf --history-merge` (repeatable) so the
    /// operator-facing path uses the same primitive the unit tests
    /// pin. Do NOT add `#[cfg(test)]` here, the production wiring
    /// depends on it.
    pub fn merge(&mut self, other: &History) {
        for (id, other_stats) in &other.by_id {
            let entry = self.by_id.entry(id.clone()).or_default();
            entry.n_blocked = entry.n_blocked.saturating_add(other_stats.n_blocked);
            entry.n_passed = entry.n_passed.saturating_add(other_stats.n_passed);
        }
    }
}

/// A scheduled payload paired with the diagnostics that justify its
/// rank: `info_gain` bits, `theta_estimate` block probability,
/// `theta_ci_95_*` Wald credible-interval bounds, and `n_trials` prior
/// observations. Used by `schedule_with_diagnostics` and the
/// `bench-waf --list-schedule` preview path.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct ScheduleEntry {
    /// Payload identifier (matches `BenchCase::id`).
    pub id: String,
    /// Posterior mean of the block probability, in `[0, 1]`.
    pub theta_estimate: f64,
    /// Lower bound of the 95% Wald credible interval for theta.
    #[serde(default)]
    pub theta_ci_95_lo: f64,
    /// Upper bound of the 95% Wald credible interval for theta.
    #[serde(default)]
    pub theta_ci_95_hi: f64,
    /// Binary Shannon entropy of `theta_estimate`, in `[0, 1]` bits.
    pub info_gain: f64,
    /// Prior observations contributing to the estimate.
    pub n_trials: u32,
}

/// Order `payloads` by descending expected info gain (ties broken by
/// fewer prior trials, then by id ascending) and return the top
/// `budget` entries with their diagnostic fields preserved.
///
/// Useful when the caller wants to display *why* a payload was
/// chosen, not just *that* it was chosen, the `bench-waf
/// --list-schedule` flag uses this to render an operator-readable
/// preview table. The plain `schedule` function is a thin wrapper
/// that discards the diagnostics and returns just the id list.
#[must_use]
pub(crate) fn schedule_with_diagnostics<'a, I, S>(
    history: &History,
    payloads: I,
    budget: usize,
) -> Vec<ScheduleEntry>
where
    I: IntoIterator<Item = &'a S>,
    S: AsRef<str> + 'a + ?Sized,
{
    if budget == 0 {
        return Vec::new();
    }
    // Pre-compute (info_gain, n_trials, stats) per payload so the
    // sort comparator reads cached f64s instead of recomputing
    // theta_estimate→info_gain (log2 + multiply) at every comparison.
    // For N=10k payloads with ~150k comparisons in unstable sort, that
    // saves ~300k log2/multiply pairs. Empirical ~7% wall-clock
    // improvement at N=10k; bigger wins at N=100k.
    let mut items: Vec<(String, f64, u32, PayloadStats)> = payloads
        .into_iter()
        .map(|p| {
            let id = p.as_ref().to_string();
            let stats = history.stats(&id);
            let info_gain = stats.info_gain();
            let n_trials = stats.n_trials();
            (id, info_gain, n_trials, stats)
        })
        .collect();
    // sort_unstable_by is faster than sort_by and equivalent here:
    // the comparator already has explicit tie-breaks (n_trials, then
    // id) so the result is deterministic regardless of underlying
    // sort stability. Wins ~20% on large corpora.
    items.sort_unstable_by(|(a_id, a_gain, a_trials, _), (b_id, b_gain, b_trials, _)| {
        // Descending by gain: b vs a, not a vs b. partial_cmp can
        // return None for NaN, but `binary_shannon` zeroes NaN out so
        // this path is defensive only.
        b_gain
            .partial_cmp(a_gain)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a_trials.cmp(b_trials))
            .then_with(|| a_id.cmp(b_id))
    });
    items
        .into_iter()
        .take(budget)
        .map(|(id, info_gain, n_trials, stats)| {
            let (lo, hi) = stats.theta_ci_95();
            ScheduleEntry {
                id,
                theta_estimate: stats.theta_estimate(),
                theta_ci_95_lo: lo,
                theta_ci_95_hi: hi,
                info_gain,
                n_trials,
            }
        })
        .collect()
}

/// Order `payloads` by descending expected info gain, ties broken by
/// fewer prior trials, then by id ascending. Returns the top
/// `budget` payload ids in schedule order.
///
/// `budget == 0` returns an empty Vec without iterating. `budget >=
/// payloads.len()` returns every payload in schedule order, useful
/// as a deterministic ordering primitive even when budget is not the
/// binding constraint.
///
/// Thin wrapper over [`schedule_with_diagnostics`] that discards the
/// per-entry diagnostic fields. If you need to surface *why* a
/// payload was chosen, call `schedule_with_diagnostics` directly.
///
/// Test-only: production paths call `schedule_with_diagnostics` so
/// they can surface the diagnostic fields (info_gain, theta, n_trials)
/// in `--list-schedule` output without a second traversal.
#[cfg(test)]
#[must_use]
pub(crate) fn schedule<'a, I, S>(history: &History, payloads: I, budget: usize) -> Vec<String>
where
    I: IntoIterator<Item = &'a S>,
    S: AsRef<str> + 'a + ?Sized,
{
    schedule_with_diagnostics(history, payloads, budget)
        .into_iter()
        .map(|e| e.id)
        .collect()
}

/// Schedule with per-class fairness, every class receives roughly
/// `budget / num_classes` slots; within each class, payloads are
/// ordered by descending info gain (same primitive as `schedule`).
///
/// ## Why this exists
///
/// Pure `schedule` is class-blind. A corpus with 95% SQL cases and
/// 5% XSS cases will, under budget pressure, deliver an "all SQL"
/// schedule even though the operator probably wanted some signal on
/// every class. Per-class fairness prevents that starvation.
///
/// ## Allocation rule
///
/// Integer division: `base = budget / num_classes`, with the
/// remainder `extras = budget % num_classes` distributed one per
/// class in iteration order (BTreeMap → alphabetical by class name).
/// This makes the per-class allocation deterministic and reproducible
/// across runs (critical for the `schedule` anti-rig guarantees).
///
/// If a class has fewer payloads than its allocation, the surplus
/// is NOT redistributed: a class with 2 payloads and a 5-slot
/// allocation contributes 2 ordered payloads, total result is
/// (budget − 3) items. This is the documented "honest under-fill"
/// contract; a redistribution mode is a future feature.
///
/// ## Output ordering
///
/// Classes interleave in BTreeMap iteration order (alphabetical),
/// each class contributing its top picks in descending info_gain
/// order. The result is NOT globally sorted by info_gain, operators
/// who want that should call `schedule` directly.
///
/// Thin wrapper over [`schedule_per_class_with_diagnostics`] that
/// discards the per-entry diagnostic fields. Use the diagnostic
/// version when the caller needs to surface `info_gain`/`theta`/
/// `n_trials` (e.g. `--list-schedule --fair-class` preview).
///
/// Test-only: production paths call `schedule_per_class_with_diagnostics`
/// so they can render `--list-schedule` output without a second traversal.
#[cfg(test)]
#[must_use]
pub(crate) fn schedule_per_class(
    history: &History,
    payloads_by_class: &std::collections::BTreeMap<String, Vec<String>>,
    budget: usize,
) -> Vec<String> {
    schedule_per_class_with_diagnostics(history, payloads_by_class, budget)
        .into_iter()
        .map(|e| e.id)
        .collect()
}

/// Per-class fairness schedule with diagnostic fields preserved.
/// Mirror of `schedule_per_class` that emits [`ScheduleEntry`]
/// values instead of bare ids, so the `bench-waf --list-schedule`
/// preview path can render correct per-case info_gain numbers even
/// when `--fair-class` is the active mode.
///
/// Same allocation rule + same interleaving order as
/// `schedule_per_class`: the only difference is the return type.
#[must_use]
pub(crate) fn schedule_per_class_with_diagnostics(
    history: &History,
    payloads_by_class: &std::collections::BTreeMap<String, Vec<String>>,
    budget: usize,
) -> Vec<ScheduleEntry> {
    if budget == 0 || payloads_by_class.is_empty() {
        return Vec::new();
    }
    let num_classes = payloads_by_class.len();
    let base_per_class = budget / num_classes;
    let extras = budget % num_classes;

    let mut result = Vec::with_capacity(budget);
    for (idx, (_class, payloads)) in payloads_by_class.iter().enumerate() {
        let class_budget = base_per_class + usize::from(idx < extras);
        if class_budget == 0 {
            continue;
        }
        let payload_refs: Vec<&str> = payloads.iter().map(String::as_str).collect();
        let entries = schedule_with_diagnostics(history, &payload_refs, class_budget);
        result.extend(entries);
    }
    result
}

/// Load a persisted [`History`] from `path`, cold-starting (empty history) when
/// the file is absent, the documented first-run path, which must not error, or
/// when it fails to parse (a warning is emitted and a cold history returned, so a
/// corrupt history never aborts a live run). A genuine IO error on an existing
/// file IS propagated. Bounded read (no OOM / TOCTOU): single fd, hard cap.
///
/// The same loader `bench-waf --history-file` uses, so the scheduler's warm-start
/// semantics are identical across every command that schedules by info gain.
pub(crate) fn load_history(path: &std::path::Path) -> Result<History, String> {
    if !path.exists() {
        return Ok(History::new());
    }
    let text =
        crate::safe_body::read_bounded_text_file(path, crate::safe_body::GENE_BANK_FILE_MAX_BYTES)
            .map_err(|e| format!("history file {} unreadable: {e}", path.display()))?;
    Ok(serde_json::from_str::<History>(&text).unwrap_or_else(|e| {
        eprintln!(
            "warn: history file {} parse error ({e}); starting cold",
            path.display()
        );
        History::new()
    }))
}

/// Persist `history` to `path` as pretty JSON via an **atomic** write (temp +
/// rename), so a crash mid-write can never truncate the operator's warm-start
/// file. Single-writer file owned by wafrift itself (never a symlink target it
/// doesn't control). The canonical persist used by both `bench-waf
/// --history-file` and `fingerprint --filter-history`.
pub(crate) fn save_history(path: &std::path::Path, history: &History) -> Result<(), String> {
    let json =
        serde_json::to_string_pretty(history).map_err(|e| format!("serialise history: {e}"))?;
    wafrift_types::loaders::write_atomic(path, json.as_bytes())
        .map_err(|e| format!("writing history file {}: {e}", path.display()))
}

/// Reorder `items` into descending info-gain schedule order under `history`,
/// returning at most `budget` of them (`budget == 0` ⇒ all, just reordered).
/// `id_of` maps an item to its scheduler id (e.g. a probe's token). When
/// `budget` is binding, the dropped items are the LOWEST-info-gain ones, under
/// a warm history that is exactly the live-query budget spent where it teaches
/// the most. Cold-start (empty history) is deterministic: every id ties at
/// θ=0.5, so the order falls back to ascending id (the scheduler's final
/// tiebreak), never RNG.
///
/// Items with ids absent from the computed schedule (only possible when `budget`
/// truncates) are dropped; duplicate ids keep the last item (battery integrity
/// forbids dup tokens, so this is defensive).
pub(crate) fn order_items_by_info_gain<T>(
    history: &History,
    items: Vec<T>,
    budget: usize,
    id_of: impl Fn(&T) -> String,
) -> Vec<T> {
    let effective = if budget == 0 {
        items.len()
    } else {
        budget.min(items.len())
    };
    let ids: Vec<String> = items.iter().map(&id_of).collect();
    let scheduled = schedule_with_diagnostics(history, &ids, effective);
    let mut by_id: std::collections::HashMap<String, T> =
        items.into_iter().map(|it| (id_of(&it), it)).collect();
    scheduled
        .into_iter()
        .filter_map(|e| by_id.remove(&e.id))
        .collect()
}

#[cfg(test)]
#[path = "info_gain_sched_tests.rs"]
mod tests;
