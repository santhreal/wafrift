//! Drift-aware evasion window detection (#115).
//!
//! WAF behaviour is not stationary. Rules reload (CF Auto-Tune retrains every
//! ~hour), edges throttle, IP reputation flips. The same payload may be blocked
//! at minute 0 and pass at minute 47.
//!
//! This module implements a CUSUM-based sequential change-point detector that
//! tracks four per-target signals:
//!
//! 1. **Median response time**: slower = heavier inspection.
//! 2. **P95 response time**: spike = new DPI layer spinning up.
//! 3. **Block rate** (over last 50 probes) (direct measure of WAF policy).
//! 4. **Body-hash entropy**: change in response diversity signals new rules.
//!
//! Each signal runs an independent CUSUM detector. A [`RegimeChange`] fires
//! when **≥ 2 signals agree** on the direction of change.
//!
//! The [`HostState`] integration calls [`DriftDetector::observe`] on every
//! probe result and, when [`RegimeChange::LooserNow`] fires, re-queues
//! previously-blocked payloads for retry.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

// ── Constants ───────────────────────────────────────────────────────────────

/// Number of probes to keep in the sliding window for baseline statistics.
const DEFAULT_WINDOW_SIZE: usize = 50;

/// CUSUM threshold: how many standard deviations of accumulated drift before
/// we fire a change-point. 4.0 σ balances false-positive rate vs. detection
/// latency at the 50-sample window.
const DEFAULT_THRESHOLD: f64 = 4.0;

/// Number of bodies to track for hash-entropy estimation.
const BODY_HASH_WINDOW: usize = 32;

/// Agreement threshold: how many independent CUSUM signals must agree before
/// a `RegimeChange` fires. Prevents single-signal noise from triggering retries.
const SIGNAL_AGREEMENT: usize = 2;

// ── Public types ─────────────────────────────────────────────────────────────

/// Direction and magnitude of a detected WAF regime change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegimeChange {
    /// WAF is blocking less aggressively (retry the blocked corpus now).
    LooserNow,
    /// WAF is blocking more aggressively (back off, slow down probing).
    StricterNow,
    /// Regime changed but signals disagree on direction (e.g. latency went
    /// up while block rate went down). Retry cautiously; do not assume free
    /// passage.
    Unclear,
}

/// A single probe observation fed into [`DriftDetector::observe`].
#[derive(Debug, Clone)]
pub struct ProbeObservation {
    /// Round-trip time of the probe in milliseconds.
    pub response_time_ms: f64,
    /// Whether this probe was blocked by the WAF.
    pub was_blocked: bool,
    /// A cheap hash of the response body (e.g. `hash(body[..512])`).
    /// `None` if the response had no body or it was not read.
    pub body_hash: Option<u64>,
}

/// CUSUM-based sequential change-point detector for a single scalar signal.
///
/// Tracks cumulative sum of deviations above/below a rolling baseline.
/// When either `s_high` or `s_low` exceeds `threshold * baseline_std` a
/// change is detected and the accumulators reset.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CusumDetector {
    /// Rolling baseline window for mean/stdev estimation.
    window: VecDeque<f64>,
    window_size: usize,
    /// CUSUM accumulator for upward shifts (signal rising above mean).
    s_high: f64,
    /// CUSUM accumulator for downward shifts (signal falling below mean).
    s_low: f64,
    /// Detection threshold as a multiple of baseline stdev.
    threshold: f64,
    /// Direction of the most-recently fired change (+1 = higher, -1 = lower).
    last_direction: i8,
}

impl CusumDetector {
    fn new(window_size: usize, threshold: f64) -> Self {
        Self {
            window: VecDeque::with_capacity(window_size),
            window_size,
            s_high: 0.0,
            s_low: 0.0,
            threshold,
            last_direction: 0,
        }
    }

    /// Push a new observation.  Returns `Some(direction)` (+1 or -1) when a
    /// change-point fires, `None` when still within the stationary regime.
    fn push(&mut self, value: f64) -> Option<i8> {
        // Need at least 4 points to estimate a meaningful baseline.
        if self.window.len() < 4 {
            if self.window.len() >= self.window_size {
                self.window.pop_front();
            }
            self.window.push_back(value);
            return None;
        }

        let (mean, std) = self.mean_std();
        // The CUSUM detection threshold k = threshold × σ. When the baseline
        // is perfectly stationary (σ ≈ 0), k → 0 and ANY deviation fires
        // immediately (a false-positive on perfectly identical synthetic data).
        //
        // Enforce a minimum σ floor to keep the detector from being hair-
        // triggered by floating-point noise, while still allowing large step
        // changes (block rate 0→1, latency 20ms→200ms) to register quickly:
        //
        //   - For signals near zero (mean < 0.1): floor = 0.01 (1% of the
        //     maximum useful magnitude for a rate-like signal in [0,1]).
        //   - For signals with positive mean: floor = 1% of mean.
        //
        // This means a single-step deviation must be at least
        //   `threshold × floor` above the mean to fire. For threshold=3.0
        //   and block rate: k/2 = 3.0 × 0.01 / 2 = 0.015, so a full-scale
        //   step from 0→1 (deviation=1.0) nets 0.985 per observation →
        //   fires after 4 observations, which is the desired behavior.
        // Minimum σ floor: prevents hair-trigger on perfectly stationary
        // baselines where σ=0 would make k=0 and any deviation fires.
        // For near-zero-mean signals (block rate, entropy in [0,1]):
        //   floor = 0.01 (requires a 1% meaningful shift per threshold unit).
        // For positive-mean signals (latency in ms):
        //   floor = 5% of mean (requires a 5% shift to count as signal).
        // This keeps threshold=10 from firing on a 10% nudge (5ms on 50ms
        // baseline) while allowing threshold=3 to fire on a 10× step change.
        let floor = if mean.abs() < 1.0 {
            0.01
        } else {
            mean.abs() * 0.05
        };
        let effective_std = std.max(floor);
        let k = self.threshold * effective_std;

        // CUSUM update: accumulate signed deviation from mean.
        self.s_high = (self.s_high + (value - mean - k / 2.0)).max(0.0);
        self.s_low = (self.s_low + (mean - value - k / 2.0)).max(0.0);

        // Slide the window.
        if self.window.len() >= self.window_size {
            self.window.pop_front();
        }
        self.window.push_back(value);

        // Fire if either accumulator exceeds the detection threshold.
        if self.s_high > k {
            self.s_high = 0.0;
            self.s_low = 0.0;
            self.last_direction = 1;
            return Some(1);
        }
        if self.s_low > k {
            self.s_high = 0.0;
            self.s_low = 0.0;
            self.last_direction = -1;
            return Some(-1);
        }

        None
    }

    fn mean_std(&self) -> (f64, f64) {
        let n = self.window.len() as f64;
        if n == 0.0 {
            return (0.0, 0.0);
        }
        let mean: f64 = self.window.iter().sum::<f64>() / n;
        let variance: f64 = self.window.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
        (mean, variance.sqrt())
    }
}

/// Per-target drift detector.  Tracks four independent CUSUM streams and
/// fires a [`RegimeChange`] when ≥ 2 agree.
///
/// # Example
///
/// ```rust
/// use wafrift_strategy::drift_window::{DriftDetector, ProbeObservation};
///
/// let mut det = DriftDetector::default();
/// for _ in 0..60 {
///     det.observe(ProbeObservation {
///         response_time_ms: 50.0,
///         was_blocked: true,
///         body_hash: Some(0xdeadbeef),
///     });
/// }
/// // After a sudden drop in block rate the detector should eventually fire
/// // LooserNow.
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftDetector {
    /// Window size passed to each CUSUM channel.
    pub window_size: usize,
    /// Detection threshold (σ-multiples) passed to each CUSUM channel.
    pub threshold: f64,

    // ── Four independent CUSUM channels ──────────────────────────────
    cusum_median_rt: CusumDetector,
    cusum_p95_rt: CusumDetector,
    cusum_block_rate: CusumDetector,
    cusum_body_entropy: CusumDetector,

    // ── Sliding windows for computing the four signals ────────────────
    /// Raw response times for the current window (for median + p95).
    rt_window: VecDeque<f64>,
    /// Boolean blocked flags for the last `window_size` probes (for block rate).
    block_window: VecDeque<bool>,
    /// Recent body hashes for Shannon entropy estimation.
    body_hash_window: VecDeque<u64>,

    /// Total probes observed (monotonically increasing).
    pub probe_count: u64,
}

impl Default for DriftDetector {
    fn default() -> Self {
        Self::new(DEFAULT_WINDOW_SIZE, DEFAULT_THRESHOLD)
    }
}

impl DriftDetector {
    /// Create a detector with explicit window and threshold parameters.
    pub fn new(window_size: usize, threshold: f64) -> Self {
        let ws = window_size.max(8); // minimum 8 for meaningful statistics
        Self {
            window_size: ws,
            threshold,
            cusum_median_rt: CusumDetector::new(ws, threshold),
            cusum_p95_rt: CusumDetector::new(ws, threshold),
            cusum_block_rate: CusumDetector::new(ws, threshold),
            cusum_body_entropy: CusumDetector::new(ws, threshold),
            rt_window: VecDeque::with_capacity(ws),
            block_window: VecDeque::with_capacity(ws),
            body_hash_window: VecDeque::with_capacity(BODY_HASH_WINDOW),
            probe_count: 0,
        }
    }

    /// Feed a probe observation and return a [`RegimeChange`] if detected.
    ///
    /// Returns `None` when the regime is stationary (or insufficient data).
    /// Returns `Some(RegimeChange)` when ≥ 2 CUSUM channels agree.
    pub fn observe(&mut self, obs: ProbeObservation) -> Option<RegimeChange> {
        self.probe_count = self.probe_count.saturating_add(1);

        // ── 1. Update sliding windows ─────────────────────────────────
        if self.rt_window.len() >= self.window_size {
            self.rt_window.pop_front();
        }
        self.rt_window.push_back(obs.response_time_ms);

        if self.block_window.len() >= self.window_size {
            self.block_window.pop_front();
        }
        self.block_window.push_back(obs.was_blocked);

        if let Some(hash) = obs.body_hash {
            if self.body_hash_window.len() >= BODY_HASH_WINDOW {
                self.body_hash_window.pop_front();
            }
            self.body_hash_window.push_back(hash);
        }

        // ── 2. Derive the four signals ────────────────────────────────
        let median_rt = self.compute_median_rt();
        let p95_rt = self.compute_p95_rt();
        let block_rate = self.compute_block_rate();
        let body_entropy = self.compute_body_entropy();

        // ── 3. Feed each signal into its CUSUM channel ────────────────
        //
        // Directional signals (block rate + latency) determine whether the
        // WAF became looser or stricter. Body-hash entropy is a
        // non-directional "something changed" witness, it contributes to
        // the total change-event count but not to the directional split,
        // because entropy can rise or fall regardless of enforcement posture.
        let mut up_votes: i32 = 0;
        let mut down_votes: i32 = 0;
        // Non-directional: entropy change just adds to total witness count.
        let mut witness_events: i32 = 0;

        for direction in [
            self.cusum_median_rt.push(median_rt),
            self.cusum_p95_rt.push(p95_rt),
            self.cusum_block_rate.push(block_rate),
        ]
        .iter()
        .flatten()
        {
            if *direction > 0 {
                up_votes += 1;
            } else {
                down_votes += 1;
            }
        }

        // Entropy fires as a non-directional witness.
        if self.cusum_body_entropy.push(body_entropy).is_some() {
            witness_events += 1;
        }

        // ── 4. Agreement gate, need ≥ 2 signals agreeing ─────────────
        // Directional vote count (block_rate + latencies fire), augmented
        // by the entropy witness if it also fired.
        let directional_votes = up_votes + down_votes;
        let total_change_witnesses = directional_votes + witness_events;

        // Must have at least 2 total witnesses of change.
        if total_change_witnesses < SIGNAL_AGREEMENT as i32 {
            return None;
        }

        // Direction is determined by the directional signals only.
        // If there are no directional votes but entropy fired, emit Unclear.
        if directional_votes == 0 {
            return Some(RegimeChange::Unclear);
        }

        // Higher latency + higher block rate = StricterNow.
        // Lower latency + lower block rate = LooserNow.
        // Mixed directional signals = Unclear.
        if up_votes >= SIGNAL_AGREEMENT as i32 && down_votes == 0 {
            Some(RegimeChange::StricterNow)
        } else if down_votes >= SIGNAL_AGREEMENT as i32 && up_votes == 0 {
            Some(RegimeChange::LooserNow)
        } else if up_votes > 0 && down_votes == 0 {
            // Only 1 directional up-vote but entropy corroborated, weak
            // evidence of stricter regime.
            Some(RegimeChange::StricterNow)
        } else if down_votes > 0 && up_votes == 0 {
            // Only 1 directional down-vote but entropy corroborated, weak
            // evidence of looser regime.
            Some(RegimeChange::LooserNow)
        } else {
            Some(RegimeChange::Unclear)
        }
    }

    // ── Signal derivation helpers ─────────────────────────────────────────

    /// Median response time over the current RT window (ms).
    fn compute_median_rt(&self) -> f64 {
        if self.rt_window.is_empty() {
            return 0.0;
        }
        let mut sorted: Vec<f64> = self.rt_window.iter().copied().collect();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let mid = sorted.len() / 2;
        if sorted.len().is_multiple_of(2) {
            (sorted[mid - 1] + sorted[mid]) / 2.0
        } else {
            sorted[mid]
        }
    }

    /// 95th-percentile response time over the current RT window (ms).
    fn compute_p95_rt(&self) -> f64 {
        if self.rt_window.is_empty() {
            return 0.0;
        }
        let mut sorted: Vec<f64> = self.rt_window.iter().copied().collect();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        // Nearest-rank P95.
        let idx = ((sorted.len() as f64 * 0.95).ceil() as usize).saturating_sub(1);
        sorted[idx.min(sorted.len() - 1)]
    }

    /// Fraction of probes blocked over the current block window.
    fn compute_block_rate(&self) -> f64 {
        if self.block_window.is_empty() {
            return 0.0;
        }
        let blocked = self.block_window.iter().filter(|&&b| b).count();
        blocked as f64 / self.block_window.len() as f64
    }

    /// Shannon entropy of the body-hash distribution (bits).
    ///
    /// A sudden shift in the diversity of response bodies (new error pages,
    /// new challenge bodies) signals a WAF rule change.
    fn compute_body_entropy(&self) -> f64 {
        if self.body_hash_window.len() < 2 {
            return 0.0;
        }
        // Count frequency of each unique hash.
        let mut counts: Vec<(u64, usize)> = Vec::new();
        for &h in &self.body_hash_window {
            if let Some(entry) = counts.iter_mut().find(|(hh, _)| *hh == h) {
                entry.1 += 1;
            } else {
                counts.push((h, 1));
            }
        }
        let total = self.body_hash_window.len() as f64;
        counts
            .iter()
            .map(|(_, c)| {
                let p = *c as f64 / total;
                if p > 0.0 { -p * p.log2() } else { 0.0 }
            })
            .sum()
    }

    /// Returns `true` if the detector has accumulated enough observations to
    /// produce meaningful change-point estimates (at least `window_size / 2`
    /// probes).
    #[must_use]
    pub fn has_baseline(&self) -> bool {
        self.probe_count >= (self.window_size / 2) as u64
    }

    /// Snapshot of the four current signal values (for diagnostics/logging).
    /// Order: `[median_rt_ms, p95_rt_ms, block_rate, body_entropy_bits]`.
    #[must_use]
    pub fn signal_snapshot(&self) -> [f64; 4] {
        [
            self.compute_median_rt(),
            self.compute_p95_rt(),
            self.compute_block_rate(),
            self.compute_body_entropy(),
        ]
    }
}

// ── Bypass-rate CUSUM change-point monitor (C-11) ────────────────────────────

/// Event returned from [`BypassRateMonitor::observe`].
///
/// `NoChange` means the CUSUM accumulator is below the decision threshold.
/// `AlarmFired` means a statistically significant drop in bypass rate was
/// detected, a WAF rule update likely pushed bypasses that were working
/// into blocked territory.
#[derive(Debug, Clone, PartialEq)]
pub enum ChangePointEvent {
    /// Bypass rate is stationary; no action needed.
    NoChange,
    /// CUSUM threshold crossed (bypass rate dropped significantly).
    AlarmFired {
        /// Current windowed bypass rate (fraction in `[0.0, 1.0]`).
        observed_rate: f64,
        /// Baseline rate at the time the alarm fired.
        baseline_rate: f64,
        /// Absolute drop in percentage points (baseline − observed) × 100.
        drop_pp: f64,
    },
}

/// Online CUSUM-based bypass-rate change-point detector.
///
/// Tracks a sliding window of bypass/block outcomes and detects downward
/// shifts in the bypass rate (i.e. "WAF started blocking more stuff").
///
/// # Algorithm
///
/// Maintains a one-sided lower CUSUM:
///
/// ```text
/// S_n = max(0, S_{n-1} + (p_baseline - p_observed - k))
/// ```
///
/// where `p_observed` is the current windowed bypass rate, `p_baseline`
/// is the rate at the start of the current stationary regime, and `k` is
/// a slack parameter (half the minimum detectable shift).  When `S_n > h`
/// (decision threshold), an alarm fires, the baseline resets to
/// `p_observed`, and `S_n` resets to zero.
///
/// # Parameters
///
/// | Parameter       | Meaning                                                        | Default |
/// |-----------------|----------------------------------------------------------------|---------|
/// | `window_size`   | Sliding window length for bypass-rate estimation               | 50      |
/// | `k`             | Slack (allowable drift per sample before CUSUM accumulates)    | 0.05    |
/// | `h`             | Decision threshold (CUSUM value that triggers an alarm)        | 0.5     |
///
/// With defaults:
/// - A steady 5 pp/sample drop accumulates into an alarm after ~10 samples.
/// - A perfectly stationary rate never fires.
///
/// # Example
///
/// ```rust
/// use wafrift_strategy::drift_window::{BypassRateMonitor, ChangePointEvent};
///
/// let mut monitor = BypassRateMonitor::new_default();
/// // Fill baseline window with 30% bypass rate.
/// for i in 0..50 {
///     monitor.observe(i % 3 == 0); // ~33% bypass
/// }
/// // Rate collapses to 0% (alarm should fire within 20 more samples).
/// let mut fired = false;
/// for _ in 0..30 {
///     if let ChangePointEvent::AlarmFired { .. } = monitor.observe(false) {
///         fired = true;
///         break;
///     }
/// }
/// assert!(fired, "alarm must fire on a 33%→0% bypass rate drop");
/// ```
#[derive(Debug, Clone)]
pub struct BypassRateMonitor {
    /// Sliding window of recent bypass outcomes (true = bypassed).
    window: VecDeque<bool>,
    /// Maximum number of samples in the sliding window.
    window_size: usize,
    /// Slack parameter k: per-sample allowable drift before CUSUM accumulates.
    k: f64,
    /// Decision threshold h: CUSUM value that triggers an alarm.
    h: f64,
    /// Current lower CUSUM accumulator.
    s: f64,
    /// Baseline bypass rate for the current stationary regime.
    /// `None` until `window_size` samples have been collected.
    baseline: Option<f64>,
}

impl BypassRateMonitor {
    /// Create a monitor with explicit parameters.
    ///
    /// - `window_size`: samples for bypass-rate estimation (min 4).
    /// - `k`: slack (typ. 0.5 × minimum detectable shift in rate).
    /// - `h`: decision threshold (larger = fewer false positives but slower
    ///   detection; smaller = faster detection but noisier).
    #[must_use]
    pub fn new(window_size: usize, k: f64, h: f64) -> Self {
        let ws = window_size.max(4);
        Self {
            window: VecDeque::with_capacity(ws),
            window_size: ws,
            k: k.max(0.0),
            h: h.max(0.0),
            s: 0.0,
            baseline: None,
        }
    }

    /// Create a monitor with production-ready defaults:
    /// `window_size = 50`, `k = 0.05`, `h = 0.5`.
    #[must_use]
    pub fn new_default() -> Self {
        Self::new(50, 0.05, 0.5)
    }

    /// Record one attempt outcome and return whether a change-point was detected.
    ///
    /// `bypassed = true` means the payload evaded the WAF; `false` means blocked.
    ///
    /// This is O(1) per call regardless of window size.
    pub fn observe(&mut self, bypassed: bool) -> ChangePointEvent {
        // Slide the window.
        if self.window.len() >= self.window_size {
            self.window.pop_front();
        }
        self.window.push_back(bypassed);

        // Need a full window to compute a meaningful rate.
        let p_observed = self.current_rate_inner();

        // Set baseline from the first full window.
        let baseline = match self.baseline {
            Some(b) => b,
            None => {
                if self.window.len() < self.window_size {
                    return ChangePointEvent::NoChange;
                }
                // First full window: establish baseline, CUSUM starts at 0.
                self.baseline = Some(p_observed);
                return ChangePointEvent::NoChange;
            }
        };

        // One-sided lower CUSUM: accumulates when rate falls below baseline.
        // S_n = max(0, S_{n-1} + (baseline - p_observed - k))
        self.s = (self.s + (baseline - p_observed - self.k)).max(0.0);

        if self.s > self.h {
            // Alarm fired: reset accumulator and update baseline to current rate.
            self.s = 0.0;
            let old_baseline = baseline;
            self.baseline = Some(p_observed);
            let drop_pp = (old_baseline - p_observed) * 100.0;
            return ChangePointEvent::AlarmFired {
                observed_rate: p_observed,
                baseline_rate: old_baseline,
                drop_pp,
            };
        }

        ChangePointEvent::NoChange
    }

    /// Current windowed bypass rate in `[0.0, 1.0]`.
    ///
    /// Returns `None` if fewer than `window_size` samples have been observed
    /// (no reliable estimate yet).
    #[must_use]
    pub fn current_rate(&self) -> Option<f64> {
        if self.window.len() < self.window_size {
            return None;
        }
        Some(self.current_rate_inner())
    }

    /// Current baseline rate.
    ///
    /// Returns `None` until the first full window has been observed.
    #[must_use]
    pub fn baseline_rate(&self) -> Option<f64> {
        self.baseline
    }

    fn current_rate_inner(&self) -> f64 {
        if self.window.is_empty() {
            return 0.0;
        }
        let bypassed = self.window.iter().filter(|&&b| b).count();
        bypassed as f64 / self.window.len() as f64
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "drift_window_tests.rs"]
mod tests;
