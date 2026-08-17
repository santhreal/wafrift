//! Per-rule WAF-bypass corpus (persistent {rule_id → bucket} store).
//!
//! `super::coverage_feedback` tracks rule_id observations in process
//! memory for the current bench run. This module persists the
//! richer corpus across runs:
//!
//! - The **payload bytes** that triggered each rule (not just the
//!   descriptor (actual reproducible bytes)).
//! - The **encoding/grammar/smuggling chain** that produced the payload
//!   so the operator can rebuild any variant by name.
//! - The **bypass set** per rule, payloads that the WAF passed
//!   (the only payloads with bounty value).
//! - **Submission status** tracking the bounty lifecycle (Queued →
//!   Submitted → Accepted / Duplicate / Rejected) so `wafrift harvest`
//!   skips already-handled bypasses. wafrift never auto-files, filing is
//!   a deliberate, one-at-a-time `wafrift submit` step.
//! - **Drift timestamps** so `super::dilution` / `super::coverage_feedback`
//!   can re-fire bypasses around CF Auto-Tune retrain windows.
//!
//! ## Why a separate module
//!
//! `coverage_feedback` is in the MAP-Elites hot path, every probe
//! response updates it. We do NOT want disk I/O in that loop. The
//! corpus is the **persistence layer**: written at round boundaries
//! (every N probes, or on shutdown). The in-memory `RuleCoverage`
//! observes; the on-disk `RuleBypassCorpus` accumulates.
//!
//! ## Target fingerprint
//!
//! One corpus per TARGET. Cloudflare's Managed Ruleset against
//! `bench/cf-real/` is a different rule surface from AWS WAF's
//! `AWSManagedRulesCommonRuleSet`. The corpus carries a
//! `target_fingerprint` (typically `<vendor>:<ruleset-version>:<host>`)
//! so cross-pollution between targets is impossible.
//!
//! ## File format
//!
//! JSON, schema-versioned. Field additions are backwards-compatible
//! via serde defaults. Schema bumps require an explicit migration in
//! `RuleBypassCorpus::load_or_default`.
//!
//! ## Concurrency
//!
//! Mid-hunt, multiple async workers may want to write the corpus.
//! `RuleBypassCorpus::save_atomic` writes to a tempfile in the
//! same directory then renames: POSIX rename is atomic on the same
//! filesystem. Callers serialize their writes with a `Mutex` at the
//! orchestrator level; the file itself is not a synchronization
//! primitive.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::coverage_feedback::{PayloadClass, RuleId};

/// Current on-disk corpus schema version. Bump when a non-additive
/// field change lands; older files load via the upgrade path.
pub const CORPUS_SCHEMA_VERSION: u32 = 1;

/// One attack-payload recorded against a WAF rule.
///
/// Distinguished from [`RecordedBypass`] in two ways:
///
/// 1. **Verdict**: a `RecordedAttempt` was blocked. A `RecordedBypass`
///    was passed.
/// 2. **Submission lifecycle**: only bypasses have submission status
///    fields; blocks are tracked for "we've seen this fail before,
///    don't retry until drift."
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedAttempt {
    /// The payload bytes as sent on the wire (after every encoder /
    /// grammar mutation / smuggling wrap).
    pub payload: String,
    /// Attack class (`sql`, `xss`, `cmd`, …) so the corpus can
    /// answer "what classes have we explored against rule X."
    pub payload_class: PayloadClass,
    /// Ordered list of technique identifiers applied to produce this
    /// payload. Operator can rebuild the variant by replaying the chain.
    pub encoding_chain: Vec<String>,
    /// Hash of the response body, collapses near-identical "Sorry,
    /// you have been blocked" pages so the corpus stays compact.
    pub response_hash: u64,
    /// Epoch seconds at observation.
    pub observed_at_secs: u64,
}

/// A confirmed WAF bypass, the WAF passed this payload through to
/// origin (verified by the oracle).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedBypass {
    /// The payload that bypassed.
    pub payload: String,
    pub payload_class: PayloadClass,
    pub encoding_chain: Vec<String>,
    pub response_hash: u64,
    pub observed_at_secs: u64,
    /// Lifecycle status of the bounty submission.
    #[serde(default)]
    pub submission: SubmissionStatus,
    /// Serialized delivery shape that produced this bypass, the EXACT
    /// `(method, path, headers, body)` envelope the winning probe used,
    /// JSON-encoded (`wafrift_grammar::grammar::equiv::DeliveryShape`).
    /// `wafrift harvest` deserializes it to re-fire the *same* request
    /// instead of guessing across standard shapes, the difference
    /// between a recorded number and a reproducible, submittable bypass.
    ///
    /// Stored as an opaque `String` (not the typed shape) so this crate
    /// stays decoupled from the grammar crate, the same deliberate
    /// decoupling as [`Self::encoding_chain`]. Empty for bypasses
    /// recorded before delivery capture, or by strategies with no
    /// equivalence shape; harvest falls back to standard shapes then.
    #[serde(default)]
    pub delivery: String,
}

/// HackerOne submission lifecycle for a single bypass.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "stage", content = "data")]
pub enum SubmissionStatus {
    /// Just discovered; awaiting the dry-run grace window.
    #[default]
    Queued,
    /// Held until `release_at_secs` epoch, first 24h of any new
    /// bypass goes here so we don't fire submissions at 3am.
    DryRunHold { release_at_secs: u64 },
    /// Sent to HackerOne, awaiting triage. `report_id` is the H1
    /// report number.
    Submitted { report_id: String },
    /// H1 accepted the report. `report_id` retained for tracking.
    Accepted { report_id: String },
    /// H1 marked duplicate of a prior report.
    Duplicate { duplicate_of: String },
    /// H1 rejected (informative / NA / out-of-scope).
    Rejected { reason: String },
}

/// All recorded attempts and bypasses for ONE WAF rule.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleBucket {
    /// Rule identifier the corpus is keyed on. Stored redundantly so
    /// a bucket extracted from the map stays self-describing.
    pub rule_id: RuleId,
    /// Optional human-readable rule name when the WAF exposes one
    /// (e.g. CRS rule "942100: SQL Injection Attack: Detected").
    #[serde(default)]
    pub description: Option<String>,
    /// Payloads that triggered this rule.
    #[serde(default)]
    pub blocked: Vec<RecordedAttempt>,
    /// Payloads that bypassed this rule (passed through to origin).
    #[serde(default)]
    pub bypassed: Vec<RecordedBypass>,
    /// Epoch seconds of last detected ruleset drift, when CF
    /// Auto-Tune retrains, this updates and previously-blocked
    /// payloads become retry-eligible.
    #[serde(default)]
    pub last_drift_at_secs: Option<u64>,
}

/// The full persistent corpus, indexed by rule_id.
///
/// Cheap to clone (BTreeMap of buckets); meant to be held by the
/// hunt orchestrator + read by the bench reporter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleBypassCorpus {
    /// Schema version, load_or_default uses this to migrate older
    /// formats. Always [`CORPUS_SCHEMA_VERSION`] on save.
    #[serde(default)]
    pub schema_version: u32,
    /// Target fingerprint: `<vendor>:<ruleset>:<host>`. Two
    /// fingerprints share no buckets; protect against cross-target
    /// pollution.
    pub target_fingerprint: String,
    /// rule_id → bucket. BTreeMap so iteration is deterministic
    /// (the bench-result determinism contract per Sonnet B's work
    /// extends to this corpus's serialization).
    #[serde(default)]
    pub buckets: BTreeMap<String, RuleBucket>,
    /// Epoch seconds at last save.
    #[serde(default)]
    pub last_saved_at_secs: u64,
}

impl RuleBypassCorpus {
    /// Create a new empty corpus for the given target fingerprint.
    #[must_use]
    pub fn new(target_fingerprint: impl Into<String>) -> Self {
        Self {
            schema_version: CORPUS_SCHEMA_VERSION,
            target_fingerprint: target_fingerprint.into(),
            buckets: BTreeMap::new(),
            last_saved_at_secs: 0,
        }
    }

    /// Maximum corpus size we will read into memory. The corpus is
    /// operator-private, self-authored state (NOT an untrusted download),
    /// so the decompression-bomb threat model behind `safe_io` does not
    /// apply, this ceiling only bounds memory on a pathologically huge
    /// file and sits far above any real corpus. A file larger than this
    /// is *preserved* (moved aside), never silently dropped. (§15 / §1)
    const CORPUS_READ_CEILING_BYTES: usize = 1024 * 1024 * 1024; // 1 GiB

    /// Load from disk, **never destroying recoverable data**.
    ///
    /// Return a fresh corpus ONLY when the file genuinely does not exist
    /// or is empty (first run for this target). Every OTHER outcome on an
    /// *existing, non-empty* file is treated as recoverable bounty data
    /// that must survive:
    ///
    /// - **Too large to read / I-O error** → the file is moved aside to
    ///   `<path>.corrupt-<epoch>` (so a later save can't overwrite it)
    ///   and a loud warning is printed before a fresh corpus is returned.
    /// - **Won't parse** (schema drift, truncation, corruption) → same
    ///   preserve-aside-then-fresh path.
    /// - **Parses, but bloated** → recompacted in memory (per-bucket caps
    ///   re-applied) and returned intact; the next save reclaims the bloat.
    ///   No bypass is ever lost, bypasses are capped generously, far
    ///   above any real hunt.
    ///
    /// This is the fix for the recurring "corpus disappeared" data loss:
    /// the old code returned an empty `Self::new(...)` on ANY read/parse
    /// failure, and the next `save_atomic` atomically overwrote the real
    /// corpus with nothing. A load failure must never silently become an
    /// empty corpus the next save destroys.
    ///
    /// `target_fingerprint` is used only when the file is absent/empty or
    /// had to be preserved-and-rebuilt, when the file IS valid its
    /// embedded fingerprint wins (callers should verify the fingerprint
    /// matches what they expect via [`Self::target_fingerprint`]).
    pub fn load_or_default(path: &Path, target_fingerprint: impl Into<String>) -> Self {
        // A genuinely missing file is a legitimate fresh start.
        if !path.exists() {
            return Self::new(target_fingerprint);
        }
        let raw = match crate::safe_io::read_capped_text(path, Self::CORPUS_READ_CEILING_BYTES) {
            Ok(s) => s,
            Err(e) => {
                // Oversize or I-O error on an existing file. We can't
                // read it, but we must NOT let the next save clobber it.
                preserve_unreadable_corpus(path, &format!("read failed: {e}"));
                return Self::new(target_fingerprint);
            }
        };
        // An empty / whitespace-only file is equivalent to absent, a
        // fresh start, with no noisy preserve-aside.
        if raw.trim().is_empty() {
            return Self::new(target_fingerprint);
        }
        match serde_json::from_str::<Self>(&raw) {
            Ok(mut corpus) => {
                if corpus.schema_version == 0 {
                    corpus.schema_version = CORPUS_SCHEMA_VERSION;
                }
                // Recompact a pre-cap / bloated corpus: truncate each
                // bucket to the respective cap on load so the next save
                // reclaims the bloat. Keeps the earliest coverage and
                // harvest samples; bypasses are capped generously so no
                // real harvest material is lost. (§15/§1)
                for bucket in corpus.buckets.values_mut() {
                    bucket.blocked.truncate(Self::MAX_BLOCKED_PER_BUCKET);
                    bucket.bypassed.truncate(Self::MAX_BYPASSED_PER_BUCKET);
                }
                corpus
            }
            Err(e) => {
                // The file exists and is non-empty but won't parse. DO
                // NOT return an empty corpus the next save would write
                // over the original (preserve the bytes aside first).
                preserve_unreadable_corpus(path, &format!("parse failed: {e}"));
                Self::new(target_fingerprint)
            }
        }
    }

    /// Save atomically via tempfile + rename. Returns an error only on
    /// I/O failure; the rename itself is atomic on the same filesystem
    /// so a concurrent reader either sees the prior snapshot or this
    /// one (never a torn write).
    pub fn save_atomic(&self, path: &Path) -> std::io::Result<()> {
        // Rolling backup: before replacing an existing non-empty corpus,
        // snapshot it to `<path>.bak`. One bad save, a logic regression,
        // a parse-fail-induced empty reload that slipped past the loader's
        // preserve guard, a schema drift, is then always one step
        // recoverable. The corpus is irreplaceable bounty data. (§15/§1)
        backup_before_overwrite(path);
        let mut snap = self.clone();
        snap.schema_version = CORPUS_SCHEMA_VERSION;
        snap.last_saved_at_secs = current_epoch_secs();
        let body = serde_json::to_vec_pretty(&snap)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        // R55 pass-19 I4 (CLAUDE.md §7 DEDUP): route through the
        // workspace's canonical atomic writer so the mkdir-parent,
        // unique-tmp-name, fsync, rename(2) sequence lives in ONE
        // place. Pre-fix this module + edge_pop_coverage + h1_dedup
        // each had their own subtly different copy.
        wafrift_types::loaders::write_atomic(path, &body)
    }

    /// Get or insert the bucket for `rule_id`. Cheap because we hand
    /// out a `&mut RuleBucket` instead of cloning.
    pub fn bucket_mut(&mut self, rule_id: &str) -> &mut RuleBucket {
        self.buckets
            .entry(rule_id.to_string())
            .or_insert_with(|| RuleBucket {
                rule_id: RuleId::new(rule_id),
                ..RuleBucket::default()
            })
    }

    /// Max BLOCKED samples retained per rule bucket. Blocked payloads are a
    /// rule-coverage sample, not harvest material (bypasses are uncapped), so a
    /// few hundred per rule fully characterise what a rule blocks. The cap
    /// bounds three real costs a 62 MB CumulusFire corpus surfaced via dogfood
    /// (§15 / §1): corpus growth toward `RULE_CORPUS_MAX_BYTES` (past which the
    /// whole corpus is lost on the next `load_or_default`), `save_atomic` write
    /// size, and the O(n) dedup scan below, which would otherwise make the hot
    /// record path O(n²) over a long hunt.
    const MAX_BLOCKED_PER_BUCKET: usize = 512;

    /// Max BYPASSED samples retained per rule bucket. Bypasses are the primary
    /// harvest material so the cap is generous (8× the blocked cap), but it is
    /// still finite: an adversarial response-varying WAF can grow `bypassed`
    /// without bound, eventually pushing the corpus past `RULE_CORPUS_MAX_BYTES`
    ///: at which point `load_or_default` silently discards the WHOLE corpus
    /// (total data-loss). This cap bounds growth far below that cliff while
    /// preserving virtually all real harvest material encountered in practice.
    /// `load_or_default` truncates over-cap buckets on load to heal corpora
    /// written before this cap was introduced.
    const MAX_BYPASSED_PER_BUCKET: usize = 4096;

    /// Record a payload that the WAF BLOCKED, tagged with the rule_id
    /// it triggered (if the oracle could attribute it).
    pub fn record_block(
        &mut self,
        rule_id: &str,
        payload: &str,
        payload_class: PayloadClass,
        encoding_chain: Vec<String>,
        response_hash: u64,
    ) {
        let entry = RecordedAttempt {
            payload: payload.to_string(),
            payload_class,
            encoding_chain,
            response_hash,
            observed_at_secs: current_epoch_secs(),
        };
        let bucket = self.bucket_mut(rule_id);
        // Coverage cap: once a rule has MAX_BLOCKED_PER_BUCKET samples we have
        // characterised what it blocks; stop recording blocked payloads to bound
        // corpus growth and keep the dedup scan below O(cap), not O(n). Bypasses
        // have their own generous cap (MAX_BYPASSED_PER_BUCKET). (§15/§1)
        if bucket.blocked.len() >= Self::MAX_BLOCKED_PER_BUCKET {
            return;
        }
        // Dedup by (response_hash, payload) so re-running the same
        // bench doesn't bloat the file.
        if !bucket
            .blocked
            .iter()
            .any(|a| a.response_hash == entry.response_hash && a.payload == entry.payload)
        {
            bucket.blocked.push(entry);
        }
    }

    /// Record a payload that BYPASSED the WAF. The default submission
    /// status is `Queued`; callers can transition via
    /// [`Self::set_submission`].
    pub fn record_bypass(
        &mut self,
        rule_id: &str,
        payload: &str,
        payload_class: PayloadClass,
        encoding_chain: Vec<String>,
        response_hash: u64,
    ) {
        let entry = RecordedBypass {
            payload: payload.to_string(),
            payload_class,
            encoding_chain,
            response_hash,
            observed_at_secs: current_epoch_secs(),
            submission: SubmissionStatus::Queued,
            delivery: String::new(),
        };
        let bucket = self.bucket_mut(rule_id);
        // Generous cap: 4 096 bypasses per rule is far more than any real hunt
        // accumulates, but bounds corpus growth away from the 128 MiB load cliff
        // that would silently discard the whole corpus (§15 / §1).
        if bucket.bypassed.len() >= Self::MAX_BYPASSED_PER_BUCKET {
            return;
        }
        if !bucket
            .bypassed
            .iter()
            .any(|b| b.response_hash == entry.response_hash && b.payload == entry.payload)
        {
            bucket.bypassed.push(entry);
        }
    }

    /// Mark a ruleset drift event on a specific rule (e.g. CF
    /// Auto-Tune retrain detected via [`crate::dilution`]'s drift
    /// detector). Triggers "retry the blocked corpus" downstream.
    pub fn mark_drift(&mut self, rule_id: &str) {
        let bucket = self.bucket_mut(rule_id);
        bucket.last_drift_at_secs = Some(current_epoch_secs());
    }

    /// Update the submission status of a previously-recorded bypass.
    /// Returns `true` if the bypass was found and updated.
    pub fn set_submission(
        &mut self,
        rule_id: &str,
        payload: &str,
        new_status: SubmissionStatus,
    ) -> bool {
        if let Some(bucket) = self.buckets.get_mut(rule_id)
            && let Some(b) = bucket.bypassed.iter_mut().find(|b| b.payload == payload)
        {
            b.submission = new_status;
            return true;
        }
        false
    }

    /// Attach the serialized delivery shape (see [`RecordedBypass::delivery`])
    /// to a previously-recorded bypass. Returns `true` if the bypass was
    /// found and updated.
    ///
    /// Recorded as a separate step after [`Self::record_bypass`] so the
    /// hot record path (which dedups by `(response_hash, payload)`) stays
    /// unchanged: the recorder calls this once, immediately after the
    /// write, with the shape the winning probe used. A blank `delivery`
    /// is never written (only a non-empty shape overwrites).
    pub fn set_delivery(&mut self, rule_id: &str, payload: &str, delivery: String) -> bool {
        if delivery.is_empty() {
            return false;
        }
        if let Some(bucket) = self.buckets.get_mut(rule_id)
            && let Some(b) = bucket.bypassed.iter_mut().find(|b| b.payload == payload)
        {
            b.delivery = delivery;
            return true;
        }
        false
    }

    /// Rules with fewer than `min_attempts` recorded blocks AND zero
    /// bypasses. The hunt orchestrator targets these first, they're
    /// the unexplored cells of the (rule_id × class) grid.
    #[must_use]
    pub fn unexplored_rules(&self, min_attempts: usize) -> Vec<String> {
        self.buckets
            .iter()
            .filter(|(_, b)| b.blocked.len() < min_attempts && b.bypassed.is_empty())
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Rules where drift was detected within the last `window_secs`
    /// AND there are blocked payloads worth re-firing.
    #[must_use]
    pub fn rules_due_for_retry(&self, window_secs: u64) -> Vec<String> {
        let now = current_epoch_secs();
        self.buckets
            .iter()
            .filter(|(_, b)| {
                b.last_drift_at_secs
                    .is_some_and(|d| now.saturating_sub(d) <= window_secs)
                    && !b.blocked.is_empty()
            })
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// All bypasses recorded against a specific rule (newest last
    /// per insertion order).
    #[must_use]
    pub fn bypasses_for_rule(&self, rule_id: &str) -> &[RecordedBypass] {
        self.buckets
            .get(rule_id)
            .map(|b| b.bypassed.as_slice())
            .unwrap_or(&[])
    }

    /// All blocked attempts recorded against a specific rule.
    #[must_use]
    pub fn blocked_for_rule(&self, rule_id: &str) -> &[RecordedAttempt] {
        self.buckets
            .get(rule_id)
            .map(|b| b.blocked.as_slice())
            .unwrap_or(&[])
    }

    /// Bypasses still in `Queued` status whose dry-run hold has
    /// expired (these are ready for submission to HackerOne).
    ///
    /// `default_dry_run_secs` is applied to bypasses still in
    /// `Queued` state whose `observed_at_secs + default_dry_run_secs`
    /// has passed (most operators leave bypasses queued without
    /// setting an explicit `DryRunHold` and rely on this default).
    #[must_use]
    pub fn novel_bypasses_pending_submission(
        &self,
        default_dry_run_secs: u64,
    ) -> Vec<(&str, &RecordedBypass)> {
        let now = current_epoch_secs();
        let mut out = vec![];
        for (rule_id, bucket) in &self.buckets {
            for b in &bucket.bypassed {
                let ready = match &b.submission {
                    SubmissionStatus::Queued => {
                        now.saturating_sub(b.observed_at_secs) >= default_dry_run_secs
                    }
                    SubmissionStatus::DryRunHold { release_at_secs } => now >= *release_at_secs,
                    _ => false,
                };
                if ready {
                    out.push((rule_id.as_str(), b));
                }
            }
        }
        out
    }

    /// Total bypass count across all rules.
    #[must_use]
    pub fn total_bypasses(&self) -> usize {
        self.buckets.values().map(|b| b.bypassed.len()).sum()
    }

    /// Total block count across all rules.
    #[must_use]
    pub fn total_blocks(&self) -> usize {
        self.buckets.values().map(|b| b.blocked.len()).sum()
    }

    /// Number of distinct rule_ids with at least one observation.
    #[must_use]
    pub fn rules_seen(&self) -> usize {
        self.buckets.len()
    }

    /// Summary suitable for the bench reporter, totals + per-class
    /// breakdown for quick "what did we learn" gut-check.
    #[must_use]
    pub fn summary(&self) -> CoverageSummary {
        let mut per_class: BTreeMap<String, ClassStats> = BTreeMap::new();
        for bucket in self.buckets.values() {
            for b in &bucket.blocked {
                let entry = per_class
                    .entry(b.payload_class.as_str().to_string())
                    .or_default();
                entry.blocks += 1;
            }
            for b in &bucket.bypassed {
                let entry = per_class
                    .entry(b.payload_class.as_str().to_string())
                    .or_default();
                entry.bypasses += 1;
            }
        }
        CoverageSummary {
            target_fingerprint: self.target_fingerprint.clone(),
            rules_seen: self.rules_seen(),
            total_blocks: self.total_blocks(),
            total_bypasses: self.total_bypasses(),
            per_class,
        }
    }
}

/// Per-class block/bypass counts for the corpus summary.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClassStats {
    pub blocks: usize,
    pub bypasses: usize,
}

/// What the bench reporter pulls when it wants a one-line gut-check
/// on the corpus state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageSummary {
    pub target_fingerprint: String,
    pub rules_seen: usize,
    pub total_blocks: usize,
    pub total_bypasses: usize,
    pub per_class: BTreeMap<String, ClassStats>,
}

/// Default disk location for the corpus: `~/.wafrift/corpus/<fingerprint>.json`.
/// Falls back to a `wafrift-bench/results/corpus/` directory under CWD when
/// the home directory can't be resolved.
#[must_use]
pub fn default_corpus_path(target_fingerprint: &str) -> PathBuf {
    let safe = sanitize_fingerprint_for_filename(target_fingerprint);
    if let Some(home) = dirs_home() {
        return home
            .join(".wafrift")
            .join("corpus")
            .join(format!("{safe}.json"));
    }
    PathBuf::from("wafrift-bench/results/corpus").join(format!("{safe}.json"))
}

/// Sanitize a fingerprint string for use as a filename, strips
/// path separators and other shell-hostile bytes.
///
/// Allows only `[A-Za-z0-9_-]`; every other character (including `.`)
/// becomes `_`. Excluding `.` prevents a crafted fingerprint such as
/// `..` from producing a `..`-bearing filename component, eliminating
/// even the theoretical path-traversal surface.
fn sanitize_fingerprint_for_filename(fp: &str) -> String {
    let sanitized: String = fp
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    // Short hash of the FULL fingerprint so fingerprints that differ
    // only in separator characters map to distinct filenames.
    let digest = Sha256::digest(fp.as_bytes());
    let short = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    format!("{sanitized}_{short:08x}")
}

fn current_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Move an existing-but-unreadable corpus file aside to a timestamped
/// sidecar (`<path>.corrupt-<epoch>`) so a subsequent `save_atomic` can
/// never overwrite it, and emit a loud warning naming the preserved file.
///
/// This is the load-side half of the corpus-durability guarantee: an
/// oversize / corrupt / unparseable corpus is *preserved*, never silently
/// discarded. Best-effort, if the file can't be moved aside we still
/// warn (and the save-side [`backup_before_overwrite`] guard provides a
/// second line of defence by copying the file to `<path>.bak` before any
/// overwrite). Never panics; the caller still receives a fresh corpus.
fn preserve_unreadable_corpus(path: &Path, reason: &str) {
    // Unique sidecar name (epoch + pid + nanos) so two corruption events within
    // the same wall-clock second can't collide, a second-granularity name
    // would let the second `rename` replace the first sidecar and lose the
    // earlier corrupt bytes. Mirrors the unique-tmp-name policy `write_atomic`
    // uses. (§15 / §1, never lose recoverable data.)
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut aside = path.as_os_str().to_owned();
    aside.push(format!(
        ".corrupt-{}-{}-{}",
        current_epoch_secs(),
        std::process::id(),
        nanos
    ));
    let aside = PathBuf::from(aside);
    match std::fs::rename(path, &aside) {
        Ok(()) => eprintln!(
            "wafrift: WARNING, corpus at {} could not be loaded ({reason}). \
             Your data was PRESERVED at {} and a fresh corpus was started. \
             Rename it back once the cause is addressed.",
            path.display(),
            aside.display(),
        ),
        Err(e) => eprintln!(
            "wafrift: ERROR, corpus at {} could not be loaded ({reason}) AND \
             could not be moved aside ({e}). Back this file up MANUALLY before \
             the next run, a save may otherwise overwrite it.",
            path.display(),
        ),
    }
}

/// Snapshot an existing non-empty corpus to `<path>.bak` before it is
/// overwritten by `RuleBypassCorpus::save_atomic`. Best-effort; never
/// blocks or fails the save. Empty/absent prior files are skipped (nothing
/// to protect). This is the save-side half of the durability guarantee.
fn backup_before_overwrite(path: &Path) {
    match std::fs::metadata(path) {
        Ok(meta) if meta.len() > 0 => {
            let mut bak = path.as_os_str().to_owned();
            bak.push(".bak");
            let _ = std::fs::copy(path, PathBuf::from(bak));
        }
        _ => {}
    }
}

fn dirs_home() -> Option<PathBuf> {
    // We don't take a hard dep on `dirs` here, read $HOME or
    // %USERPROFILE% directly. Keeps the crate's dep surface tight.
    if let Ok(h) = std::env::var("HOME")
        && !h.is_empty()
    {
        return Some(PathBuf::from(h));
    }
    if let Ok(h) = std::env::var("USERPROFILE")
        && !h.is_empty()
    {
        return Some(PathBuf::from(h));
    }
    None
}

#[cfg(test)]
#[path = "rule_corpus_tests.rs"]
mod tests;
