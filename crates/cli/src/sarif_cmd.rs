//! `wafrift sarif`: emit SARIF 2.1.0 from a `bench-waf --output` or
//! `scan --output` JSON file.
//!
//! SARIF (Static Analysis Results Interchange Format) is the
//! OASIS-standardised JSON for security-tool output. GitHub Advanced
//! Security, Azure DevOps, and most enterprise SAST/DAST UIs accept
//! SARIF natively, emitting it from wafrift's bypass JSON gives the
//! tool a first-class lane into enterprise scanning workflows
//! (PR-blocking checks, dashboards, alert routing) without anyone
//! writing a wafrift-specific parser.
//!
//! ## Input
//!
//! Accepts THREE wafrift output shapes:
//!
//! - **`bench-waf --output`** / **`scan --output`**: top-level
//!   `results` array. Each result with `evaded.variants_bypassed > 0`
//!   becomes one SARIF result.
//! - **`hunt --campaign-id`** state files (`~/.wafrift/hunt-*.json`):
//!   top-level `bypasses` array (`CampaignBypass` items with
//!   `class`/`technique`/`round`/`discovered_at`). Each entry becomes
//!   one SARIF result.
//!
//! If neither key is present, the command emits a SARIF envelope with
//! an empty `results` array AND exits 2 (anti-rig, silent success on
//! schema-mismatch was the dogfood report's BUG-1+2). Use `--quiet`
//! to suppress the stderr warning and stick with exit 0 if you
//! deliberately want an empty SARIF (e.g., CI gate that runs even on
//! a clean campaign).
//!
//! ## Output schema
//!
//! ```json
//! {
//!   "version": "2.1.0",
//!   "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
//!   "runs": [{
//!     "tool": { "driver": { "name": "wafrift", "version": "<crate version>" } },
//!     "results": [
//!       {
//!         "ruleId": "waf-bypass-sql",
//!         "level": "error",
//!         "message": { "text": "WAF bypass confirmed (sql) via tamper/comment, encoding/url/double" },
//!         "locations": [
//!           { "physicalLocation": { "artifactLocation": { "uri": "https://target.example/login" } } }
//!         ],
//!         "properties": {
//!           "class": "sql",
//!           "case_id": "sql_blind_001",
//!           "techniques": ["tamper/comment", "encoding/url/double"],
//!           "variants_bypassed": 2
//!         }
//!       }
//!     ]
//!   }]
//! }
//! ```
//!
//! ## Reserved-rule-ID contract (LAW 2)
//!
//! `ruleId` is `waf-bypass-<class>` where `<class>` is the lower-cased
//! attack class (sql, xss, cmdi, …). Adding a new class is additive;
//! renaming any existing class would break consumers that filter on
//! `ruleId`: DON'T do it.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Args;
use colored::Colorize;
use serde::Serialize;
use serde_json::Value;

/// SARIF 2.1.0 schema URI (OASIS Committee Specification 02). LAW 2:
/// pinned constant, downstream consumers may use this URI to detect
/// the schema variant; changing it is a breaking change.
const SARIF_SCHEMA_URI: &str =
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json";

/// SARIF format version string. LAW 2: pinned, emitting an older or
/// newer version silently would break consumers' validators.
const SARIF_VERSION: &str = "2.1.0";

/// Reuse the cluster_cmd 256 MiB cap, same operator-typo defence
/// (e.g. `--input /dev/zero`).
const SARIF_INPUT_MAX_BYTES: usize = 256 * 1024 * 1024;

/// Default placeholder URI when the input JSON has no target URL.
/// Bench corpus runs against a synthetic httpbin testbed and don't
/// carry a real per-result URL; SARIF *requires* an `artifactLocation`,
/// so the bench data hashes into this stable placeholder so consumer
/// dedup logic still works.
const SARIF_BENCH_TARGET_PLACEHOLDER: &str = "urn:wafrift:bench-corpus";

#[derive(Args, Debug)]
pub(crate) struct SarifArgs {
    /// Path to a wafrift output JSON. Accepted shapes:
    ///   - `bench-waf --output <FILE>` / `scan --output <FILE>` (top-level `results` array)
    ///   - `hunt --campaign-id <ID>` state file `~/.wafrift/hunt-<ID>.json` (top-level `bypasses` array)
    /// Pass `-` to read from stdin (`wafrift scan ... | wafrift sarif -`).
    #[arg(value_name = "FILE")]
    pub input: PathBuf,

    /// Target URL associated with this run. When the input is a
    /// `scan --output` or `hunt` state it usually carries `target_url`
    /// already, but the bench corpus does not, use this flag to
    /// attach the URL of the WAF you were attacking so SARIF
    /// consumers (GitHub Code Scanning, etc.) get a real location to
    /// render.
    #[arg(long)]
    pub target_url: Option<String>,

    /// Suppress stderr warnings when the input JSON has no recognised
    /// bypass key (`results` or `bypasses`), emits an empty SARIF
    /// envelope with exit 0 instead of exit 2. Use for CI gates that
    /// run even on a clean campaign.
    #[arg(long, default_value_t = false)]
    pub quiet: bool,
}

// ─── SARIF types (serde-friendly subset of v2.1.0) ──────────────────────────

#[derive(Debug, Serialize)]
struct SarifLog<'a> {
    version: &'static str,
    #[serde(rename = "$schema")]
    schema: &'static str,
    runs: Vec<SarifRun<'a>>,
}

#[derive(Debug, Serialize)]
struct SarifRun<'a> {
    tool: SarifTool<'a>,
    results: Vec<SarifResult>,
    /// SARIF 2.1.0 §3.18.3: maps `result.taxa[].toolComponent.name`
    /// references onto the CWE taxonomy. Each finding's CWE-942 entry
    /// resolves through this, enables GitHub Code Scanning to render
    /// the CWE link in the UI.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    taxonomies: Vec<SarifTaxonomy>,
}

#[derive(Debug, Serialize)]
struct SarifTool<'a> {
    driver: SarifDriver<'a>,
}

#[derive(Debug, Serialize)]
struct SarifDriver<'a> {
    name: &'static str,
    version: &'a str,
    #[serde(rename = "informationUri")]
    information_uri: &'static str,
    /// SARIF 2.1.0 §3.19.23: per-rule metadata referenced by
    /// `result.ruleId`. Populated with one entry per distinct ruleId
    /// in the results so SARIF consumers can render readable rule
    /// names instead of just the opaque `waf-bypass-sql` string.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    rules: Vec<SarifReportingDescriptor>,
}

/// SARIF 2.1.0 §3.49 reportingDescriptor (rule metadata). Used as
/// the `tool.driver.rules` entries so consumers can show the full
/// rule name + short description + help URI alongside each finding.
#[derive(Debug, Serialize)]
struct SarifReportingDescriptor {
    id: String,
    name: String,
    #[serde(rename = "shortDescription")]
    short_description: SarifMessage,
    #[serde(rename = "fullDescription")]
    full_description: SarifMessage,
    #[serde(rename = "helpUri")]
    help_uri: &'static str,
    #[serde(rename = "defaultConfiguration")]
    default_configuration: SarifReportingConfiguration,
}

#[derive(Debug, Serialize)]
struct SarifReportingConfiguration {
    level: &'static str,
}

/// SARIF 2.1.0 §3.18 toolComponent (taxonomy descriptor). For CWE
/// the canonical URI is documented at OASIS.
#[derive(Debug, Serialize)]
struct SarifTaxonomy {
    name: &'static str,
    version: &'static str,
    #[serde(rename = "informationUri")]
    information_uri: &'static str,
    #[serde(rename = "downloadUri")]
    download_uri: &'static str,
    taxa: Vec<SarifTaxon>,
}

#[derive(Debug, Serialize)]
struct SarifTaxon {
    id: &'static str,
    name: &'static str,
    #[serde(rename = "shortDescription")]
    short_description: SarifMessage,
}

#[derive(Debug, Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: &'static str,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
    /// SARIF 2.1.0 §3.27.23: stable identifiers used by consumers
    /// (GitHub Code Scanning, etc.) for cross-run dedup. We populate
    /// `primaryLocationLineHash` with a hash of (class, technique,
    /// target), same finding emitted twice gets the same fingerprint
    /// and the consumer dedupes the alert.
    #[serde(
        rename = "partialFingerprints",
        skip_serializing_if = "serde_json::Map::is_empty"
    )]
    partial_fingerprints: serde_json::Map<String, Value>,
    /// SARIF 2.1.0 §3.27.27: CWE references for this result.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    taxa: Vec<SarifTaxonReference>,
    #[serde(skip_serializing_if = "serde_json::Map::is_empty")]
    properties: serde_json::Map<String, Value>,
}

#[derive(Debug, Serialize)]
struct SarifTaxonReference {
    id: &'static str,
    #[serde(rename = "toolComponent")]
    tool_component: SarifTaxonComponentRef,
}

#[derive(Debug, Serialize)]
struct SarifTaxonComponentRef {
    name: &'static str,
}

#[derive(Debug, Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Debug, Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Serialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
}

#[derive(Debug, Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

// ─── Entry point ─────────────────────────────────────────────────────────────

/// Exit code 2, input JSON had no recognised bypass key
/// (`results` or `bypasses`). Anti-rig: zero-result SARIF with exit 0
/// silently lies to CI pipelines that upload to GitHub Code Scanning.
/// `--quiet` suppresses the warning and downgrades to exit 0 when the
/// caller deliberately wants an empty SARIF.
pub(crate) const EXIT_NO_RECOGNISED_BYPASS_KEY: u8 = 2;

pub(crate) fn run_sarif(args: SarifArgs) -> ExitCode {
    let raw = match read_input(&args.input) {
        Ok(s) => s,
        Err(e) => {
            return crate::helpers::input_error(e);
        }
    };
    let json: Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            return crate::helpers::input_error(format!("parse JSON: {e}"));
        }
    };

    let target = args
        .target_url
        .as_deref()
        .or_else(|| json.get("target_url").and_then(|v| v.as_str()))
        .unwrap_or(SARIF_BENCH_TARGET_PLACEHOLDER);

    let (results, schema) = build_sarif_results_with_schema(&json, target);
    let schema_mismatch = matches!(schema, BypassSchema::Unrecognised);
    if schema_mismatch && !args.quiet {
        eprintln!(
            "{} input JSON has no recognised bypass key (`results` or `bypasses`). Emitting empty SARIF. Exit 2.",
            "warn:".yellow().bold(),
        );
    }

    let crate_version = env!("CARGO_PKG_VERSION");
    // Rules + taxonomies emitted only when there are results to describe
    // an empty SARIF stays minimal so jq-pipe smoke tests stay simple.
    let (rules, taxonomies) = if results.is_empty() {
        (Vec::new(), Vec::new())
    } else {
        (build_rules_table(&results), vec![build_cwe_taxonomy()])
    };
    let log = SarifLog {
        version: SARIF_VERSION,
        schema: SARIF_SCHEMA_URI,
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "wafrift",
                    version: crate_version,
                    information_uri: "https://github.com/santhreal/wafrift",
                    rules,
                },
            },
            results,
            taxonomies,
        }],
    };

    match serde_json::to_string_pretty(&log) {
        Ok(s) => {
            println!("{s}");
            if schema_mismatch && !args.quiet {
                ExitCode::from(EXIT_NO_RECOGNISED_BYPASS_KEY)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(e) => {
            eprintln!("{} serialize SARIF: {e}", "error:".red().bold());
            ExitCode::from(1)
        }
    }
}

/// Which wafrift output schema produced these SARIF results. Used by
/// run_sarif to decide whether to emit the schema-mismatch warning
/// and exit code 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BypassSchema {
    /// Top-level `results` array (`bench-waf --output` / `scan --output`).
    BenchResults,
    /// Top-level `bypasses` array (`hunt` campaign state).
    HuntBypasses,
    /// Neither key present (empty SARIF + exit 2).
    Unrecognised,
}

fn read_input(path: &std::path::Path) -> Result<String, String> {
    if path.as_os_str() == "-" {
        match crate::safe_body::read_bounded_text_stdin(SARIF_INPUT_MAX_BYTES) {
            Ok(s) => Ok(s),
            Err(crate::safe_body::ReadError::Transport(msg)) => Err(format!("read stdin: {msg}")),
            Err(crate::safe_body::ReadError::Overrun {
                cap_bytes,
                observed_bytes,
            }) => Err(format!(
                "stdin exceeded {cap_bytes}-byte cap ({observed_bytes} bytes seen)"
            )),
        }
    } else {
        match crate::safe_body::read_bounded_text_file(path, SARIF_INPUT_MAX_BYTES) {
            Ok(s) => Ok(s),
            Err(crate::safe_body::ReadError::Transport(msg)) => {
                Err(format!("read {}: {msg}", path.display()))
            }
            Err(crate::safe_body::ReadError::Overrun {
                cap_bytes,
                observed_bytes,
            }) => Err(format!(
                "{} exceeded {cap_bytes}-byte cap ({observed_bytes} bytes seen)",
                path.display()
            )),
        }
    }
}

/// CWE-942: "Permissive Cross-domain Policy with Untrusted Domains".
/// The closest CWE for a confirmed WAF bypass; SARIF consumers (GitHub
/// Code Scanning, etc.) use this to render the CWE link in the UI.
const SARIF_CWE_ID: &str = "942";

/// Build the SARIF taxonomy entry for CWE references.
fn build_cwe_taxonomy() -> SarifTaxonomy {
    SarifTaxonomy {
        name: "CWE",
        version: "4.14",
        information_uri: "https://cwe.mitre.org/",
        download_uri: "https://cwe.mitre.org/data/xml/cwec_v4.14.xml.zip",
        taxa: vec![SarifTaxon {
            id: SARIF_CWE_ID,
            name: "CWE-942",
            short_description: SarifMessage {
                text: "Permissive Cross-domain Policy with Untrusted Domains \
                       (used as the closest mapping for confirmed WAF bypass. \
                       the request reached the application despite the perimeter \
                       control)"
                    .to_string(),
            },
        }],
    }
}

/// Collect distinct `ruleId`s from the results and emit one
/// [`SarifReportingDescriptor`] per: SARIF 2.1.0 §3.19.23. Consumers
/// dereference `result.ruleId` into this table to render readable rule
/// names + descriptions in their UI.
fn build_rules_table(results: &[SarifResult]) -> Vec<SarifReportingDescriptor> {
    let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for r in results {
        seen.insert(r.rule_id.as_str());
    }
    seen.into_iter()
        .map(|rule_id| {
            // rule_id is "waf-bypass-<class>" (extract the class for the human name).
            let class = rule_id.strip_prefix("waf-bypass-").unwrap_or(rule_id);
            SarifReportingDescriptor {
                id: rule_id.to_string(),
                name: format!("WafBypass{}", title_case(class)),
                short_description: SarifMessage {
                    text: format!("WAF bypass confirmed for {class} payload class",),
                },
                full_description: SarifMessage {
                    text: format!(
                        "wafrift confirmed a request carrying a {class}-class payload \
                         reached the origin application despite the WAF in front. \
                         Per the 3-gate oracle (WAF didn't return a recognised \
                         block marker + reached app status + structural validity), \
                         this is a real bypass not a false positive."
                    ),
                },
                help_uri: "https://github.com/santhreal/wafrift",
                default_configuration: SarifReportingConfiguration { level: "error" },
            }
        })
        .collect()
}

fn title_case(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) => c.to_ascii_uppercase().to_string() + chars.as_str(),
        None => String::new(),
    }
}

/// Compute a stable per-finding fingerprint as a hex u64. Inputs:
/// (rule_id, target URL, technique-or-case-id). Two runs that emit
/// the same finding produce the same fingerprint. GitHub Code
/// Scanning uses this to dedupe alerts across PRs.
fn finding_fingerprint(rule_id: &str, target: &str, key: &str) -> String {
    // Cheap stable hash: DefaultHasher is fine for non-crypto identity.
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    rule_id.hash(&mut h);
    target.hash(&mut h);
    key.hash(&mut h);
    format!("{:016x}", h.finish())
}

/// Dispatch to the right schema parser based on which top-level key
/// the input JSON carries. Returns the SARIF results AND which
/// schema was matched (so `run_sarif` can warn + exit-2 on
/// `Unrecognised`).
fn build_sarif_results_with_schema(json: &Value, target: &str) -> (Vec<SarifResult>, BypassSchema) {
    if json.get("results").and_then(|v| v.as_array()).is_some() {
        (
            build_from_bench_results(json, target),
            BypassSchema::BenchResults,
        )
    } else if json.get("bypasses").and_then(|v| v.as_array()).is_some() {
        (
            build_from_hunt_bypasses(json, target),
            BypassSchema::HuntBypasses,
        )
    } else {
        (Vec::new(), BypassSchema::Unrecognised)
    }
}

/// Test-only shim that drops the schema tag, keeps the existing
/// `build_sarif_results` test surface stable while the production
/// callers use the schema-aware variant.
#[cfg(test)]
fn build_sarif_results(json: &Value, target: &str) -> Vec<SarifResult> {
    build_sarif_results_with_schema(json, target).0
}

/// Walk the bench/scan `results` array and emit one [`SarifResult`]
/// per case whose `evaded.variants_bypassed > 0`. Cases with zero
/// bypasses are NOT emitted: SARIF is for actionable findings, and
/// "we tried but didn't bypass" belongs in the bench scoreboard, not
/// the finding stream.
fn build_from_bench_results(json: &Value, target: &str) -> Vec<SarifResult> {
    let Some(results) = json.get("results").and_then(|v| v.as_array()) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for result in results {
        let case_id = result
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let class = result
            .get("class")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let Some(Value::Object(evaded)) = result.get("evaded") else {
            continue;
        };
        let bypassed = evaded
            .get("variants_bypassed")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        if bypassed == 0 {
            continue;
        }

        let techniques: Vec<String> = evaded
            .get("bypass_techniques")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|t| t.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();

        let mut properties = serde_json::Map::new();
        properties.insert("class".into(), Value::String(class.to_string()));
        properties.insert("case_id".into(), Value::String(case_id.to_string()));
        properties.insert("variants_bypassed".into(), Value::Number(bypassed.into()));
        if !techniques.is_empty() {
            properties.insert(
                "techniques".into(),
                Value::Array(
                    techniques
                        .iter()
                        .map(|t| Value::String(t.clone()))
                        .collect(),
                ),
            );
        }
        // C-14 rule-quality fields carry through to SARIF properties
        // when present, consumers (GitHub Code Scanning, security
        // dashboards) can filter / sort by these without parsing the
        // raw bench JSON.
        if let Some(cq) = result.get("case_quality").and_then(|v| v.as_str()) {
            properties.insert("case_quality".into(), Value::String(cq.to_string()));
        }
        if let Some(qs) = result.get("quality_score").and_then(|v| v.as_f64())
            && let Some(n) = serde_json::Number::from_f64(qs)
        {
            properties.insert("quality_score".into(), Value::Number(n));
        }

        let message_text = if techniques.is_empty() {
            format!(
                "WAF bypass confirmed (class={class}, case={case_id}, variants_bypassed={bypassed})"
            )
        } else {
            format!(
                "WAF bypass confirmed (class={class}, case={case_id}, variants_bypassed={bypassed}) via {}",
                techniques.join(", ")
            )
        };

        let rule_id = format!("waf-bypass-{class}");
        let mut fingerprints = serde_json::Map::new();
        fingerprints.insert(
            "primaryLocationLineHash".into(),
            Value::String(finding_fingerprint(&rule_id, target, case_id)),
        );
        out.push(SarifResult {
            rule_id,
            // Confirmed bypasses are always actionable findings.
            level: "error",
            message: SarifMessage { text: message_text },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: target.to_string(),
                    },
                },
            }],
            partial_fingerprints: fingerprints,
            taxa: vec![SarifTaxonReference {
                id: SARIF_CWE_ID,
                tool_component: SarifTaxonComponentRef { name: "CWE" },
            }],
            properties,
        });
    }
    out
}

/// Walk a `hunt --campaign-id` state file's `bypasses` array (each
/// item a `CampaignBypass` with `class` + `technique` + `round` +
/// `discovered_at`) and emit one SARIF result per entry. Every
/// CampaignBypass is by construction a confirmed bypass, no zero-bypass
/// filtering needed here.
fn build_from_hunt_bypasses(json: &Value, target: &str) -> Vec<SarifResult> {
    let Some(bypasses) = json.get("bypasses").and_then(|v| v.as_array()) else {
        return Vec::new();
    };

    // The hunt state already carries `target_url`; if the caller didn't
    // override with --target-url, prefer the campaign's target.
    let target = if target == SARIF_BENCH_TARGET_PLACEHOLDER {
        json.get("target_url")
            .and_then(|v| v.as_str())
            .unwrap_or(target)
    } else {
        target
    };

    let campaign_id = json
        .get("campaign_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let mut out = Vec::new();
    for b in bypasses {
        let class = b.get("class").and_then(|v| v.as_str()).unwrap_or("unknown");
        let technique = b.get("technique").and_then(|v| v.as_str()).unwrap_or("");
        let round = b.get("round").and_then(|v| v.as_u64()).unwrap_or(0);
        let discovered_at = b.get("discovered_at").and_then(|v| v.as_u64()).unwrap_or(0);

        let mut properties = serde_json::Map::new();
        properties.insert("class".into(), Value::String(class.to_string()));
        properties.insert("campaign_id".into(), Value::String(campaign_id.to_string()));
        properties.insert("round".into(), Value::Number(round.into()));
        properties.insert("discovered_at".into(), Value::Number(discovered_at.into()));
        if !technique.is_empty() {
            properties.insert("technique".into(), Value::String(technique.to_string()));
        }

        let message_text = if technique.is_empty() {
            format!("WAF bypass confirmed (campaign={campaign_id}, class={class}, round={round})")
        } else {
            format!(
                "WAF bypass confirmed (campaign={campaign_id}, class={class}, round={round}) via {technique}"
            )
        };

        let rule_id = format!("waf-bypass-{class}");
        // Hunt fingerprint key: technique uniquely identifies a hunt
        // bypass (same campaign re-finding the same technique should
        // dedupe).
        let fingerprint_key = if technique.is_empty() {
            format!("round-{round}")
        } else {
            technique.to_string()
        };
        let mut fingerprints = serde_json::Map::new();
        fingerprints.insert(
            "primaryLocationLineHash".into(),
            Value::String(finding_fingerprint(&rule_id, target, &fingerprint_key)),
        );
        out.push(SarifResult {
            rule_id,
            level: "error",
            message: SarifMessage { text: message_text },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: target.to_string(),
                    },
                },
            }],
            partial_fingerprints: fingerprints,
            taxa: vec![SarifTaxonReference {
                id: SARIF_CWE_ID,
                tool_component: SarifTaxonComponentRef { name: "CWE" },
            }],
            properties,
        });
    }
    out
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "sarif_cmd_tests.rs"]
mod tests;
