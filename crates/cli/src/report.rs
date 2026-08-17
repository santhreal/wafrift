//! `wafrift report`: generate a pentest-ready markdown writeup from
//! the proxy gene bank.
//!
//! The proxy gene bank is a JSON ledger of which evasion technique
//! pools work against which hosts (plus identified WAF). For a
//! practitioner finishing an engagement, the natural artefact to deliver
//! is one markdown file per host (or one combined report), with every
//! finding paired with the exact `wafrift replay` command that
//! reproduces it. Report turns the ledger into that artefact in one
//! shot (no manual transcription).

use clap::Args;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use wafrift_types::glob_match;

use crate::helpers::shell_single_quote;
use crate::raw_request::RawRequest;

#[derive(Args, Debug)]
pub(crate) struct ReportArgs {
    /// Path to the proxy gene bank JSON. Repeatable: pass `--proxy-bank a.json
    /// --proxy-bank b.json` to merge multiple banks (engagement teams running
    /// several wafrift-proxies). Hosts are unioned; per-host `proven_winners` /
    /// blocklisted are unioned; the first non-null `waf_name` wins.
    /// Default (no flag) `~/.wafrift/gene-bank.json`.
    ///
    /// Also accepts `--gene-bank` as an alias, dogfood sonnet 3 (2026-05)
    /// flagged that operators reach for "gene bank" naming
    /// (`--gene-bank-dir` was tried) and got `unexpected argument` with no
    /// hint. The alias closes the muscle-memory gap.
    #[arg(long, visible_alias = "gene-bank")]
    pub proxy_bank: Vec<PathBuf>,

    /// One or more `wafrift scan --format json` output files to fold
    /// into the report. This is what makes `scan` → `report` compose:
    /// previously `report` only read the proxy gene bank, so a user who
    /// ran `scan` then `report` got "No bypasses recorded yet" even
    /// with findings in hand. Repeatable.
    #[arg(long)]
    pub scan_json: Vec<PathBuf>,

    /// Read a `wafrift scan --format json` blob from stdin, so
    /// `wafrift scan ... --format json | wafrift report --scan-stdin`
    /// works as a one-liner.
    #[arg(long, default_value_t = false)]
    pub scan_stdin: bool,

    /// Restrict the report to hosts matching this glob (`*.example.com`).
    /// Repeatable / comma-separated. Empty = all hosts.
    #[arg(long, num_args = 1.., value_delimiter = ',')]
    pub only_host: Vec<String>,

    /// Write the markdown to this file instead of stdout.
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// Suggested target URL for replay commands (e.g. `https://api.example.com/search`).
    /// If omitted, replay snippets use `https://{host}/<PATH>` where `<PATH>` is a
    /// literal placeholder, it is printed verbatim and must be replaced by the
    /// operator with the actual endpoint path. Passing a target that literally
    /// contains `<PATH>` is allowed and will be reproduced as-is.
    #[arg(long)]
    pub target_template: Option<String>,

    /// Suggested param name for replay commands.
    #[arg(long, default_value = "q")]
    pub param: String,

    /// Suggested payload for replay commands. Quote-escape carefully.
    #[arg(long, default_value = "PAYLOAD-HERE")]
    pub payload: String,

    /// Output format. `markdown` (default) is the pentest-shaped writeup;
    /// `json` is a stable, machine-parseable surface for CI gating and
    /// downstream report tooling. Both honour `--only-host`.
    #[arg(long, default_value = "markdown", value_parser = ["markdown", "json"])]
    pub format: String,
}

/// Stable JSON shape for `--format json`. The `schema_version` field
/// mirrors `_wafrift/status` and lets downstream tools detect format
/// drift across wafrift releases.
#[derive(Serialize)]
struct JsonReport<'a> {
    schema_version: u32,
    wafrift_version: &'static str,
    source_schema: u32,
    total_hosts: usize,
    hosts_with_bypasses: usize,
    findings: Vec<JsonFinding<'a>>,
}

#[derive(Serialize)]
struct JsonFinding<'a> {
    host: &'a str,
    waf: Option<&'a str>,
    proven_techniques: &'a [String],
    blocklisted_techniques: &'a [String],
    /// Concrete bypass payloads + reproducers, carried over from
    /// scan-JSON ingestion. Empty when only the proxy bank was the
    /// source. The shape mirrors `BypassFinding` so a downstream
    /// tool deserialising this report can use the same struct as
    /// the raw scan JSON.
    bypass_findings: &'a [BypassFinding],
    /// `wafrift replay` invocation that re-runs the finding through
    /// the wafrift evasion engine, drives the gene bank, picks fresh
    /// variants, surfaces a verdict.
    replay_command: String,
    /// Raw `curl -i` invocation that fires the equivalent HTTP request
    /// shape (GET ?param=payload) directly at the target, for
    /// hand-off to a client who does not (yet) have wafrift installed.
    /// Built via [`RawRequest::to_curl`] so the shell escape matches
    /// the one used everywhere else in the CLI.
    curl_command: String,
}

const REPORT_SCHEMA_VERSION: u32 = 2;

#[derive(Deserialize, Debug, Default)]
struct PersistedHostState {
    #[serde(default)]
    proven_winners: Vec<String>,
    #[serde(default)]
    blocklisted: Vec<String>,
    #[serde(default)]
    waf_name: Option<String>,
    /// Concrete bypass payloads carried over from `wafrift scan
    /// --format json` ingestion. Empty on the legacy proxy-bank-only
    /// load path (the proxy stores only the technique chain it
    /// proved out, not the original payload it succeeded with).
    /// Populated by [`ingest_scan_json`] and rendered as a "Bypass
    /// payloads" section per host so the pentest report carries the
    /// exact bytes that beat the WAF (not just the strategy class).
    /// Backwards-compat-safe: `serde(default)` means existing
    /// gene-bank JSON deserialises to an empty Vec.
    #[serde(default)]
    bypass_findings: Vec<BypassFinding>,
}

/// One concrete bypass surfaced from a scan JSON. Mirrors the shape
/// emitted by `scan/mod.rs` under `--format json` so a future code
/// path could deserialise straight from the raw scan output without
/// the manual `ingest_scan_json` extraction.
#[derive(Deserialize, serde::Serialize, Debug, Clone)]
struct BypassFinding {
    /// 1-based variant ID, same numbering scheme as the scan output.
    variant: u64,
    /// Concrete payload bytes that bypassed.
    payload: String,
    /// Strategy chain that produced the payload, joined for display.
    techniques: Vec<String>,
    /// Oracle confidence (0.0–1.0).
    confidence: f64,
    /// Operator-pasteable curl reproducer. Populated when the source
    /// scan JSON included `repro_curl` (the URL-query + raw-runner
    /// paths now both emit it); `None` for older scan JSON that
    /// predates the field.
    #[serde(default)]
    repro_curl: Option<String>,
    /// ddmin-distilled smallest variant (`scan --auto-distill`).
    /// `None` for runs without that flag.
    #[serde(default)]
    minimal_payload: Option<String>,
}

#[derive(Deserialize, Debug, Default)]
struct PersistedGeneBank {
    #[serde(default)]
    schema: u32,
    #[serde(default)]
    hosts: HashMap<String, PersistedHostState>,
}

/// Union two banks: `dst` is mutated in place with the host union from `src`.
/// Per host: `proven_winners` and blocklisted are union-merged (preserving
/// dst's order, then appending unseen entries from src). The first non-null
/// `waf_name` wins. Schema becomes max(dst, src).
fn merge_banks(dst: &mut PersistedGeneBank, src: PersistedGeneBank) {
    dst.schema = dst.schema.max(src.schema);
    for (host, src_state) in src.hosts {
        let entry = dst.hosts.entry(host).or_default();
        for w in src_state.proven_winners {
            if !entry.proven_winners.contains(&w) {
                entry.proven_winners.push(w);
            }
        }
        for b in src_state.blocklisted {
            if !entry.blocklisted.contains(&b) {
                entry.blocklisted.push(b);
            }
        }
        if entry.waf_name.is_none() {
            entry.waf_name = src_state.waf_name;
        }
        // Bypass findings are uniqued on (variant, payload), same
        // bypass surfaced by two scan runs against the same host
        // shouldn't double in the report. Order preserves dst-first
        // so the most-recently-ingested run wins display position
        // for new findings.
        for f in src_state.bypass_findings {
            let already = entry
                .bypass_findings
                .iter()
                .any(|e| e.variant == f.variant && e.payload == f.payload);
            if !already {
                entry.bypass_findings.push(f);
            }
        }
    }
}

/// Reduce a target URL to a bare host (the gene-bank/report key).
fn host_from_target(target: &str) -> String {
    // Delegate to the shared transport extractor, it handles
    // IPv6 brackets correctly. Pre-fix the local naive
    // rsplit_once(':') split `[::1]` on the LAST `:` of the
    // address itself, yielding `[:` instead of `[::1]`. Report
    // aggregation against an IPv6-target scan was effectively
    // broken (host-keyed buckets used the mangled string).
    wafrift_transport::host_from_url(target).unwrap_or_else(|| "unknown-host".to_string())
}

/// Parse a `wafrift scan --format json` blob into the same host-keyed
/// model the proxy gene bank uses, so both sources flow through the
/// identical render path. Accepts the bare `scan` object or the
/// `--report-layers` wrapper that nests it under `"scan"`.
fn ingest_scan_json(raw: &str, src: &str) -> Result<PersistedGeneBank, String> {
    let v: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| format!("parse scan JSON from {src}: {e}"))?;
    let scan = v.get("scan").filter(|s| s.is_object()).unwrap_or(&v);

    let target = scan
        .get("target")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            format!("{src}: not a wafrift scan JSON (no `target` field), did you pipe `scan --format json`?")
        })?;
    let host = host_from_target(target);

    let mut techniques: Vec<String> = Vec::new();
    let mut bypass_findings: Vec<BypassFinding> = Vec::new();
    if let Some(arr) = scan
        .get("bypass_variants")
        .and_then(serde_json::Value::as_array)
    {
        for bv in arr {
            if let Some(ts) = bv.get("techniques").and_then(serde_json::Value::as_array) {
                for t in ts {
                    if let Some(s) = t.as_str()
                        && !techniques.iter().any(|x| x == s)
                    {
                        techniques.push(s.to_string());
                    }
                }
            }
            // Preserve the concrete bypass payload + repro_curl
            // the previous cut threw these away and the rendered
            // report only carried the technique class, which made
            // the pentest deliverable answer "what bypassed?" with
            // "url+case_swap" instead of the actual exploit string.
            if let Ok(finding) = serde_json::from_value::<BypassFinding>(bv.clone()) {
                bypass_findings.push(finding);
            }
        }
    }

    let waf_name = scan
        .get("waf")
        .and_then(serde_json::Value::as_str)
        .filter(|w| !w.is_empty() && !w.eq_ignore_ascii_case("none"))
        .map(str::to_string);

    let mut hosts = HashMap::new();
    hosts.insert(
        host,
        PersistedHostState {
            proven_winners: techniques,
            blocklisted: Vec::new(),
            waf_name,
            bypass_findings,
        },
    );
    Ok(PersistedGeneBank { schema: 1, hosts })
}

pub(crate) fn run_report(args: ReportArgs) -> ExitCode {
    let has_scan_src = !args.scan_json.is_empty() || args.scan_stdin;
    let mut merged = PersistedGeneBank::default();

    // ── scan JSON sources ──
    if args.scan_stdin {
        // Bounded read: an unbounded stdin().read_to_string() would OOM
        // on `wafrift report --scan-stdin < /dev/zero`. Scan JSON files
        // are compact (kilobytes); 64 MiB is the same cap used for gene
        // banks and comfortably covers any legitimate scan output.
        let raw = match crate::safe_body::read_bounded_text_stdin(
            crate::safe_body::GENE_BANK_FILE_MAX_BYTES,
        ) {
            Ok(s) => s,
            Err(e) => {
                return crate::helpers::input_error(format!("read scan JSON from stdin: {e}"));
            }
        };
        match ingest_scan_json(&raw, "stdin") {
            Ok(b) => merge_banks(&mut merged, b),
            Err(e) => {
                return crate::helpers::input_error(e);
            }
        }
    }
    for path in &args.scan_json {
        // Bounded read: operator-supplied paths may resolve to /dev/zero
        // or a hostile symlink pointing at a multi-GB file. 64 MiB cap
        // matches the gene-bank cap and fits any legitimate scan output.
        let raw = match crate::safe_body::read_bounded_text_file(
            path,
            crate::safe_body::GENE_BANK_FILE_MAX_BYTES,
        ) {
            Ok(s) => s,
            Err(e) => {
                return crate::helpers::input_error(format!("read {}: {e}", path.display()));
            }
        };
        match ingest_scan_json(&raw, &path.display().to_string()) {
            Ok(b) => merge_banks(&mut merged, b),
            Err(e) => {
                return crate::helpers::input_error(e);
            }
        }
    }

    // ── proxy gene bank sources ──
    // Load when explicitly requested, or as the sole source when no
    // scan JSON was supplied (preserves the original default). When
    // scan JSON IS supplied and no bank is explicitly named, don't
    // hard-fail on a missing default bank (the scan data stands alone).
    let load_proxy = !args.proxy_bank.is_empty() || !has_scan_src;
    if load_proxy {
        let paths = match resolve_paths(&args.proxy_bank) {
            Ok(p) => p,
            Err(msg) => {
                return crate::helpers::input_error(msg);
            }
        };
        for path in &paths {
            // Check for NotFound before the bounded read so we can
            // present the practitioner-facing hint message. A metadata()
            // call does not open the file, so there is no TOCTOU-with-OOM
            // risk: the subsequent bounded open will fail cleanly if the
            // path changes between these two calls.
            if !path.exists() {
                // A missing bank file is a hard error ONLY when the operator
                // named it explicitly via --proxy-bank. Two cases skip to the
                // empty-bank render (exit 0) instead:
                //   - has_scan_src: scan data already stands alone; a missing
                //     default proxy bank is irrelevant in that mode.
                //   - args.proxy_bank.is_empty(): this is the DEFAULT path
                //     (~/.wafrift/gene-bank.json), created lazily by
                //     wafrift-proxy. On a fresh install (or a clean CI runner)
                //     it simply does not exist yet, report then renders the
                //     "No bypasses recorded yet" page. That empty state IS the
                //     honest result, surfaced loudly in the report body (and as
                //     findings:[] / total_hosts:0 in JSON), not a silent,
                //     recall-losing fallback. An explicitly-named missing path
                //     is operator error and still fails closed below.
                if has_scan_src || args.proxy_bank.is_empty() {
                    continue;
                }
                return crate::helpers::input_error(format!(
                    "gene bank not found: {}\n\n\
                     hint: the gene bank is created automatically by wafrift-proxy.\n\
                     Run `wafrift-proxy --listen 127.0.0.1:8080 --mitm` and browse\n\
                     through it, then re-run `wafrift report`.\n\
                     Or pass `--scan-json <file>` / `--scan-stdin` to report from\n\
                     `wafrift scan --format json` output instead.",
                    path.display()
                ));
            }
            // Bounded read: operator-supplied bank paths may resolve to
            // /dev/zero or a hostile symlink. The 64 MiB cap is the same
            // used by proxy gene_bank_io (MAX_GENE_BANK_BYTES) and seed.rs.
            let raw = match crate::safe_body::read_bounded_text_file(
                path,
                crate::safe_body::GENE_BANK_FILE_MAX_BYTES,
            ) {
                Ok(s) => s,
                Err(e) => {
                    return crate::helpers::input_error(format!("read {}: {e}", path.display()));
                }
            };
            let bank: PersistedGeneBank = match serde_json::from_str(&raw) {
                Ok(b) => b,
                Err(e) => {
                    return crate::helpers::input_error(format!("parse {}: {e}", path.display()));
                }
            };
            merge_banks(&mut merged, bank);
        }
    }
    let bank = merged;

    let mut hosts: Vec<(&String, &PersistedHostState)> = bank
        .hosts
        .iter()
        .filter(|(name, hs)| {
            !hs.proven_winners.is_empty()
                && (args.only_host.is_empty()
                    || args.only_host.iter().any(|p| host_matches(p, name)))
        })
        .collect();
    hosts.sort_by(|a, b| a.0.cmp(b.0));

    let body = match args.format.as_str() {
        "json" => match render_json(&bank, &hosts, &args) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error: serialize json: {e}");
                return ExitCode::from(1);
            }
        },
        _ => render_markdown(&bank, &hosts, &args),
    };

    match args.output.as_ref() {
        Some(p) => match fs::write(p, &body) {
            Ok(()) => {
                eprintln!(
                    "wrote {} report ({} hosts, {} bytes) → {}",
                    args.format,
                    hosts.len(),
                    body.len(),
                    p.display()
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: write {}: {e}", p.display());
                ExitCode::from(1)
            }
        },
        None => {
            print!("{body}");
            // JSON consumers expect a trailing newline; markdown already
            // provides its own.
            if args.format == "json" {
                println!();
            }
            ExitCode::SUCCESS
        }
    }
}

fn render_json(
    bank: &PersistedGeneBank,
    hosts: &[(&String, &PersistedHostState)],
    args: &ReportArgs,
) -> Result<String, serde_json::Error> {
    let findings: Vec<JsonFinding<'_>> = hosts
        .iter()
        .map(|(name, hs)| {
            let target = args
                .target_template
                .clone()
                .unwrap_or_else(|| format!("https://{name}/<PATH>"));
            let replay_command = format!(
                "wafrift replay --target {target} --param {param} --payload {payload} --from-host {name}",
                target = shell_single_quote(&target),
                param = args.param,
                payload = shell_single_quote(&args.payload),
                name = shell_single_quote(name),
            );
            let curl_command = curl_reproducer(&target, &args.param, &args.payload);
            JsonFinding {
                host: name.as_str(),
                waf: hs.waf_name.as_deref(),
                proven_techniques: &hs.proven_winners,
                blocklisted_techniques: &hs.blocklisted,
                bypass_findings: &hs.bypass_findings,
                replay_command,
                curl_command,
            }
        })
        .collect();
    let report = JsonReport {
        schema_version: REPORT_SCHEMA_VERSION,
        wafrift_version: env!("CARGO_PKG_VERSION"),
        source_schema: bank.schema,
        total_hosts: bank.hosts.len(),
        hosts_with_bypasses: hosts.len(),
        findings,
    };
    serde_json::to_string_pretty(&report)
}

fn render_markdown(
    bank: &PersistedGeneBank,
    hosts: &[(&String, &PersistedHostState)],
    args: &ReportArgs,
) -> String {
    let mut out = String::new();
    out.push_str("# wafrift findings report\n\n");
    out.push_str(&format!(
        "Source: proxy gene bank schema v{} · {} host(s) with bypasses · {} host(s) total\n\n",
        bank.schema,
        hosts.len(),
        bank.hosts.len()
    ));

    if hosts.is_empty() {
        // N14 fix (dogfood R29 cohort): the natural workflow
        // `wafrift scan ... | wafrift report` produces nothing
        // useful unless `--scan-stdin` was passed. The empty-report
        // message now explicitly names that flag so the operator
        // does not assume the gene bank is broken.
        out.push_str(
            "_No bypasses recorded yet._\n\n\
             Tip: this report only reads the gene bank by default. \
             To include results from a `wafrift scan` run, pipe its \
             JSON output via `--scan-stdin` or pass it explicitly:\n\n\
             ```\n\
             wafrift scan <URL> --payload '<x>' --format json \\\n  \
               | wafrift report --scan-stdin\n\
             ```\n\n\
             Or `wafrift report --scan-json scan.json`.\n",
        );
        return out;
    }

    out.push_str("## Summary\n\n");
    out.push_str("| Host | WAF | Proven techniques | Blocklisted |\n");
    out.push_str("|------|-----|-------------------|-------------|\n");
    for (name, hs) in hosts {
        out.push_str(&format!(
            "| `{}` | {} | {} | {} |\n",
            name,
            hs.waf_name.as_deref().unwrap_or("-"),
            hs.proven_winners.len(),
            hs.blocklisted.len()
        ));
    }
    out.push('\n');

    out.push_str("## Findings\n\n");
    for (name, hs) in hosts {
        out.push_str(&format!("### `{name}`\n\n"));
        if let Some(waf) = &hs.waf_name {
            out.push_str(&format!("**Identified WAF:** {waf}\n\n"));
        }
        out.push_str(&format!(
            "**Bypass count:** {} proven technique(s)\n\n",
            hs.proven_winners.len()
        ));

        out.push_str("**Working techniques:**\n\n");
        for t in &hs.proven_winners {
            out.push_str(&format!("- `{t}`\n"));
        }
        out.push('\n');

        if !hs.blocklisted.is_empty() {
            out.push_str("**Techniques the WAF reliably blocks** (do not use):\n\n");
            for t in &hs.blocklisted {
                out.push_str(&format!("- `{t}`\n"));
            }
            out.push('\n');
        }

        // Concrete bypass payloads, present only when the report
        // was fed scan JSON (proxy-bank-only loads carry technique
        // strings, not the original exploit bytes). The pentest-
        // report deliverable lives here: the exact payload the
        // client engineer can paste into Burp, sqlmap, or curl.
        if !hs.bypass_findings.is_empty() {
            out.push_str(&format!(
                "**Bypass payloads ({} variant{}):**\n\n",
                hs.bypass_findings.len(),
                if hs.bypass_findings.len() == 1 {
                    ""
                } else {
                    "s"
                }
            ));
            for f in &hs.bypass_findings {
                out.push_str(&format!(
                    "- **Variant #{}** · confidence {:.2} · techniques: {}\n",
                    f.variant,
                    f.confidence,
                    if f.techniques.is_empty() {
                        "_(none recorded)_".to_string()
                    } else {
                        f.techniques
                            .iter()
                            .map(|t| format!("`{t}`"))
                            .collect::<Vec<_>>()
                            .join(" → ")
                    }
                ));
                out.push_str(&format!(
                    "\n  ```\n  {}\n  ```\n",
                    f.payload.replace('\n', "\n  ")
                ));
                if let Some(min) = &f.minimal_payload {
                    out.push_str(&format!(
                        "\n  _Distilled minimum ({} bytes):_ `{}`\n",
                        min.len(),
                        min
                    ));
                }
                if let Some(curl) = &f.repro_curl {
                    out.push_str(&format!("\n  Reproduce:\n  ```sh\n  {curl}\n  ```\n"));
                }
            }
            out.push('\n');
        }

        let target = args
            .target_template
            .clone()
            .unwrap_or_else(|| format!("https://{name}/<PATH>"));
        out.push_str("**Reproduce via wafrift replay:**\n\n```sh\n");
        out.push_str(&format!(
            "wafrift replay \\\n  --target {target} \\\n  --param {param} \\\n  --payload {payload} \\\n  --from-host {name}\n",
            target = shell_single_quote(&target),
            param = args.param,
            payload = shell_single_quote(&args.payload),
            name = shell_single_quote(name),
        ));
        out.push_str("```\n\n");

        out.push_str("**Reproduce via raw curl:**\n\n```sh\n");
        out.push_str(&curl_reproducer(&target, &args.param, &args.payload));
        out.push_str("\n```\n\n");
    }

    out.push_str("## Methodology\n\n");
    out.push_str(
        "Each \"bypass\" entry above is a technique pool that produced a non-blocked HTTP \
         response (status not in 403/406 and no WAF-block body fragments) against the target \
         host while wafrift-proxy was in front of the practitioner's HTTP client. Replay the \
         finding via `wafrift replay --from-host <host>` to reproduce on demand.\n\n",
    );
    out.push_str(
        "Authorisation: only run replay against hosts you own or have explicit written \
         authorisation to test. The proxy will refuse private/loopback/RFC1918 destinations \
         unless `--allow-private-upstream` is set.\n",
    );
    out
}

fn host_matches(pattern: &str, host: &str) -> bool {
    // Delegates to the canonical O(|p|·|s|) iterative glob matcher in
    // wafrift-types, shared with the proxy scope filter. The old local
    // recursive impl was O(|host|^k) (a ReDoS risk in the hot path).
    glob_match(pattern, host)
}

/// Build the `curl -i …` reproducer for a finding. Mirrors the
/// canonical GET-shape probe `scan` fires for every variant:
/// `target?param=urlencoded(payload)` with no body and no extra
/// headers (the operator brings their own session via Burp / curl
/// `-b cookie.jar`). Returns a single-line, ready-to-paste curl
/// command, escaping handled by [`RawRequest::to_curl`], which
/// shares the canonical shell escape with [`crate::helpers::shell_single_quote`].
///
/// Why a helper instead of inline format! magic: routes through the
/// SAME `RawRequest`/`to_curl` path the scan engine uses to surface
/// reproducers, so a fix to one curl-shape rule applies everywhere.
fn curl_reproducer(target: &str, param: &str, payload: &str) -> String {
    let url = match reqwest::Url::parse(target) {
        Ok(mut url) => {
            url.query_pairs_mut().append_pair(param, payload);
            url.to_string()
        }
        // Falls back when `target_template` contains the literal
        // `<PATH>` placeholder (not a valid URL): emit the obvious
        // shape and let the operator hand-edit before running.
        Err(_) => format!(
            "{target}?{param}={payload_enc}",
            payload_enc = urlencoding_query(payload)
        ),
    };
    RawRequest {
        method: "GET".to_string(),
        url,
        headers: Vec::new(),
        body: Vec::new(),
    }
    .to_curl()
}

/// Minimal application/x-www-form-urlencoded escape for the query-
/// string fallback above. `reqwest::Url::parse` does the real thing
/// when the target IS a valid URL; this fallback covers the
/// `<PATH>` placeholder case only.
fn urlencoding_query(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn resolve_paths(custom: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    if !custom.is_empty() {
        return Ok(custom.to_vec());
    }
    // $HOME on POSIX; %USERPROFILE% on Windows (cmd / PowerShell ship
    // it; Git Bash / WSL set $HOME so this still works there too).
    // Pre-fix, bare-Windows operators saw `$HOME not set` and had to
    // pass --proxy-bank explicitly, the hint message didn't mention
    // %USERPROFILE% so they assumed wafrift was broken.
    let home_dir = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"));
    let home = home_dir.ok_or_else(|| {
        "neither $HOME nor %USERPROFILE% set; pass --proxy-bank explicitly".to_string()
    })?;
    Ok(vec![
        PathBuf::from(home).join(".wafrift").join("gene-bank.json"),
    ])
}

#[cfg(test)]
#[path = "report_tests.rs"]
mod tests;
