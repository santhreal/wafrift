    use super::*;

    fn fake_bank() -> PersistedGeneBank {
        let mut hosts = HashMap::new();
        hosts.insert(
            "api.example.com".into(),
            PersistedHostState {
                proven_winners: vec!["EncodingUrl".into(), "GrammarTautology".into()],
                blocklisted: vec!["XssTagScript".into()],
                waf_name: Some("ModSecurity-CRS".into()),
                bypass_findings: Vec::new(),
            },
        );
        hosts.insert(
            "no-finds.example.com".into(),
            PersistedHostState {
                proven_winners: vec![],
                blocklisted: vec![],
                waf_name: None,
                bypass_findings: Vec::new(),
            },
        );
        PersistedGeneBank { schema: 1, hosts }
    }

    #[test]
    fn report_omits_hosts_with_no_bypasses() {
        let bank = fake_bank();
        let hosts: Vec<_> = bank
            .hosts
            .iter()
            .filter(|(_, hs)| !hs.proven_winners.is_empty())
            .collect();
        let args = ReportArgs {
            proxy_bank: vec![],
            scan_json: vec![],
            scan_stdin: false,
            only_host: vec![],
            output: None,
            target_template: None,
            param: "q".into(),
            payload: "x".into(),
            format: "markdown".into(),
        };
        let md = render_markdown(&bank, &hosts, &args);
        assert!(md.contains("api.example.com"));
        assert!(!md.contains("no-finds.example.com"));
        assert!(md.contains("ModSecurity-CRS"));
        assert!(md.contains("EncodingUrl"));
        assert!(md.contains("XssTagScript"));
        assert!(md.contains("wafrift replay"));
    }

    // shell_escape lived here until 2026-05-20; the canonical
    // implementation is now `helpers::shell_single_quote` and the
    // round-trip-through-bash test moved with it. Single source of
    // truth (one fix, every caller benefits).

    #[test]
    fn host_matches_glob_pattern() {
        assert!(host_matches("*.example.com", "api.example.com"));
        assert!(!host_matches("*.example.com", "elsewhere.tld"));
    }

    #[test]
    fn report_with_no_findings_uses_friendly_empty_state() {
        let bank = PersistedGeneBank {
            schema: 1,
            hosts: HashMap::new(),
        };
        let args = ReportArgs {
            proxy_bank: vec![],
            scan_json: vec![],
            scan_stdin: false,
            only_host: vec![],
            output: None,
            target_template: None,
            param: "q".into(),
            payload: "x".into(),
            format: "markdown".into(),
        };
        let md = render_markdown(&bank, &[], &args);
        assert!(md.contains("No bypasses recorded yet"));
    }

    #[test]
    fn json_format_emits_stable_schema() {
        let bank = fake_bank();
        let mut hosts: Vec<_> = bank
            .hosts
            .iter()
            .filter(|(_, hs)| !hs.proven_winners.is_empty())
            .collect();
        hosts.sort_by(|a, b| a.0.cmp(b.0));
        let args = ReportArgs {
            proxy_bank: vec![],
            scan_json: vec![],
            scan_stdin: false,
            only_host: vec![],
            output: None,
            target_template: None,
            param: "q".into(),
            payload: "x".into(),
            format: "json".into(),
        };
        let json = render_json(&bank, &hosts, &args).expect("json must serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        // Stable top-level keys.
        assert_eq!(parsed["schema_version"], REPORT_SCHEMA_VERSION);
        assert_eq!(parsed["source_schema"], 1);
        assert_eq!(parsed["total_hosts"], 2);
        assert_eq!(parsed["hosts_with_bypasses"], 1);
        // Finding payload.
        let findings = parsed["findings"].as_array().expect("findings array");
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f["host"], "api.example.com");
        assert_eq!(f["waf"], "ModSecurity-CRS");
        assert_eq!(f["proven_techniques"][0], "EncodingUrl");
        assert_eq!(f["blocklisted_techniques"][0], "XssTagScript");
        // Replay command must round-trip the host literally.
        let cmd = f["replay_command"].as_str().expect("replay_command string");
        assert!(cmd.contains("--from-host 'api.example.com'"));
        assert!(cmd.contains("--target 'https://api.example.com/<PATH>'"));
        // Curl reproducer must be a single-line `curl -i …` invocation
        // pointing at the same host with the param/payload baked in.
        let curl = f["curl_command"].as_str().expect("curl_command string");
        assert!(curl.starts_with("curl -i"), "got: {curl}");
        assert!(curl.contains("api.example.com"), "host present: {curl}");
        assert!(curl.contains("q=x"), "param=payload present: {curl}");
    }

    #[test]
    fn json_format_serializes_empty_findings_array() {
        // No bypasses: findings must be [], not null. Downstream tooling
        // that does `len(findings)` would crash on null.
        let bank = PersistedGeneBank {
            schema: 1,
            hosts: HashMap::new(),
        };
        let args = ReportArgs {
            proxy_bank: vec![],
            scan_json: vec![],
            scan_stdin: false,
            only_host: vec![],
            output: None,
            target_template: None,
            param: "q".into(),
            payload: "x".into(),
            format: "json".into(),
        };
        let json = render_json(&bank, &[], &args).expect("json must serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert!(parsed["findings"].is_array());
        assert_eq!(parsed["findings"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn merge_banks_unions_hosts_and_techniques() {
        // bank A: api.example.com with WAF + one winner
        let mut a_hosts = HashMap::new();
        a_hosts.insert(
            "api.example.com".into(),
            PersistedHostState {
                proven_winners: vec!["EncodingUrl".into()],
                blocklisted: vec!["XssTagScript".into()],
                waf_name: Some("ModSecurity".into()),
                bypass_findings: Vec::new(),
            },
        );
        let mut a = PersistedGeneBank {
            schema: 1,
            hosts: a_hosts,
        };

        // bank B: same host with a different winner + new host
        let mut b_hosts = HashMap::new();
        b_hosts.insert(
            "api.example.com".into(),
            PersistedHostState {
                proven_winners: vec!["EncodingUrl".into(), "GrammarTautology".into()],
                blocklisted: vec!["CmdSubshell".into()],
                waf_name: None,
                bypass_findings: Vec::new(),
            },
        );
        b_hosts.insert(
            "edge.example.com".into(),
            PersistedHostState {
                proven_winners: vec!["HeaderHostShard".into()],
                blocklisted: vec![],
                waf_name: Some("Cloudflare".into()),
                bypass_findings: Vec::new(),
            },
        );
        let b = PersistedGeneBank {
            schema: 2,
            hosts: b_hosts,
        };

        merge_banks(&mut a, b);

        // schema becomes max
        assert_eq!(a.schema, 2);
        // host union
        assert_eq!(a.hosts.len(), 2);
        assert!(a.hosts.contains_key("edge.example.com"));
        // techniques unioned + dedup'd, dst order preserved then src appended
        let api = a.hosts.get("api.example.com").unwrap();
        assert_eq!(
            api.proven_winners,
            vec!["EncodingUrl".to_string(), "GrammarTautology".to_string()]
        );
        assert_eq!(
            api.blocklisted,
            vec!["XssTagScript".to_string(), "CmdSubshell".to_string()]
        );
        // first non-null waf_name wins (dst's ModSecurity beats src's None)
        assert_eq!(api.waf_name.as_deref(), Some("ModSecurity"));
        // edge picked up Cloudflare from src since dst had no entry
        let edge = a.hosts.get("edge.example.com").unwrap();
        assert_eq!(edge.waf_name.as_deref(), Some("Cloudflare"));
    }

    // ── host_from_target ──────────────────────────────────────

    #[test]
    fn host_from_target_extracts_host_from_full_url() {
        assert_eq!(host_from_target("http://example.com/api"), "example.com");
        assert_eq!(
            host_from_target("https://api.example.com/"),
            "api.example.com"
        );
    }

    #[test]
    fn host_from_target_strips_port() {
        assert_eq!(
            host_from_target("http://example.com:8080/api"),
            "example.com"
        );
        assert_eq!(host_from_target("https://example.com:443/"), "example.com");
    }

    #[test]
    fn host_from_target_strips_userinfo() {
        assert_eq!(
            host_from_target("http://user:pass@example.com/admin"),
            "example.com"
        );
    }

    #[test]
    fn host_from_target_lowercases_host() {
        assert_eq!(
            host_from_target("https://API.EXAMPLE.COM/path"),
            "api.example.com"
        );
    }

    #[test]
    fn host_from_target_handles_no_scheme() {
        assert_eq!(host_from_target("example.com/api"), "example.com");
    }

    #[test]
    fn host_from_target_handles_query_string() {
        assert_eq!(host_from_target("http://x.com/api?a=1"), "x.com");
    }

    #[test]
    fn host_from_target_handles_fragment() {
        assert_eq!(host_from_target("http://x.com/api#frag"), "x.com");
    }

    #[test]
    fn host_from_target_empty_host_falls_back_to_unknown() {
        assert_eq!(host_from_target(""), "unknown-host");
        assert_eq!(host_from_target("http:///path"), "unknown-host");
    }

    // ── glob_match ────────────────────────────────────────────

    #[test]
    fn glob_match_literal_string_matches() {
        assert!(glob_match("example.com", "example.com"));
        assert!(!glob_match("example.com", "other.com"));
    }

    #[test]
    fn glob_match_is_case_insensitive() {
        assert!(glob_match("Example.Com", "example.COM"));
    }

    #[test]
    fn glob_match_star_matches_zero_or_more_chars() {
        assert!(glob_match("*.example.com", "api.example.com"));
        assert!(glob_match("*.example.com", "deep.api.example.com"));
        // Zero-char match.
        assert!(glob_match("api*.example.com", "api.example.com"));
    }

    #[test]
    fn glob_match_question_matches_exactly_one() {
        assert!(glob_match("?", "a"));
        assert!(!glob_match("?", ""));
        assert!(!glob_match("?", "ab"));
    }

    #[test]
    fn glob_match_double_star_collapses() {
        // `**` should match anything (zero or more chars). The recurse
        // logic handles this naturally (verify it doesn't blow up).
        assert!(glob_match("**", "any.host.here"));
        assert!(glob_match("a**b", "axxxxxxb"));
    }

    #[test]
    fn glob_match_empty_pattern_only_matches_empty_string() {
        assert!(glob_match("", ""));
        assert!(!glob_match("", "x"));
    }

    #[test]
    fn glob_match_no_partial_match() {
        // The glob is anchored (no prefix/suffix match unless `*`).
        assert!(!glob_match("api", "api.example.com"));
        assert!(glob_match("api*", "api.example.com"));
    }

    // ── ingest_scan_json ──────────────────────────────────────

    #[test]
    fn ingest_scan_json_parses_bare_scan_object() {
        let json = r#"{
            "target": "http://example.com",
            "waf": "ModSecurity",
            "bypass_variants": [
                {"techniques": ["EncodingUrl", "GrammarTautology"]}
            ]
        }"#;
        let bank = ingest_scan_json(json, "stdin").unwrap();
        let host = bank.hosts.get("example.com").expect("host present");
        assert_eq!(host.proven_winners.len(), 2);
        assert!(host.proven_winners.contains(&"EncodingUrl".to_string()));
        assert_eq!(host.waf_name.as_deref(), Some("ModSecurity"));
    }

    #[test]
    fn ingest_scan_json_unwraps_report_layers_envelope() {
        // The `--report-layers` JSON nests the scan object under
        // `"scan"`. ingest_scan_json should unwrap that.
        let json = r#"{
            "scan": {
                "target": "http://example.com",
                "waf": "ModSecurity",
                "bypass_variants": []
            }
        }"#;
        let bank = ingest_scan_json(json, "stdin").unwrap();
        assert!(bank.hosts.contains_key("example.com"));
    }

    #[test]
    fn ingest_scan_json_dedupes_repeated_techniques() {
        let json = r#"{
            "target": "http://example.com",
            "bypass_variants": [
                {"techniques": ["EncodingUrl", "EncodingUrl", "GrammarTautology"]},
                {"techniques": ["GrammarTautology", "EncodingHex"]}
            ]
        }"#;
        let bank = ingest_scan_json(json, "stdin").unwrap();
        let host = bank.hosts.get("example.com").unwrap();
        // EncodingUrl and GrammarTautology de-duped; total = 3 unique.
        assert_eq!(host.proven_winners.len(), 3);
        let mut sorted = host.proven_winners.clone();
        sorted.sort();
        assert_eq!(
            sorted,
            vec![
                "EncodingHex".to_string(),
                "EncodingUrl".to_string(),
                "GrammarTautology".to_string(),
            ]
        );
    }

    #[test]
    fn ingest_scan_json_treats_waf_none_as_no_waf_name() {
        // The scan JSON emits `"waf": "None"` when no WAF detected.
        // ingest_scan_json should NOT set a waf_name in that case
        // matched waf_name: None.
        let json = r#"{
            "target": "http://example.com",
            "waf": "None",
            "bypass_variants": []
        }"#;
        let bank = ingest_scan_json(json, "stdin").unwrap();
        let host = bank.hosts.get("example.com").unwrap();
        assert!(host.waf_name.is_none());
    }

    #[test]
    fn ingest_scan_json_rejects_input_without_target_field() {
        let json = r#"{"bypass_variants": []}"#;
        let err = ingest_scan_json(json, "stdin").unwrap_err();
        assert!(err.contains("target"));
    }

    #[test]
    fn ingest_scan_json_rejects_malformed_json() {
        let err = ingest_scan_json("not json", "stdin").unwrap_err();
        assert!(err.contains("parse"));
    }

    // ── curl_reproducer ──────────────────────────────────────

    #[test]
    fn curl_reproducer_builds_a_well_formed_curl_for_real_url() {
        let out = curl_reproducer("https://example.com/api", "q", "test");
        // Starts with the canonical `curl -i` (no -X for GET).
        assert!(out.starts_with("curl -i "), "got: {out}");
        // URL is single-quoted (via shell_single_quote) and carries
        // the query.
        assert!(
            out.contains("'https://example.com/api?q=test'"),
            "got: {out}"
        );
        // No body flag for GET.
        assert!(!out.contains("--data-binary"), "got: {out}");
    }

    #[test]
    fn curl_reproducer_url_encodes_special_chars_in_payload_via_url_parser() {
        let out = curl_reproducer("https://x.example/", "q", "' OR 1=1--");
        // reqwest's Url::query_pairs_mut applies form-urlencoding.
        // The apostrophe rides through (form-urlencoding only encodes
        // a small set), but spaces become `+`.
        assert!(out.contains("q="), "got: {out}");
        assert!(out.contains("OR+1%3D1"), "got: {out}");
    }

    #[test]
    fn curl_reproducer_shell_quotes_payload_for_safety() {
        // A payload with apostrophes must arrive escaped, single-
        // quote shell escape becomes `'\''`. The outer URL is wrapped
        // in `'…'` so the inner `'` MUST be split out.
        let out = curl_reproducer("https://x.example/", "q", "a'b");
        // The escape produces `'\''` between two surrounding apostrophes.
        // We just assert the dangerous raw `'a'b'` form is NEVER present.
        assert!(!out.contains("'a'b'"), "raw apostrophe leaked: {out}");
    }

    #[test]
    fn curl_reproducer_handles_path_placeholder_target_via_url_encoding() {
        // The default report target is `https://{host}/<PATH>`
        // reqwest::Url::parse accepts it by URL-encoding `<` and `>`
        // to `%3C` / `%3E`. Operator hand-edits the path before
        // running. Still produces a usable curl line.
        let out = curl_reproducer("https://api.example/<PATH>", "q", "x");
        assert!(out.starts_with("curl -i "), "got: {out}");
        assert!(out.contains("api.example"), "got: {out}");
        // `<PATH>` is URL-encoded by reqwest, operator un-escapes
        // before running.
        assert!(out.contains("%3CPATH%3E"), "got: {out}");
        assert!(out.contains("q=x"), "got: {out}");
    }

    #[test]
    fn curl_reproducer_url_path_encodes_payload_via_form_urlencoding() {
        // reqwest::Url::query_pairs_mut uses application/x-www-form-
        // urlencoded: spaces become `+`, apostrophes get %-encoded
        // (`%27`). The fallback path is only reached on a TRULY
        // unparseable target (see `curl_reproducer_fallback_*` below).
        let out = curl_reproducer("https://x/<PATH>", "q", "a b'");
        assert!(out.contains("q=a+b%27"), "got: {out}");
    }

    #[test]
    fn curl_reproducer_fallback_handles_truly_malformed_target() {
        // Target with no scheme, reqwest::Url::parse rejects (it
        // demands an absolute URL). Falls into the manual encoding
        // path. Confirms the function never panics on adversarial
        // operator input.
        let out = curl_reproducer("noscheme.example/<PATH>", "q", "a b");
        assert!(out.starts_with("curl -i "), "got: {out}");
        // Manual encoder uses %20 for spaces (not `+`).
        assert!(out.contains("q=a%20b"), "got: {out}");
    }

    #[test]
    fn curl_reproducer_fallback_url_encodes_metachars_in_payload() {
        // Same fallback path, confirms `'` and `=` are %-encoded
        // when the target is unparseable.
        let out = curl_reproducer("badtarget", "q", "a=b'");
        assert!(out.contains("q=a%3Db%27"), "got: {out}");
    }

    // ── render_markdown, curl + replay blocks both present ──

    #[test]
    fn render_markdown_emits_both_replay_and_curl_reproducer_blocks() {
        let bank = fake_bank();
        let hosts: Vec<_> = bank
            .hosts
            .iter()
            .filter(|(_, hs)| !hs.proven_winners.is_empty())
            .collect();
        let args = ReportArgs {
            proxy_bank: vec![],
            scan_json: vec![],
            scan_stdin: false,
            only_host: vec![],
            output: None,
            target_template: None,
            param: "q".into(),
            payload: "PAYLOAD".into(),
            format: "markdown".into(),
        };
        let md = render_markdown(&bank, &hosts, &args);
        assert!(
            md.contains("Reproduce via wafrift replay"),
            "missing replay heading"
        );
        assert!(
            md.contains("Reproduce via raw curl"),
            "missing curl heading"
        );
        // Curl invocation must appear inside the markdown.
        assert!(md.contains("curl -i "), "curl block missing: {md}");
    }

    // ── urlencoding_query ────────────────────────────────────

    #[test]
    fn urlencoding_query_passes_unreserved_chars_through() {
        assert_eq!(
            urlencoding_query("HelloWorld-123_test.~"),
            "HelloWorld-123_test.~"
        );
    }

    #[test]
    fn urlencoding_query_percent_encodes_specials() {
        assert_eq!(urlencoding_query(" "), "%20");
        assert_eq!(urlencoding_query("'"), "%27");
        assert_eq!(urlencoding_query("="), "%3D");
        assert_eq!(urlencoding_query("&"), "%26");
    }

    // ── bypass_findings end-to-end ─────────────────────────────────

    fn fixture_scan_json_with_two_bypasses() -> String {
        // Mirrors the shape `scan/mod.rs` emits under --format json,
        // including the new `repro_curl` field on each variant.
        serde_json::json!({
            "scan_schema_version": 1,
            "target": "https://example.com/api",
            "waf": "Cloudflare",
            "total_variants": 30,
            "bypassed": 2,
            "blocked": 28,
            "errors": 0,
            "bypass_rate_pct": 6.7,
            "bypass_variants": [
                {
                    "variant": 1,
                    "payload": "%27%20OR%201%3D1--",
                    "techniques": ["url", "case_swap"],
                    "confidence": 0.93,
                    "repro_curl": "curl -G --data-urlencode 'q=%27 OR 1=1--' 'https://example.com/api'",
                    "minimal_payload": null
                },
                {
                    "variant": 17,
                    "payload": "/**/UNION/**/SELECT",
                    "techniques": ["sql_comment"],
                    "confidence": 0.81,
                    "repro_curl": "curl -G --data-urlencode 'q=/**/UNION/**/SELECT' 'https://example.com/api'",
                    "minimal_payload": "UNION SELECT"
                }
            ]
        })
        .to_string()
    }

    #[test]
    fn ingest_scan_json_captures_bypass_findings_not_just_techniques() {
        let raw = fixture_scan_json_with_two_bypasses();
        let bank = ingest_scan_json(&raw, "fixture").expect("ingest");
        let state = bank
            .hosts
            .get("example.com")
            .expect("host present after ingestion");
        assert_eq!(state.bypass_findings.len(), 2);
        assert_eq!(state.bypass_findings[0].variant, 1);
        assert_eq!(state.bypass_findings[0].payload, "%27%20OR%201%3D1--");
        assert_eq!(
            state.bypass_findings[0].techniques,
            vec!["url", "case_swap"]
        );
        assert!(state.bypass_findings[0].repro_curl.is_some());
        assert!(state.bypass_findings[0].minimal_payload.is_none());
        // The distilled payload of the second finding must round-
        // trip through serde unchanged.
        assert_eq!(
            state.bypass_findings[1].minimal_payload.as_deref(),
            Some("UNION SELECT")
        );
    }

    #[test]
    fn render_markdown_emits_actual_bypass_payloads_when_present() {
        let raw = fixture_scan_json_with_two_bypasses();
        let bank = ingest_scan_json(&raw, "fixture").expect("ingest");
        let hosts: Vec<(&String, &PersistedHostState)> = bank.hosts.iter().collect();
        let args = ReportArgs {
            output: None,
            scan_json: Vec::new(),
            scan_stdin: false,
            proxy_bank: Vec::new(),
            target_template: Some("https://example.com/api".into()),
            param: "q".into(),
            payload: "placeholder".into(),
            only_host: Vec::new(),
            format: "markdown".into(),
        };
        let md = render_markdown(&bank, &hosts, &args);
        // Both concrete payloads must appear in the rendered
        // markdown (not just the technique labels).
        assert!(
            md.contains("%27%20OR%201%3D1--"),
            "first concrete payload missing from markdown:\n{md}"
        );
        assert!(
            md.contains("/**/UNION/**/SELECT"),
            "second concrete payload missing from markdown:\n{md}"
        );
        // The repro_curl line must surface so the report is
        // copy-pasteable into a pentest deliverable.
        assert!(
            md.contains("curl -G --data-urlencode"),
            "repro_curl missing from markdown:\n{md}"
        );
        // Distilled-minimum callout must surface when present.
        assert!(
            md.contains("Distilled minimum"),
            "minimal_payload callout missing:\n{md}"
        );
    }

    #[test]
    fn render_markdown_omits_payloads_section_for_proxy_bank_only_input() {
        // When only a proxy gene bank is loaded (no scan JSON), the
        // bypass_findings list is empty and the "Bypass payloads"
        // section must not appear, preserves the historical
        // proxy-bank-only report shape exactly.
        let mut bank = PersistedGeneBank::default();
        bank.hosts.insert(
            "x.test".into(),
            PersistedHostState {
                proven_winners: vec!["url".into()],
                blocklisted: Vec::new(),
                waf_name: Some("Akamai".into()),
                bypass_findings: Vec::new(),
            },
        );
        let hosts: Vec<(&String, &PersistedHostState)> = bank.hosts.iter().collect();
        let args = ReportArgs {
            output: None,
            scan_json: Vec::new(),
            scan_stdin: false,
            proxy_bank: Vec::new(),
            target_template: None,
            param: "q".into(),
            payload: "x".into(),
            only_host: Vec::new(),
            format: "markdown".into(),
        };
        let md = render_markdown(&bank, &hosts, &args);
        assert!(
            !md.contains("Bypass payloads"),
            "proxy-bank-only render must NOT show the bypass-payloads section:\n{md}"
        );
    }

    #[test]
    fn merge_banks_uniques_findings_on_variant_and_payload() {
        // Two ingestions of the same scan must NOT double-list the
        // same bypass.
        let raw = fixture_scan_json_with_two_bypasses();
        let bank_a = ingest_scan_json(&raw, "a").expect("ingest a");
        let bank_b = ingest_scan_json(&raw, "b").expect("ingest b");
        let mut merged = PersistedGeneBank::default();
        merge_banks(&mut merged, bank_a);
        merge_banks(&mut merged, bank_b);
        let state = merged
            .hosts
            .get("example.com")
            .expect("host present after merge");
        assert_eq!(
            state.bypass_findings.len(),
            2,
            "merged bypasses must not duplicate on identical input"
        );
    }

    #[test]
    fn render_json_includes_bypass_findings_in_findings_array() {
        let raw = fixture_scan_json_with_two_bypasses();
        let bank = ingest_scan_json(&raw, "fixture").expect("ingest");
        let hosts: Vec<(&String, &PersistedHostState)> = bank.hosts.iter().collect();
        let args = ReportArgs {
            output: None,
            scan_json: Vec::new(),
            scan_stdin: false,
            proxy_bank: Vec::new(),
            target_template: Some("https://example.com/api".into()),
            param: "q".into(),
            payload: "placeholder".into(),
            only_host: Vec::new(),
            format: "json".into(),
        };
        let body = render_json(&bank, &hosts, &args).expect("render");
        let v: serde_json::Value = serde_json::from_str(&body).expect("parse");
        let findings = v["findings"].as_array().expect("findings array");
        assert_eq!(findings.len(), 1);
        let bf = findings[0]["bypass_findings"]
            .as_array()
            .expect("bypass_findings array");
        assert_eq!(bf.len(), 2);
        assert_eq!(bf[0]["payload"], "%27%20OR%201%3D1--");
        assert_eq!(bf[1]["payload"], "/**/UNION/**/SELECT");
    }

    // ── OOM / bounded-read boundary tests ────────────────────────────────────

    /// Anti-rig: scan_json bounded read must reject a file at (cap + 1) bytes
    /// and accept one at exactly cap bytes. Pins the OOM defence added in the
    /// audit pass that replaced unbounded fs::read_to_string.
    ///
    /// We use a small synthetic cap (4 KiB) so the test doesn't allocate
    /// GENE_BANK_FILE_MAX_BYTES (64 MiB) of RAM. The boundary predicate
    /// is identical regardless of cap value.
    #[test]
    fn scan_json_bounded_read_cap_boundary() {
        use std::io::Write;
        let cap: usize = 4 * 1024; // 4 KiB synthetic cap for test speed

        let dir = std::env::temp_dir();
        let at_cap_path = dir.join("wafrift_test_at_cap.bin");
        let over_cap_path = dir.join("wafrift_test_over_cap.bin");

        // File at exactly the cap (must succeed).
        {
            let mut f = std::fs::File::create(&at_cap_path).expect("create at-cap");
            f.write_all(&vec![b' '; cap]).expect("write at-cap");
        }
        let result_at = crate::safe_body::read_bounded_text_file(&at_cap_path, cap);
        let _ = std::fs::remove_file(&at_cap_path);
        assert!(
            result_at.is_ok(),
            "file exactly at cap must be accepted, got: {result_at:?}"
        );

        // File one byte over the cap (must be rejected (Overrun)).
        {
            let mut f = std::fs::File::create(&over_cap_path).expect("create over-cap");
            f.write_all(&vec![b' '; cap + 1]).expect("write over-cap");
        }
        let result_over = crate::safe_body::read_bounded_text_file(&over_cap_path, cap);
        let _ = std::fs::remove_file(&over_cap_path);
        assert!(
            matches!(
                result_over,
                Err(crate::safe_body::ReadError::Overrun { .. })
            ),
            "file one byte past cap must be Overrun, got: {result_over:?}"
        );
    }

    /// proxy_bank path that does not exist → graceful error, not panic.
    #[test]
    fn proxy_bank_missing_file_exits_cleanly() {
        let missing = std::env::temp_dir().join("wafrift_test_no_such_bank.json");
        // Ensure it really does not exist.
        let _ = std::fs::remove_file(&missing);
        assert!(
            !missing.exists(),
            "precondition: file must not exist for this test"
        );
        // The production path does `if !path.exists() { … }` before the
        // bounded read. Verify read_bounded_text_file returns a Transport
        // error so our exists()-before-open ordering is correct.
        let result = crate::safe_body::read_bounded_text_file(
            &missing,
            crate::safe_body::GENE_BANK_FILE_MAX_BYTES,
        );
        assert!(
            matches!(result, Err(crate::safe_body::ReadError::Transport(_))),
            "missing file must be Transport error, got: {result:?}"
        );
    }