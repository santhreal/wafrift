    use super::*;
    use serde_json::json;

    fn bench_with_one_bypass() -> Value {
        json!({
            "schema_version": 1,
            "results": [{
                "id": "sql_blind_001",
                "class": "sql",
                "evaded": {
                    "variants_bypassed": 2,
                    "variants_total": 5,
                    "bypass_techniques": ["tamper/comment", "encoding/url/double"],
                }
            }]
        })
    }

    /// LAW 12: SARIF version + schema URI are pinned constants
    /// silently emitting a different version would break consumer
    /// validators.
    #[test]
    fn sarif_version_and_schema_uri_are_pinned() {
        assert_eq!(SARIF_VERSION, "2.1.0");
        assert!(SARIF_SCHEMA_URI.starts_with("https://"));
        assert!(SARIF_SCHEMA_URI.contains("sarif-schema-2.1.0"));
    }

    /// Empty input → empty results array, but the SARIF envelope
    /// (version, schema, tool driver, runs) is still present.
    /// Anti-rig: a tool that has never run still produces valid
    /// SARIF (no `Vec::is_empty() ? skip emit : emit` rig).
    #[test]
    fn empty_results_emits_valid_empty_sarif_envelope() {
        let j = json!({ "schema_version": 1, "results": [] });
        let results = build_sarif_results(&j, "https://target.example/");
        assert!(results.is_empty());
    }

    /// Missing `results` array → empty SARIF results (not a panic).
    /// LAW 1: a malformed input should produce honest emptiness,
    /// not a crash.
    #[test]
    fn missing_results_array_does_not_panic() {
        let j = json!({});
        let results = build_sarif_results(&j, "https://target.example/");
        assert!(results.is_empty());
    }

    /// One bypass case → one SARIF result with the expected ruleId,
    /// level, properties, and target URL.
    #[test]
    fn one_bypass_maps_to_one_sarif_result() {
        let j = bench_with_one_bypass();
        let results = build_sarif_results(&j, "https://target.example/");
        assert_eq!(results.len(), 1);
        let r = &results[0];
        assert_eq!(r.rule_id, "waf-bypass-sql");
        assert_eq!(r.level, "error");
        assert!(r.message.text.contains("class=sql"));
        assert!(r.message.text.contains("case=sql_blind_001"));
        assert!(r.message.text.contains("tamper/comment"));
        assert_eq!(r.locations.len(), 1);
        assert_eq!(
            r.locations[0].physical_location.artifact_location.uri,
            "https://target.example/"
        );
        assert_eq!(
            r.properties.get("class").and_then(|v| v.as_str()),
            Some("sql")
        );
        assert_eq!(
            r.properties
                .get("variants_bypassed")
                .and_then(|v| v.as_u64()),
            Some(2)
        );
    }

    /// Cases with `variants_bypassed == 0` MUST be dropped, these
    /// are negative evidence. Anti-rig: pre-existing test in the
    /// bench scoreboard counts them, but the SARIF finding stream
    /// must not.
    #[test]
    fn zero_bypassed_case_is_dropped() {
        let j = json!({
            "schema_version": 1,
            "results": [
                {
                    "id": "sql_001",
                    "class": "sql",
                    "evaded": { "variants_bypassed": 0, "variants_total": 5 }
                },
                {
                    "id": "sql_002",
                    "class": "sql",
                    "evaded": {
                        "variants_bypassed": 1,
                        "variants_total": 5,
                        "bypass_techniques": ["tamper/x"]
                    }
                },
            ]
        });
        let results = build_sarif_results(&j, "https://t/");
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0]
                .properties
                .get("case_id")
                .and_then(|v| v.as_str()),
            Some("sql_002")
        );
    }

    /// Results array with missing `evaded` field (e.g. a case that
    /// never ran) is silently skipped (same behaviour as cluster_cmd).
    #[test]
    fn results_without_evaded_field_are_skipped() {
        let j = json!({
            "schema_version": 1,
            "results": [
                { "id": "sql_a", "class": "sql" },
                {
                    "id": "sql_b",
                    "class": "sql",
                    "evaded": {
                        "variants_bypassed": 1,
                        "bypass_techniques": ["tamper/y"]
                    }
                },
            ]
        });
        let results = build_sarif_results(&j, "https://t/");
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0]
                .properties
                .get("case_id")
                .and_then(|v| v.as_str()),
            Some("sql_b")
        );
    }

    /// Bypass with no `bypass_techniques` field (degraded bench
    /// recorder) → SARIF result still emits with the case id in the
    /// message, but `properties.techniques` is omitted (not present
    /// as an empty array).
    #[test]
    fn bypass_with_no_techniques_field_emits_result_without_techniques_property() {
        let j = json!({
            "schema_version": 1,
            "results": [{
                "id": "sql_solo",
                "class": "sql",
                "evaded": { "variants_bypassed": 1 }
            }]
        });
        let results = build_sarif_results(&j, "https://t/");
        assert_eq!(results.len(), 1);
        assert!(results[0].properties.get("techniques").is_none());
        assert!(results[0].message.text.contains("variants_bypassed=1"));
    }

    /// Multiple classes → distinct ruleIds. SARIF consumers filter
    /// on ruleId; a class collision into one ruleId would defeat
    /// per-class dashboards.
    #[test]
    fn multiple_classes_produce_distinct_rule_ids() {
        let j = json!({
            "schema_version": 1,
            "results": [
                {
                    "id": "sql_001", "class": "sql",
                    "evaded": { "variants_bypassed": 1, "bypass_techniques": ["t1"] }
                },
                {
                    "id": "xss_001", "class": "xss",
                    "evaded": { "variants_bypassed": 1, "bypass_techniques": ["t2"] }
                },
                {
                    "id": "cmdi_001", "class": "cmdi",
                    "evaded": { "variants_bypassed": 1, "bypass_techniques": ["t3"] }
                },
            ]
        });
        let results = build_sarif_results(&j, "https://t/");
        let rule_ids: Vec<&str> = results.iter().map(|r| r.rule_id.as_str()).collect();
        assert!(rule_ids.contains(&"waf-bypass-sql"));
        assert!(rule_ids.contains(&"waf-bypass-xss"));
        assert!(rule_ids.contains(&"waf-bypass-cmdi"));
    }

    /// DOGFOOD BUG-1 regression: hunt campaign state file uses
    /// `bypasses` (not `results`). Pre-fix, this returned 0 SARIF
    /// results and exit code 0 (silently lying to CI uploaders).
    /// Post-fix: each CampaignBypass becomes one SARIF result with
    /// the campaign_id + round + class + technique in properties.
    #[test]
    fn hunt_bypasses_schema_produces_one_result_per_bypass() {
        let j = json!({
            "campaign_id": "race-test",
            "target_url": "https://waf.cumulusfire.net",
            "started_at": 1714500000u64,
            "rounds_completed": 12u64,
            "total_bypasses": 3u64,
            "schema_version": 1u32,
            "bypasses": [
                { "discovered_at": 1714500100u64, "round": 1u64, "class": "sql",
                  "technique": "tamper/comment", "submitted": false },
                { "discovered_at": 1714500200u64, "round": 2u64, "class": "xss",
                  "technique": "encoding/double-url", "submitted": true },
                { "discovered_at": 1714500300u64, "round": 3u64, "class": "ldap",
                  "technique": "split-attr", "submitted": false },
            ],
        });
        let (results, schema) = build_sarif_results_with_schema(&j, SARIF_BENCH_TARGET_PLACEHOLDER);
        assert_eq!(schema, BypassSchema::HuntBypasses);
        assert_eq!(results.len(), 3);

        let sql = results
            .iter()
            .find(|r| r.rule_id == "waf-bypass-sql")
            .unwrap();
        assert_eq!(sql.level, "error");
        assert!(sql.message.text.contains("campaign=race-test"));
        assert!(sql.message.text.contains("round=1"));
        assert!(sql.message.text.contains("tamper/comment"));
        // hunt has target_url at the top level, should be picked
        // up when caller didn't pass --target-url.
        assert_eq!(
            sql.locations[0].physical_location.artifact_location.uri,
            "https://waf.cumulusfire.net"
        );
        assert_eq!(
            sql.properties.get("campaign_id").and_then(|v| v.as_str()),
            Some("race-test")
        );
    }

    /// DOGFOOD BUG-2 regression: input JSON with neither `results`
    /// nor `bypasses` keys is reported as `Unrecognised` so run_sarif
    /// can emit exit code 2. Pre-fix, run_sarif silently emitted an
    /// empty SARIF + exit 0, lying to CI uploaders.
    #[test]
    fn unrecognised_schema_is_flagged_not_silently_zeroed() {
        let j = json!({ "some_other_key": [1, 2, 3] });
        let (results, schema) = build_sarif_results_with_schema(&j, "https://t/");
        assert!(results.is_empty());
        assert_eq!(schema, BypassSchema::Unrecognised);
    }

    /// LAW 12: pin EXIT_NO_RECOGNISED_BYPASS_KEY == 2 (a public exit
    /// code that CI pipelines may treat as "warning, no findings").
    /// A silent flip would change the script semantics.
    #[test]
    fn exit_code_for_unrecognised_schema_is_pinned() {
        assert_eq!(EXIT_NO_RECOGNISED_BYPASS_KEY, 2);
    }

    /// Bench-results format still recognised after the schema-aware
    /// rewrite (anti-regression for the original path).
    #[test]
    fn bench_results_schema_still_recognised() {
        let j = bench_with_one_bypass();
        let (results, schema) = build_sarif_results_with_schema(&j, "https://t/");
        assert_eq!(schema, BypassSchema::BenchResults);
        assert_eq!(results.len(), 1);
    }

    /// hunt input with `target_url` overrides the placeholder when
    /// caller did NOT pass --target-url, but a real --target-url
    /// argument wins.
    #[test]
    fn hunt_target_url_priority() {
        let j = json!({
            "campaign_id": "x",
            "target_url": "https://hunt.example/",
            "bypasses": [{
                "discovered_at": 1u64, "round": 1u64, "class": "sql",
                "technique": "t", "submitted": false
            }],
        });
        // Placeholder → hunt's target_url wins.
        let (r, _) = build_sarif_results_with_schema(&j, SARIF_BENCH_TARGET_PLACEHOLDER);
        assert_eq!(
            r[0].locations[0].physical_location.artifact_location.uri,
            "https://hunt.example/"
        );
        // Explicit --target-url → caller wins.
        let (r2, _) = build_sarif_results_with_schema(&j, "https://override.example/");
        assert_eq!(
            r2[0].locations[0].physical_location.artifact_location.uri,
            "https://override.example/"
        );
    }

    /// End-to-end: build a real SarifLog and serialize it. Verifies
    /// the JSON shape matches what SARIF consumers expect: `version`,
    /// `$schema`, `runs[0].tool.driver.name == "wafrift"`,
    /// `runs[0].results` array.
    #[test]
    fn full_sarif_log_serializes_with_expected_envelope() {
        let j = bench_with_one_bypass();
        let results = build_sarif_results(&j, "https://target/");
        let rules = build_rules_table(&results);
        let taxonomies = vec![build_cwe_taxonomy()];
        let log = SarifLog {
            version: SARIF_VERSION,
            schema: SARIF_SCHEMA_URI,
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "wafrift",
                        version: "0.0.0-test",
                        information_uri: "https://example/",
                        rules,
                    },
                },
                results,
                taxonomies,
            }],
        };
        let s = serde_json::to_string(&log).unwrap();
        // Round-trip back to Value to inspect the shape, this is
        // exactly what a SARIF consumer (GitHub, etc.) would do.
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["version"].as_str(), Some("2.1.0"));
        assert!(
            v["$schema"]
                .as_str()
                .unwrap()
                .contains("sarif-schema-2.1.0")
        );
        assert_eq!(
            v["runs"][0]["tool"]["driver"]["name"].as_str(),
            Some("wafrift")
        );
        assert_eq!(
            v["runs"][0]["results"][0]["ruleId"].as_str(),
            Some("waf-bypass-sql")
        );
        assert_eq!(v["runs"][0]["results"][0]["level"].as_str(), Some("error"));
    }

    // ─── SARIF 2.1.0 enterprise upgrade tests ───────────────────────────────

    /// LAW 9 wiring: rules table populated with one entry per distinct
    /// ruleId in the results. SARIF consumers (GitHub Code Scanning)
    /// dereference `result.ruleId` into `tool.driver.rules[]` to render
    /// readable rule names (a missing rule entry shows the opaque ID).
    #[test]
    fn rules_table_has_one_entry_per_distinct_rule_id() {
        let j = json!({
            "schema_version": 1,
            "results": [
                { "id": "sql_001", "class": "sql",
                  "evaded": { "variants_bypassed": 1, "bypass_techniques": ["t1"] } },
                { "id": "sql_002", "class": "sql",
                  "evaded": { "variants_bypassed": 1, "bypass_techniques": ["t2"] } },
                { "id": "xss_001", "class": "xss",
                  "evaded": { "variants_bypassed": 1, "bypass_techniques": ["t3"] } },
            ]
        });
        let results = build_sarif_results(&j, "https://t/");
        let rules = build_rules_table(&results);
        assert_eq!(rules.len(), 2, "two distinct classes → two rule entries");
        let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        assert!(ids.contains(&"waf-bypass-sql"));
        assert!(ids.contains(&"waf-bypass-xss"));
        // human name is TitleCased class
        let sql = rules.iter().find(|r| r.id == "waf-bypass-sql").unwrap();
        assert_eq!(sql.name, "WafBypassSql");
        assert_eq!(sql.default_configuration.level, "error");
    }

    /// LAW 12 anti-rig: CWE taxonomy emitted with id 942 + human name.
    /// SARIF consumers render the CWE link in the UI; a missing
    /// taxonomy makes the CWE reference dangling.
    #[test]
    fn cwe_taxonomy_includes_942_with_human_name() {
        let tax = build_cwe_taxonomy();
        assert_eq!(tax.name, "CWE");
        assert!(tax.information_uri.starts_with("https://cwe.mitre.org"));
        assert_eq!(tax.taxa.len(), 1);
        assert_eq!(tax.taxa[0].id, SARIF_CWE_ID);
        assert_eq!(tax.taxa[0].name, "CWE-942");
    }

    /// LAW 12 stable-hash invariant: same input → same fingerprint.
    /// GitHub Code Scanning uses `partialFingerprints` to dedupe
    /// alerts across PRs; a non-deterministic hash defeats that.
    #[test]
    fn finding_fingerprint_is_deterministic() {
        let f1 = finding_fingerprint("waf-bypass-sql", "https://t/", "sql_001");
        let f2 = finding_fingerprint("waf-bypass-sql", "https://t/", "sql_001");
        assert_eq!(f1, f2, "same input → same fingerprint");
        assert_eq!(f1.len(), 16, "16-hex-char u64");
    }

    /// LAW 12: different ruleIds → different fingerprints. A collision
    /// would cause GitHub to merge two genuinely different findings
    /// into one alert.
    #[test]
    fn finding_fingerprint_differs_for_different_rule_ids() {
        let sql = finding_fingerprint("waf-bypass-sql", "https://t/", "case_001");
        let xss = finding_fingerprint("waf-bypass-xss", "https://t/", "case_001");
        assert_ne!(sql, xss);
    }

    /// LAW 12: different targets → different fingerprints. Same finding
    /// against two different WAFs should NOT dedupe.
    #[test]
    fn finding_fingerprint_differs_for_different_targets() {
        let a = finding_fingerprint("waf-bypass-sql", "https://a/", "case_001");
        let b = finding_fingerprint("waf-bypass-sql", "https://b/", "case_001");
        assert_ne!(a, b);
    }

    /// LAW 9 wiring: every SarifResult carries a partialFingerprints
    /// map with `primaryLocationLineHash`. Field set but never read
    /// would be a stub (LAW 11).
    #[test]
    fn every_bench_result_has_partial_fingerprints() {
        let j = bench_with_one_bypass();
        let results = build_sarif_results(&j, "https://t/");
        assert_eq!(results.len(), 1);
        assert!(
            results[0]
                .partial_fingerprints
                .contains_key("primaryLocationLineHash"),
            "primaryLocationLineHash must be populated"
        );
    }

    /// LAW 9 wiring: every SarifResult carries a CWE-942 taxa
    /// reference. Required for GitHub Code Scanning to render the CWE
    /// link.
    #[test]
    fn every_bench_result_has_cwe_taxon_reference() {
        let j = bench_with_one_bypass();
        let results = build_sarif_results(&j, "https://t/");
        assert_eq!(results[0].taxa.len(), 1);
        assert_eq!(results[0].taxa[0].id, SARIF_CWE_ID);
        assert_eq!(results[0].taxa[0].tool_component.name, "CWE");
    }

    /// Same applies to hunt-bypasses path, both schemas must produce
    /// the enterprise fields.
    #[test]
    fn every_hunt_result_has_partial_fingerprints_and_taxa() {
        let j = json!({
            "campaign_id": "x", "target_url": "https://t/",
            "bypasses": [{ "discovered_at": 1u64, "round": 1u64,
                           "class": "sql", "technique": "t", "submitted": false }],
        });
        let (results, _) = build_sarif_results_with_schema(&j, SARIF_BENCH_TARGET_PLACEHOLDER);
        assert_eq!(results.len(), 1);
        assert!(
            results[0]
                .partial_fingerprints
                .contains_key("primaryLocationLineHash")
        );
        assert_eq!(results[0].taxa.len(), 1);
        assert_eq!(results[0].taxa[0].id, SARIF_CWE_ID);
    }

    /// LAW 9 wiring: when the bench JSON carries C-14 rule-quality
    /// fields (`case_quality` + `quality_score`), they must surface
    /// in SARIF properties so consumers can filter on them. Pre-fix,
    /// SARIF discarded these silently, operators couldn't tell
    /// "signal" cases from "trivial_pass" cases in GitHub Code
    /// Scanning.
    #[test]
    fn case_quality_fields_carry_through_to_sarif_properties() {
        let j = json!({
            "schema_version": 1,
            "results": [{
                "id": "sql_001",
                "class": "sql",
                "case_quality": "signal",
                "quality_score": 0.8113,
                "evaded": {
                    "variants_bypassed": 2,
                    "bypass_techniques": ["t1", "t2"]
                }
            }]
        });
        let results = build_sarif_results(&j, "https://t/");
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0]
                .properties
                .get("case_quality")
                .and_then(|v| v.as_str()),
            Some("signal")
        );
        let qs = results[0]
            .properties
            .get("quality_score")
            .and_then(|v| v.as_f64());
        assert!(
            qs.map(|q| (q - 0.8113).abs() < 1e-6).unwrap_or(false),
            "quality_score must round-trip: {qs:?}"
        );
    }

    /// LAW 2 backwards-compat: cases WITHOUT case_quality/quality_score
    /// (older bench JSON) still produce valid SARIF, fields are
    /// optional, no silent panic.
    #[test]
    fn missing_case_quality_fields_are_optional() {
        let j = bench_with_one_bypass();
        let results = build_sarif_results(&j, "https://t/");
        assert_eq!(results.len(), 1);
        assert!(
            results[0].properties.get("case_quality").is_none(),
            "case_quality must be absent when input JSON didn't carry it"
        );
        assert!(
            results[0].properties.get("quality_score").is_none(),
            "quality_score must be absent when input JSON didn't carry it"
        );
    }

    /// LAW 12: title_case capitalises just the first byte; ASCII-only
    /// (attack class identifiers are always ASCII).
    #[test]
    fn title_case_capitalises_first_letter_only() {
        assert_eq!(title_case("sql"), "Sql");
        assert_eq!(title_case("xss"), "Xss");
        assert_eq!(title_case("cmdi"), "Cmdi");
        assert_eq!(title_case(""), "");
        assert_eq!(title_case("a"), "A");
    }

    /// Full integration: end-to-end SARIF with the enterprise fields
    /// round-trips through serde and exposes the expected paths to
    /// consumers.
    #[test]
    fn enterprise_sarif_round_trip_exposes_rules_taxonomies_fingerprints() {
        let j = bench_with_one_bypass();
        let results = build_sarif_results(&j, "https://target/");
        let rules = build_rules_table(&results);
        let taxonomies = vec![build_cwe_taxonomy()];
        let log = SarifLog {
            version: SARIF_VERSION,
            schema: SARIF_SCHEMA_URI,
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "wafrift",
                        version: "0.0.0-test",
                        information_uri: "https://example/",
                        rules,
                    },
                },
                results,
                taxonomies,
            }],
        };
        let s = serde_json::to_string(&log).unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        // rules table is at runs[0].tool.driver.rules
        assert_eq!(
            v["runs"][0]["tool"]["driver"]["rules"][0]["id"].as_str(),
            Some("waf-bypass-sql")
        );
        assert_eq!(
            v["runs"][0]["tool"]["driver"]["rules"][0]["defaultConfiguration"]["level"].as_str(),
            Some("error")
        );
        // taxonomies at runs[0].taxonomies
        assert_eq!(v["runs"][0]["taxonomies"][0]["name"].as_str(), Some("CWE"));
        assert_eq!(
            v["runs"][0]["taxonomies"][0]["taxa"][0]["id"].as_str(),
            Some("942")
        );
        // partialFingerprints on each result
        assert!(
            v["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"]
                .as_str()
                .is_some()
        );
        // taxa reference on each result
        assert_eq!(
            v["runs"][0]["results"][0]["taxa"][0]["id"].as_str(),
            Some("942")
        );
        assert_eq!(
            v["runs"][0]["results"][0]["taxa"][0]["toolComponent"]["name"].as_str(),
            Some("CWE")
        );
    }
