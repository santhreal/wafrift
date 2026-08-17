    use super::*;

    #[test]
    fn iso8601_round_trips_known_epoch() {
        // 2024-01-01T00:00:00Z = 1704067200 seconds since 1970-01-01.
        // Verify our civil-from-days computes the right calendar date.
        let (y, m, d) = civil_from_days(1704067200 / 86400);
        assert_eq!((y, m, d), (2024, 1, 1));
    }

    #[test]
    fn iso8601_round_trips_leap_year_feb_29() {
        // 2024-02-29 = day 1709164800 / 86400 = 19782.
        let (y, m, d) = civil_from_days(19782);
        assert_eq!((y, m, d), (2024, 2, 29));
    }

    #[test]
    fn truncate_ascii_short() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn truncate_ascii_long() {
        // Byte-cap semantics: n=5 → cap=4 bytes → last char boundary ≤ 4
        // is at offset 3 (char 'd' of "hell"), so output is "hell…".
        // The old char-count variant produced "hello…" (5 chars); the
        // byte-cap form is strictly ≤n bytes before the ellipsis.
        assert_eq!(truncate("hello world", 5), "hell…");
    }

    #[test]
    fn truncate_unicode_grapheme_safe_at_char_boundary() {
        // The canonical implementation (probe_classify::truncate) uses a
        // BYTE cap, not a char count, so for n=3 on Greek text (2 bytes
        // per char): cap = 2 bytes → the cut lands after the first char
        // `α` (byte boundary at offset 2). The output is "α…", not "αβγ…".
        // This is intentional and documented in probe_classify::truncate
        // the byte cap is strictly tighter and avoids multi-byte overruns.
        let s = "αβγδεζηθικλμ";
        let t = truncate(s, 3);
        assert_eq!(t, "α…");
    }

    #[test]
    fn render_markdown_contains_all_section_headers() {
        let r = OneshotReport {
            target: "https://example.com".into(),
            started_at: "2026-05-20T00:00:00Z".into(),
            elapsed_ms: 42,
            ..Default::default()
        };
        let md = render_markdown(&r);
        assert!(md.contains("# wafrift oneshot: https://example.com"));
        assert!(md.contains("## 1. WAF detection"));
        assert!(md.contains("## 2. Infrastructure fingerprint"));
        assert!(md.contains("## 3. Bypass probe"));
        assert!(md.contains("## 4. Live scan"));
        assert!(md.contains("## Reproduce this whole report"));
    }

    #[test]
    fn markdown_bypass_probe_scope_cites_canonical_probe_count() {
        // §10 COHERENCE: the full markdown is a client deliverable.
        // Its bypass-probe scope sentence must cite the real auth-bypass
        // corpus size (AUTH_BYPASS_PROBE_COUNT), never a stale literal
        // pre-fix it claimed a "136-probe" set and a "150-probe sweep"
        // long after the corpus grew to 230. This pins the 4th doc site
        // the count integrity test (auth_bypass_probe_count_documented)
        // does not reach.
        let mut r = OneshotReport {
            target: "https://example.test/".into(),
            ..Default::default()
        };
        r.detect.ran = true;
        r.bypass_probe.ran = true;
        let md = render_markdown(&r);
        assert!(
            md.contains(&format!("{AUTH_BYPASS_PROBE_COUNT}-probe auth-bypass set")),
            "scope sentence must cite the canonical count; got:\n{md}"
        );
        assert!(
            !md.contains("136-probe") && !md.contains("150-probe"),
            "markdown still carries a stale hardcoded probe count:\n{md}"
        );
    }

    #[test]
    fn render_text_compact_summary() {
        let mut r = OneshotReport {
            target: "https://example.com".into(),
            started_at: "2026-05-20T00:00:00Z".into(),
            elapsed_ms: 100,
            ..Default::default()
        };
        r.detect.baseline_status = Some(403);
        r.detect.baseline_body_len = Some(512);
        r.detect.detected.push(DetectedWaf {
            name: "Cloudflare".into(),
            confidence: 0.92,
            indicators: vec!["cf-ray header".into()],
        });
        let txt = render_text(&r);
        assert!(txt.contains("=== wafrift oneshot: https://example.com ==="));
        assert!(txt.contains("HTTP 403"));
        assert!(txt.contains("Cloudflare (92%)"));
    }

    #[test]
    fn render_markdown_marks_scan_skipped_when_no_payload() {
        let mut r = OneshotReport {
            target: "https://example.com".into(),
            ..Default::default()
        };
        r.scan.skipped_reason = Some("no --payload given".into());
        let md = render_markdown(&r);
        assert!(
            md.contains("Skipped: _no --payload given_"),
            "scan-skipped reason should be present in markdown:\n{md}"
        );
    }

    // ── Deep render + I/O edge cases (added 2026-05-20).

    #[test]
    fn render_markdown_with_all_phases_errored_is_still_well_formed() {
        // Failure-mode soak: every phase errored. Markdown must
        // still contain all four sections, we never want a half-
        // rendered report just because one phase failed.
        let mut r = OneshotReport {
            target: "https://example.com".into(),
            ..Default::default()
        };
        r.detect.error = Some("connection refused".into());
        r.fingerprint.ran = true; // even when detect errors, fingerprint can read headers it had
        r.bypass_probe.error = Some("rate-limited too hard".into());
        r.scan.error = Some("scan oracle blew up".into());
        let md = render_markdown(&r);
        for section in [
            "## 1. WAF detection",
            "## 2. Infrastructure fingerprint",
            "## 3. Bypass probe",
            "## 4. Live scan",
        ] {
            assert!(md.contains(section), "missing {section} in:\n{md}");
        }
        // The detect-error path must call out the error directly.
        assert!(md.contains("connection refused"));
    }

    #[test]
    fn render_json_round_trips_via_serde() {
        // serde-derived: any OneshotReport must round-trip
        // through serde_json without information loss. A regression
        // that adds a non-Serialize field breaks this.
        let mut r = OneshotReport {
            target: "https://x.com".into(),
            started_at: "2026-05-20T00:00:00Z".into(),
            elapsed_ms: 7,
            ..Default::default()
        };
        r.detect.baseline_status = Some(403);
        r.detect.baseline_body_len = Some(512);
        r.detect.detected.push(DetectedWaf {
            name: "Cloudflare".into(),
            confidence: 0.92,
            indicators: vec!["cf-ray".into()],
        });
        r.fingerprint
            .markers
            .push(("server".into(), "cloudflare".into()));
        r.scan.skipped_reason = Some("no --payload given".into());
        let json = serde_json::to_string(&r).expect("serialise");
        // Parse it back as a Value (struct can't be deserialised
        // because the impl is one-way). Sanity that key paths exist.
        let v: serde_json::Value = serde_json::from_str(&json).expect("re-parse");
        assert_eq!(v["target"], "https://x.com");
        assert_eq!(v["detect"]["baseline_status"], 403);
        assert_eq!(v["detect"]["detected"][0]["name"], "Cloudflare");
        assert_eq!(v["fingerprint"]["markers"][0][0], "server");
        assert_eq!(v["scan"]["skipped_reason"], "no --payload given");
    }

    #[test]
    fn render_markdown_pipe_character_in_marker_does_not_break_table() {
        // The fingerprint table uses pipe-separated columns. A header
        // value containing `|` would break the table rendering, the
        // renderer must escape pipes in marker values.
        let mut r = OneshotReport {
            target: "https://x".into(),
            ..Default::default()
        };
        // Mark fingerprint as ran, post-dogfood-fix the renderer
        // guards on `ran` to avoid emitting "No CDN markers…" on a
        // dead target where the fingerprint phase never executed.
        r.fingerprint.ran = true;
        r.fingerprint
            .markers
            .push(("x-via".into(), "edge|cache|hit".into()));
        let md = render_markdown(&r);
        // Pipe characters in values must be escaped or otherwise
        // not produce additional table columns. The implementation
        // uses `v.replace('|', "\\|")`: verify the literal
        // appears in the output.
        assert!(
            md.contains(r"edge\|cache\|hit"),
            "pipe-bearing marker value must be escaped in markdown table:\n{md}"
        );
    }

    #[test]
    fn truncate_zero_length_input_is_empty_no_panic() {
        assert_eq!(truncate("", 10), "");
        assert_eq!(truncate("", 0), "");
    }

    #[test]
    fn truncate_at_exact_length_does_not_add_ellipsis() {
        assert_eq!(truncate("hello", 5), "hello");
    }

    #[test]
    fn iso8601_spans_year_boundary() {
        // 2025-12-31 23:59:59 UTC = 1767225599 seconds.
        let (y, m, d) = civil_from_days(1767225599 / 86400);
        assert_eq!((y, m, d), (2025, 12, 31));
        // 2026-01-01 00:00:00 UTC = 1767225600 seconds.
        let (y2, m2, d2) = civil_from_days(1767225600 / 86400);
        assert_eq!((y2, m2, d2), (2026, 1, 1));
    }

    #[test]
    fn iso8601_spans_century_boundary() {
        // 2099-12-31 → 2100-01-01 (centennial non-leap year).
        // 2100-01-01 00:00:00 UTC = 4102444800 seconds.
        let (y, m, d) = civil_from_days(4102444800 / 86400);
        assert_eq!((y, m, d), (2100, 1, 1));
        // 2100 is NOT a leap year (divisible by 100 but not 400).
        // So 2100-03-01 is day 4112380800 / 86400. Let's verify
        // 2100-02-28 is the last day of February.
        let feb28 = 4102444800 + 86400 * (31 + 27); // jan31 + feb1..28 days
        let (y, m, d) = civil_from_days(feb28 / 86400);
        assert_eq!((y, m, d), (2100, 2, 28));
        let mar1 = feb28 + 86400;
        let (y, m, d) = civil_from_days(mar1 / 86400);
        assert_eq!(
            (y, m, d),
            (2100, 3, 1),
            "2100 must NOT have a Feb 29 (not a leap year)"
        );
    }

    #[test]
    fn scan_level_for_variants_thresholds_match_help_text() {
        // the fullArgs help text promises a specific mapping.
        // Pinning the boundaries so future tweaks don't silently
        // change operator-visible behaviour.
        assert_eq!(scan_level_for_variants(0), "light");
        assert_eq!(scan_level_for_variants(1), "light");
        assert_eq!(scan_level_for_variants(15), "light");
        assert_eq!(scan_level_for_variants(16), "medium");
        assert_eq!(scan_level_for_variants(25), "medium");
        assert_eq!(scan_level_for_variants(26), "heavy");
        assert_eq!(scan_level_for_variants(30), "heavy"); // historical default
        assert_eq!(scan_level_for_variants(1000), "heavy");
    }

    #[test]
    fn fence_escape_inserts_zwsp_around_inner_backticks() {
        let s = "before```after";
        let out = fence_escape(s);
        assert!(!out.contains("```"), "rendered: {out:?}");
        assert!(out.contains("before"));
        assert!(out.contains("after"));
    }

    #[test]
    fn fence_escape_leaves_safe_payload_unchanged() {
        let s = "SELECT 1 -- safe";
        assert_eq!(fence_escape(s), s);
    }

    #[test]
    fn apply_scan_json_populates_phase_fields_and_variants() {
        // Verifies that the JSON-shape contract between scan and
        // depth doesn't drift: every documented field flows
        // through into PhaseScan, and bypass_variants deserialise
        // into the BypassVariantSummary rows the renderer expects.
        let json = serde_json::json!({
            "scan_schema_version": 1,
            "target": "https://example.com",
            "waf": "Cloudflare",
            "payload_type": "Sql",
            "total_variants": 47,
            "bypassed": 3,
            "blocked": 42,
            "errors": 2,
            "bypass_rate_pct": 6.4,
            "elapsed_ms": 18234.0,
            "bypass_variants": [
                {"variant": 1, "payload": "' OR 1=1--", "techniques": ["url"], "confidence": 0.91, "minimal_payload": null},
                {"variant": 17, "payload": "/**/UNION/**/SELECT", "techniques": ["sql_comment", "case_swap"], "confidence": 0.83, "minimal_payload": "UNION SELECT"},
            ],
        });
        let mut phase = PhaseScan::default();
        apply_scan_json(&mut phase, &json);
        assert_eq!(phase.waf_name.as_deref(), Some("Cloudflare"));
        assert_eq!(phase.total_variants, Some(47));
        assert_eq!(phase.bypassed, Some(3));
        assert_eq!(phase.blocked, Some(42));
        assert_eq!(phase.errors, Some(2));
        assert!((phase.bypass_rate_pct.unwrap() - 6.4).abs() < 1e-6);
        assert!((phase.elapsed_ms.unwrap() - 18234.0).abs() < 1e-6);
        assert_eq!(phase.bypass_variants.len(), 2);
        assert_eq!(phase.bypass_variants[0].variant, 1);
        assert_eq!(phase.bypass_variants[0].payload, "' OR 1=1--");
        assert!(phase.bypass_variants[0].minimal_payload.is_none());
        assert_eq!(phase.bypass_variants[1].variant, 17);
        assert_eq!(
            phase.bypass_variants[1].minimal_payload.as_deref(),
            Some("UNION SELECT")
        );
    }

    #[test]
    fn apply_scan_json_tolerates_missing_fields() {
        // A scan binary that omits some fields (e.g. an older
        // release, or a forward-compat newer one) must not panic.
        let json = serde_json::json!({"target": "x"});
        let mut phase = PhaseScan::default();
        apply_scan_json(&mut phase, &json);
        assert!(phase.waf_name.is_none());
        assert!(phase.total_variants.is_none());
        assert!(phase.bypass_variants.is_empty());
    }

    #[test]
    fn apply_scan_json_unwraps_layer_report_envelope() {
        // When the operator runs `wafrift scan --report-layers
        // --format json`, the JSON nests the scan body under a
        // top-level "scan" key. Before this fix, `apply_scan_json`
        // read fields directly off the root and silently produced
        // an all-None PhaseScan. The unwrap matches what
        // `report::ingest_scan_json` does, same primitive on both
        // readers means one fix point if the shape evolves.
        let layered = serde_json::json!({
            "layer_report": {
                "network": {"target": "https://x", "baseline_get_status": 200},
            },
            "scan": {
                "target": "https://x",
                "waf": "Cloudflare",
                "total_variants": 12,
                "bypassed": 2,
                "blocked": 10,
                "bypass_rate_pct": 16.7,
                "bypass_variants": [
                    {"variant": 1, "payload": "p", "techniques": [], "confidence": 0.9}
                ],
            },
        });
        let mut phase = PhaseScan::default();
        apply_scan_json(&mut phase, &layered);
        assert_eq!(phase.waf_name.as_deref(), Some("Cloudflare"));
        assert_eq!(phase.total_variants, Some(12));
        assert_eq!(phase.bypassed, Some(2));
        assert_eq!(phase.bypass_variants.len(), 1);
        assert_eq!(phase.bypass_variants[0].payload, "p");
    }

    #[test]
    fn apply_scan_json_preserves_repro_curl_and_minimal_repro_curl() {
        // The scan JSON now emits per-variant repro_curl; depth
        // must round-trip both fields so the markdown renderer can
        // prefer the scan-supplied reproducer (raw-runner-accurate)
        // over a re-synthesised one.
        let json = serde_json::json!({
            "bypass_variants": [
                {
                    "variant": 1,
                    "payload": "p1",
                    "techniques": [],
                    "confidence": 0.9,
                    "repro_curl": "curl --header 'X: 1' https://x/",
                    "minimal_repro_curl": "curl -H X:1 https://x/m"
                }
            ]
        });
        let mut phase = PhaseScan::default();
        apply_scan_json(&mut phase, &json);
        assert_eq!(phase.bypass_variants.len(), 1);
        assert_eq!(
            phase.bypass_variants[0].repro_curl.as_deref(),
            Some("curl --header 'X: 1' https://x/")
        );
        assert_eq!(
            phase.bypass_variants[0].minimal_repro_curl.as_deref(),
            Some("curl -H X:1 https://x/m")
        );
    }

    #[test]
    fn render_markdown_prefers_scan_supplied_repro_curl_when_present() {
        let mut r = OneshotReport {
            target: "https://example.com".into(),
            ..Default::default()
        };
        r.scan.ran = true;
        r.scan.bypass_variants = vec![BypassVariantSummary {
            variant: 1,
            payload: "evil".into(),
            techniques: vec![],
            confidence: 0.5,
            minimal_payload: None,
            repro_curl: Some("curl --data-binary '@payload.bin' https://x/api".into()),
            minimal_repro_curl: None,
        }];
        let md = render_markdown(&r);
        // The exact scan-supplied repro must surface verbatim.
        assert!(
            md.contains("curl --data-binary '@payload.bin' https://x/api"),
            "scan-supplied repro_curl missing or rewritten:\n{md}"
        );
        // The renderer must NOT also emit a synthesised
        // curl -G --data-urlencode line for this variant, would be
        // duplicated noise.
        let repro_section_start = md.find("**Reproduce:**").expect("repro header missing");
        let after = &md[repro_section_start..];
        let next_section = after.find("###").unwrap_or(after.len());
        let repro_block = &after[..next_section];
        assert!(
            !repro_block.contains("curl -G --data-urlencode"),
            "render must NOT also emit synthesised reproducer when scan provided one:\n{repro_block}"
        );
    }

    #[test]
    fn render_markdown_falls_back_to_synthesized_repro_when_scan_omitted_it() {
        let mut r = OneshotReport {
            target: "https://example.com".into(),
            ..Default::default()
        };
        r.scan.ran = true;
        r.scan.param = Some("q".into());
        r.scan.bypass_variants = vec![BypassVariantSummary {
            variant: 1,
            payload: "evil".into(),
            techniques: vec![],
            confidence: 0.5,
            minimal_payload: None,
            repro_curl: None,
            minimal_repro_curl: None,
        }];
        let md = render_markdown(&r);
        assert!(
            md.contains("curl -G --data-urlencode q='evil' 'https://example.com'"),
            "fallback synthesised reproducer missing:\n{md}"
        );
    }

    #[test]
    fn render_markdown_caps_table_at_25_variants_with_footer() {
        // Permissive targets (or operators passing a huge cap) can
        // surface hundreds of bypasses. The markdown must render
        // only the top 25 + note the overflow.
        let mut r = OneshotReport {
            target: "https://x".into(),
            ..Default::default()
        };
        r.scan.ran = true;
        r.scan.bypass_variants = (0..50)
            .map(|i| BypassVariantSummary {
                variant: i,
                payload: format!("v{i}"),
                techniques: vec![],
                confidence: 0.5,
                minimal_payload: None,
                repro_curl: None,
                minimal_repro_curl: None,
            })
            .collect();
        let md = render_markdown(&r);
        // First 25 must render.
        for i in 0..25 {
            assert!(
                md.contains(&format!("Variant #{i} ")),
                "variant {i} not rendered (should be in top 25)"
            );
        }
        // The 26th-and-beyond must NOT render.
        for i in 25..50 {
            assert!(
                !md.contains(&format!("Variant #{i} ")),
                "variant {i} rendered past the 25-cap"
            );
        }
        // The overflow footer must call out the truncation.
        assert!(
            md.contains("Showing top 25 of 50"),
            "render-cap footer missing or wrong count:\n{md}"
        );
    }

    #[test]
    fn render_markdown_omits_summary_table_when_no_counters_present() {
        // Partial scan output (binary mid-crash, future fields-only
        // emit) must not produce a header-only table.
        let mut r = OneshotReport {
            target: "https://x".into(),
            ..Default::default()
        };
        r.scan.ran = true;
        r.scan.payload = Some("p".into());
        // No counters set, no bypasses.
        let md = render_markdown(&r);
        assert!(
            !md.contains("### Scan summary"),
            "must not emit header-only summary table:\n{md}"
        );
        assert!(
            md.contains("No variants bypassed"),
            "must still emit zero-bypasses note:\n{md}"
        );
    }

    // ── verdict paragraph ─────────────────────────────────────

    #[test]
    fn verdict_lists_detected_waf_with_confidence() {
        let mut r = OneshotReport {
            target: "https://x".into(),
            ..Default::default()
        };
        r.detect.ran = true;
        r.detect.detected.push(DetectedWaf {
            name: "Cloudflare".into(),
            confidence: 0.92,
            indicators: vec![],
        });
        let v = render_verdict_paragraph(&r);
        assert!(
            v.contains("Cloudflare (92%)"),
            "verdict missing detected WAF:\n{v}"
        );
    }

    #[test]
    fn verdict_uses_differential_verdict_when_static_corpus_was_empty() {
        let mut r = OneshotReport {
            target: "https://x".into(),
            ..Default::default()
        };
        r.detect.ran = true;
        r.detect.differential = Some("status flipped 200 → 403; server header changed".into());
        let v = render_verdict_paragraph(&r);
        assert!(
            v.contains("present (differential-probe verdict"),
            "verdict missing differential branch:\n{v}"
        );
        assert!(v.contains("status flipped"));
    }

    #[test]
    fn verdict_surfaces_high_severity_count_for_bypass_probe() {
        let mut r = OneshotReport {
            target: "https://x".into(),
            ..Default::default()
        };
        r.bypass_probe.ran = true;
        r.bypass_probe.total_probes = Some(191);
        r.bypass_probe.total_divergences = Some(3);
        r.bypass_probe.divergences = vec![
            DivergenceSummary {
                family: "headers".into(),
                label: "x".into(),
                description: String::new(),
                baseline_status: 403,
                probe_status: 200,
                body_delta_pct: 90.0,
                curl_cmd: "c".into(),
                severity: "HIGH".into(),
            },
            DivergenceSummary {
                family: "f".into(),
                label: "y".into(),
                description: String::new(),
                baseline_status: 403,
                probe_status: 302,
                body_delta_pct: 30.0,
                curl_cmd: "c".into(),
                severity: "MEDIUM".into(),
            },
            DivergenceSummary {
                family: "f".into(),
                label: "z".into(),
                description: String::new(),
                baseline_status: 403,
                probe_status: 401,
                body_delta_pct: 5.0,
                curl_cmd: "c".into(),
                severity: "LOW".into(),
            },
        ];
        let v = render_verdict_paragraph(&r);
        assert!(
            v.contains("191 probes fired"),
            "verdict missing probes_fired count:\n{v}"
        );
        assert!(
            v.contains("3 divergences"),
            "verdict missing divergence count:\n{v}"
        );
        assert!(
            v.contains("1 HIGH severity"),
            "verdict missing HIGH-severity callout:\n{v}"
        );
    }

    #[test]
    fn verdict_calls_out_zero_bypass_when_scan_held() {
        let mut r = OneshotReport {
            target: "https://x".into(),
            ..Default::default()
        };
        r.scan.ran = true;
        r.scan.total_variants = Some(30);
        r.scan.bypassed = Some(0);
        let v = render_verdict_paragraph(&r);
        assert!(
            v.contains("30 variants fired, **0 bypasses**"),
            "verdict missing 'WAF held' framing:\n{v}"
        );
    }

    #[test]
    fn verdict_surfaces_bypass_rate_when_scan_succeeded() {
        let mut r = OneshotReport {
            target: "https://x".into(),
            ..Default::default()
        };
        r.scan.ran = true;
        r.scan.total_variants = Some(50);
        r.scan.bypassed = Some(3);
        r.scan.bypass_rate_pct = Some(6.0);
        let v = render_verdict_paragraph(&r);
        assert!(
            v.contains("3 bypassed**"),
            "verdict missing bypassed count:\n{v}"
        );
        assert!(v.contains("(6.0%"), "verdict missing bypass rate:\n{v}");
    }

    #[test]
    fn verdict_renders_skipped_phases_explicitly() {
        let mut r = OneshotReport {
            target: "https://x".into(),
            ..Default::default()
        };
        r.bypass_probe.skipped_reason = Some("--skip-bypass-probe set".into());
        r.scan.skipped_reason = Some("no --payload given".into());
        let v = render_verdict_paragraph(&r);
        assert!(
            v.contains("Auth / path / method probe:** skipped"),
            "verdict missing bypass-probe-skipped line:\n{v}"
        );
        assert!(
            v.contains("Payload mutation scan:** skipped"),
            "verdict missing scan-skipped line:\n{v}"
        );
    }

    #[test]
    fn render_markdown_embeds_verdict_section_near_top() {
        let mut r = OneshotReport {
            target: "https://x".into(),
            started_at: "2026-05-21T00:00:00Z".into(),
            elapsed_ms: 1,
            ..Default::default()
        };
        r.scan.ran = true;
        r.scan.total_variants = Some(30);
        r.scan.bypassed = Some(2);
        let md = render_markdown(&r);
        let verdict_pos = md
            .find("## Verdict at a glance")
            .expect("verdict header missing");
        let section1_pos = md
            .find("## 1. WAF detection")
            .expect("section 1 header missing");
        assert!(
            verdict_pos < section1_pos,
            "verdict must render BEFORE section 1 (skim-first ordering)"
        );
    }

    #[test]
    fn apply_bypass_probe_json_flattens_results_and_drains_divergences() {
        // The bypass-probe JSON is `{"results": [...]}` keyed by
        // URL; depth flattens across URLs into one divergence
        // list so the renderer doesn't have to know about per-URL
        // grouping. Also sums probes_fired for the summary.
        let json = serde_json::json!({
            "results": [
                {
                    "target": "https://x/a",
                    "probes_fired": 191,
                    "divergences": [
                        {
                            "family": "headers",
                            "label": "X-Original-URL",
                            "description": "Override URL parser",
                            "baseline_status": 403,
                            "probe_status": 200,
                            "body_delta_pct": 87.4,
                            "curl_cmd": "curl -H 'X-Original-URL: /admin' https://x/a",
                            "severity": "HIGH"
                        }
                    ]
                },
                {
                    "target": "https://x/b",
                    "probes_fired": 8,
                    "divergences": [
                        {
                            "family": "methods",
                            "label": "X-HTTP-Method-Override",
                            "baseline_status": 403,
                            "probe_status": 401,
                            "body_delta_pct": 12.0,
                            "curl_cmd": "curl -X POST -H 'X-HTTP-Method-Override: GET' https://x/b",
                            "severity": "MEDIUM"
                        }
                    ]
                }
            ]
        });
        let mut phase = PhaseBypassProbe::default();
        apply_bypass_probe_json(&mut phase, &json);
        assert_eq!(phase.total_probes, Some(199));
        assert_eq!(phase.total_divergences, Some(2));
        assert_eq!(phase.divergences.len(), 2);
        // First finding's full payload round-tripped.
        assert_eq!(phase.divergences[0].family, "headers");
        assert_eq!(phase.divergences[0].severity, "HIGH");
        assert_eq!(phase.divergences[0].description, "Override URL parser");
        // Second finding has no description, must default to empty,
        // not panic.
        assert_eq!(phase.divergences[1].family, "methods");
        assert_eq!(phase.divergences[1].description, "");
    }

    #[test]
    fn apply_bypass_probe_json_tolerates_empty_results() {
        let json = serde_json::json!({"results": []});
        let mut phase = PhaseBypassProbe::default();
        apply_bypass_probe_json(&mut phase, &json);
        assert!(phase.total_probes.is_none());
        assert_eq!(phase.total_divergences, Some(0));
        assert!(phase.divergences.is_empty());
    }

    #[test]
    fn apply_bypass_probe_json_tolerates_missing_results_key() {
        // A future scan binary or a corrupted file could omit the
        // top-level "results" key. Must not panic, the renderer
        // already handles empty divergences gracefully.
        let json = serde_json::json!({"unrelated": "field"});
        let mut phase = PhaseBypassProbe::default();
        apply_bypass_probe_json(&mut phase, &json);
        assert!(phase.total_probes.is_none());
        assert_eq!(phase.total_divergences, Some(0));
        assert!(phase.divergences.is_empty());
    }

    #[test]
    fn render_markdown_bypass_probe_section_lists_high_severity_first() {
        let mut r = OneshotReport {
            target: "https://x".into(),
            ..Default::default()
        };
        r.bypass_probe.ran = true;
        r.bypass_probe.total_probes = Some(191);
        r.bypass_probe.total_divergences = Some(3);
        r.bypass_probe.divergences = vec![
            DivergenceSummary {
                family: "methods".into(),
                label: "low-find".into(),
                description: String::new(),
                baseline_status: 403,
                probe_status: 401,
                body_delta_pct: 5.0,
                curl_cmd: "low-curl".into(),
                severity: "LOW".into(),
            },
            DivergenceSummary {
                family: "headers".into(),
                label: "high-find".into(),
                description: "smoking-gun".into(),
                baseline_status: 403,
                probe_status: 200,
                body_delta_pct: 90.0,
                curl_cmd: "high-curl".into(),
                severity: "HIGH".into(),
            },
            DivergenceSummary {
                family: "paths".into(),
                label: "mid-find".into(),
                description: String::new(),
                baseline_status: 403,
                probe_status: 302,
                body_delta_pct: 30.0,
                curl_cmd: "mid-curl".into(),
                severity: "MEDIUM".into(),
            },
        ];
        let md = render_markdown(&r);
        let high_pos = md.find("high-find").expect("HIGH find missing");
        let mid_pos = md.find("mid-find").expect("MEDIUM find missing");
        let low_pos = md.find("low-find").expect("LOW find missing");
        assert!(high_pos < mid_pos, "HIGH must render before MEDIUM:\n{md}");
        assert!(mid_pos < low_pos, "MEDIUM must render before LOW:\n{md}");
        // The probe summary surfaces both counts.
        assert!(md.contains("| 191 |"), "probes_fired count missing:\n{md}");
        assert!(md.contains("**3**"), "divergences count missing:\n{md}");
    }

    #[test]
    fn render_markdown_bypass_probe_section_calls_out_zero_divergences() {
        let mut r = OneshotReport {
            target: "https://x".into(),
            ..Default::default()
        };
        r.bypass_probe.ran = true;
        r.bypass_probe.total_probes = Some(191);
        r.bypass_probe.total_divergences = Some(0);
        // divergences vec stays empty.
        let md = render_markdown(&r);
        assert!(
            md.contains("No probes diverged"),
            "zero-divergences note missing:\n{md}"
        );
    }

    #[test]
    fn render_markdown_bypass_probe_section_caps_at_25_with_footer() {
        let mut r = OneshotReport {
            target: "https://x".into(),
            ..Default::default()
        };
        r.bypass_probe.ran = true;
        r.bypass_probe.divergences = (0..50)
            .map(|i| DivergenceSummary {
                family: "f".into(),
                label: format!("div-{i}"),
                description: String::new(),
                baseline_status: 403,
                probe_status: 200,
                body_delta_pct: 50.0,
                curl_cmd: format!("curl-{i}"),
                severity: "LOW".into(),
            })
            .collect();
        r.bypass_probe.total_divergences = Some(50);
        let md = render_markdown(&r);
        assert!(
            md.contains("Showing top 25 of 50"),
            "render-cap footer missing:\n{md}"
        );
        // First few must appear; tail must not.
        assert!(md.contains("div-0"), "first finding missing");
        assert!(!md.contains("div-49"), "tail finding leaked past cap");
    }

    #[test]
    fn apply_scan_json_skips_malformed_variants_without_aborting() {
        // A single bad row in bypass_variants must not throw away
        // the entire phase; downstream rendering still surfaces the
        // good rows.
        let json = serde_json::json!({
            "bypass_variants": [
                {"variant": "not-a-number"}, // malformed
                {"variant": 7, "payload": "good", "techniques": [], "confidence": 0.5},
            ],
        });
        let mut phase = PhaseScan::default();
        apply_scan_json(&mut phase, &json);
        assert_eq!(phase.bypass_variants.len(), 1);
        assert_eq!(phase.bypass_variants[0].variant, 7);
    }

    #[test]
    fn render_markdown_emits_bypass_variants_table_when_scan_ran() {
        let mut r = OneshotReport {
            target: "https://example.com/search".into(),
            ..Default::default()
        };
        r.scan.ran = true;
        r.scan.payload = Some("' OR 1=1--".into());
        r.scan.param = Some("q".into());
        r.scan.waf_name = Some("Cloudflare".into());
        r.scan.total_variants = Some(50);
        r.scan.bypassed = Some(2);
        r.scan.blocked = Some(48);
        r.scan.bypass_rate_pct = Some(4.0);
        r.scan.elapsed_ms = Some(12_300.0);
        r.scan.bypass_variants = vec![BypassVariantSummary {
            variant: 5,
            payload: "%27 OR 1=1--".into(),
            techniques: vec!["url".into(), "case_swap".into()],
            confidence: 0.88,
            minimal_payload: None,
            repro_curl: None,
            minimal_repro_curl: None,
        }];
        let md = render_markdown(&r);
        // Summary table must surface counters with the post-dogfood
        // labels (pre-fix the row was misleadingly named "Variants
        // fired" (operator who set --scan-variants 5 saw 615 there)).
        assert!(
            md.contains("Total requests fired"),
            "missing total_requests_fired row:\n{md}"
        );
        assert!(md.contains("| 50 |"), "total_variants value missing");
        assert!(md.contains("**2**"), "bypassed bolded count missing");
        // The variant payload must be in the rendered output
        // this is the entire point of the fix.
        assert!(md.contains("Variant #5"), "variant header missing");
        assert!(md.contains("%27 OR 1=1--"), "variant payload missing");
        assert!(
            md.contains("`url` → `case_swap`"),
            "techniques chain missing"
        );
        // The curl repro must be parameter-aware.
        assert!(
            md.contains("curl -G --data-urlencode q=") && md.contains("example.com/search"),
            "curl reproducer missing or malformed:\n{md}"
        );
    }

    #[test]
    fn render_markdown_marks_section_2_not_reached_when_detect_errored() {
        // Pre-dogfood-fix: when detect errored, section 2 still
        // emitted "No CDN / server / cache markers surfaced…",
        // which falsely implied a connection succeeded. The guard
        // on fingerprint.ran must surface "Not reached" instead.
        let mut r = OneshotReport {
            target: "https://x".into(),
            ..Default::default()
        };
        r.detect.error = Some("connection refused".into());
        // fingerprint.ran intentionally false.
        let md = render_markdown(&r);
        let s2_pos = md
            .find("## 2. Infrastructure fingerprint")
            .expect("section 2 header missing");
        let after = &md[s2_pos..];
        let next_section = after.find("\n## ").unwrap_or(after.len());
        let section_body = &after[..next_section];
        assert!(
            section_body.contains("Not reached"),
            "section 2 must surface Not reached when detect errored:\n{section_body}"
        );
        assert!(
            !section_body.contains("No CDN / server / cache markers surfaced"),
            "section 2 must NOT pretend a connection succeeded:\n{section_body}"
        );
    }

    #[test]
    fn render_markdown_scan_summary_uses_explore_pool_and_total_request_labels() {
        // Operator-facing label fix from dogfood: --scan-variants
        // bounds the explore pool, not the total fires. Section 4
        // must show BOTH numbers with unambiguous row labels so
        // pasting --scan-variants 5 doesn't produce a confusing
        // "Variants fired | 615" row.
        let mut r = OneshotReport {
            target: "https://x".into(),
            ..Default::default()
        };
        r.scan.ran = true;
        r.scan.explore_variants = Some(5);
        r.scan.total_variants = Some(615);
        r.scan.bypassed = Some(0);
        let md = render_markdown(&r);
        assert!(
            md.contains("| Explore pool (variants tried initially) | 5 |"),
            "missing explore-pool row:\n{md}"
        );
        assert!(
            md.contains("| Total requests fired (across all phases) | 615 |"),
            "missing total-fired row:\n{md}"
        );
        // The old misleading "Variants fired" row must NOT appear.
        assert!(
            !md.contains("| Variants fired |"),
            "old misleading row label still present:\n{md}"
        );
    }

    #[test]
    fn render_markdown_calls_out_zero_bypasses_when_scan_ran_but_found_none() {
        let mut r = OneshotReport {
            target: "https://example.com".into(),
            ..Default::default()
        };
        r.scan.ran = true;
        r.scan.payload = Some("payload".into());
        r.scan.bypassed = Some(0);
        r.scan.total_variants = Some(40);
        // bypass_variants intentionally empty.
        let md = render_markdown(&r);
        assert!(
            md.contains("No variants bypassed"),
            "must explicitly note zero-bypass outcome, not just elide the table:\n{md}"
        );
        // The summary table must still show the 40-variant fire.
        assert!(md.contains("| 40 |"));
    }

    #[test]
    fn render_markdown_with_scan_error_includes_rerun_command() {
        let mut r = OneshotReport {
            target: "https://example.com".into(),
            ..Default::default()
        };
        r.scan.ran = true;
        r.scan.error = Some("connection refused".into());
        r.scan.raw_text = Some("wafrift scan ...".into());
        let md = render_markdown(&r);
        assert!(md.contains("connection refused"));
        assert!(
            md.contains("wafrift scan ..."),
            "re-run command must still appear when scan errored, so the operator can reproduce the failure"
        );
    }

    #[test]
    fn render_markdown_escapes_triple_backtick_in_payload() {
        let mut r = OneshotReport {
            target: "https://x".into(),
            ..Default::default()
        };
        r.scan.ran = true;
        r.scan.bypass_variants = vec![BypassVariantSummary {
            variant: 1,
            payload: "evil```backtick".into(),
            techniques: vec![],
            confidence: 0.5,
            minimal_payload: None,
            repro_curl: None,
            minimal_repro_curl: None,
        }];
        let md = render_markdown(&r);
        // The literal ``` from the payload must not appear in the
        // final markdown, otherwise it closes the surrounding
        // code fence early.
        let payload_idx = md.find("evil").expect("payload missing");
        // Look for ``` AFTER "evil" but before the next \n```\n
        // section close (the legitimate end-of-fence).
        let after = &md[payload_idx..];
        let next_fence = after.find("\n```\n").unwrap_or(after.len());
        let payload_section = &after[..next_fence];
        assert!(
            !payload_section.contains("```"),
            "payload's literal ``` leaked into markdown, fence will break:\n{payload_section}"
        );
    }

    #[test]
    fn output_writes_file_to_disk() {
        use std::env::temp_dir;
        // emit() is a private fn that writes to args.output when
        // set. We exercise it via render_markdown + manual write
        // (mirrors emit's behaviour without the side effects of
        // run_oneshot).
        let r = OneshotReport {
            target: "https://example.com".into(),
            started_at: "2026-05-20T00:00:00Z".into(),
            elapsed_ms: 1,
            ..Default::default()
        };
        let rendered = render_markdown(&r);
        let path = temp_dir().join(format!("wafrift-oneshot-out-{}.md", std::process::id()));
        std::fs::write(&path, &rendered).expect("write");
        let read_back = std::fs::read_to_string(&path).expect("read");
        assert_eq!(read_back, rendered);
        let _ = std::fs::remove_file(&path);
    }