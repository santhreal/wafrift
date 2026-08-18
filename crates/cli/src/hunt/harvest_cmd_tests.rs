    use super::*;
    use wafrift_evolution::coverage_feedback::PayloadClass;

    // ── policing-probe table (differential-baseline re-verify) ───────────────

    #[test]
    fn embedded_policing_probes_load_and_are_nonempty() {
        let m = load_policing_probes(POLICING_PROBES_TOML).expect("shipped probe table is valid");
        assert!(
            m.len() >= 8,
            "ship a real per-class probe table, got {}",
            m.len()
        );
        assert!(m.values().all(|p| !p.trim().is_empty()));
    }

    #[test]
    fn policing_probes_cover_every_recorded_corpus_class() {
        // The cumulusfire corpus carries exactly these classes; the differential
        // gate must have a probe for each or it would silently drop candidates.
        for class in [
            "cmdi", "sql", "ssrf", "ssti", "ldap", "nosql", "path", "xxe", "xss", "cve_pocs",
        ] {
            assert!(
                class_policing_probe(class).is_some(),
                "no policing probe for corpus class `{class}`: differential would drop it"
            );
        }
    }

    #[test]
    fn policing_probe_loader_fails_closed_on_empty() {
        assert!(load_policing_probes("# nothing\n").is_err());
        assert!(load_policing_probes("").is_err());
    }

    #[test]
    fn policing_probe_loader_rejects_an_empty_payload() {
        let bad = "[[probe]]\nclass=\"sql\"\npayload=\"\"\n";
        assert!(load_policing_probes(bad).is_err());
    }

    #[test]
    fn an_unknown_class_has_no_policing_probe() {
        assert!(class_policing_probe("totally-unknown-class").is_none());
    }

    fn bypass(class: &str, payload: &str, chain: &[&str]) -> RecordedBypass {
        RecordedBypass {
            payload: payload.to_string(),
            payload_class: PayloadClass::new(class),
            encoding_chain: chain.iter().map(|s| (*s).to_string()).collect(),
            response_hash: 0,
            observed_at_secs: 0,
            submission: SubmissionStatus::Queued,
            delivery: String::new(),
        }
    }

    #[test]
    fn weakness_id_maps_known_classes_and_defaults() {
        assert_eq!(weakness_id_for_class("sql"), 89);
        assert_eq!(weakness_id_for_class("ssrf"), 918);
        assert_eq!(weakness_id_for_class("xxe"), 611);
        // Unknown class falls back to CWE-20, never panics.
        assert_eq!(weakness_id_for_class("brand-new-class"), 20);
    }

    #[test]
    fn root_cause_technique_is_first_non_identity_step() {
        assert_eq!(
            root_cause_technique(&bypass("ssrf", "x", &["identity", "inet_aton_form"])),
            "inet_aton_form"
        );
        assert_eq!(
            root_cause_technique(&bypass("sql", "x", &["ws_equiv", "case"])),
            "ws_equiv"
        );
        // All-identity (or empty) chain → "identity".
        assert_eq!(
            root_cause_technique(&bypass("xss", "x", &["identity"])),
            "identity"
        );
        assert_eq!(root_cause_technique(&bypass("xss", "x", &[])), "identity");
    }

    #[test]
    fn collapse_keeps_one_shortest_canonical_per_class_technique() {
        // 4 SSRF inet_aton variants + 1 SSRF rfc3986 + 1 cmdi → 3 root causes,
        // and the SSRF inet_aton canonical is the SHORTEST of its group.
        let cands = vec![
            (
                "r".into(),
                bypass("ssrf", "http://0xC0.0xA8.0.1/longest", &["inet_aton_form"]),
            ),
            ("r".into(), bypass("ssrf", "//0/", &["inet_aton_form"])), // shortest
            (
                "r".into(),
                bypass("ssrf", "http://2130706433/", &["inet_aton_form"]),
            ),
            (
                "r".into(),
                bypass("ssrf", "http://allowed@0.0.0.0/", &["rfc3986_userinfo"]),
            ),
            ("r".into(), bypass("cmdi", "; id ", &["separator_swap"])),
            (
                "r".into(),
                bypass("cmdi", "; cat /etc/passwd", &["separator_swap"]),
            ),
        ];
        let out = collapse_to_root_causes(cands);
        assert_eq!(out.len(), 3, "3 unique (class × technique) root causes");
        let ssrf_inet = out
            .iter()
            .find(|(_, b)| {
                b.payload_class.as_str() == "ssrf" && root_cause_technique(b) == "inet_aton_form"
            })
            .expect("ssrf inet_aton root cause present");
        assert_eq!(
            ssrf_inet.1.payload, "//0/",
            "canonical must be the shortest variant"
        );
        let cmdi = out
            .iter()
            .find(|(_, b)| b.payload_class.as_str() == "cmdi")
            .expect("cmdi root cause present");
        assert_eq!(cmdi.1.payload, "; id ", "shortest cmdi variant kept");
    }

    #[test]
    fn collapse_is_deterministic_across_runs() {
        let mk = || {
            vec![
                ("r".into(), bypass("sql", "1 OR 1=1", &["ws_equiv"])),
                ("r".into(), bypass("sql", "1 OR 1=1", &["ws_equiv"])),
                ("r".into(), bypass("sql", "1 OR 2=2", &["ws_equiv"])),
            ]
        };
        let a = collapse_to_root_causes(mk());
        let b = collapse_to_root_causes(mk());
        assert_eq!(a.len(), 1);
        assert_eq!(
            a[0].1.payload, b[0].1.payload,
            "same corpus → same canonical"
        );
    }

    #[test]
    fn is_unhandled_only_true_for_queued_and_dryrun() {
        assert!(is_unhandled(&SubmissionStatus::Queued));
        assert!(is_unhandled(&SubmissionStatus::DryRunHold {
            release_at_secs: 1
        }));
        assert!(!is_unhandled(&SubmissionStatus::Submitted {
            report_id: "1".into()
        }));
        assert!(!is_unhandled(&SubmissionStatus::Accepted {
            report_id: "1".into()
        }));
        assert!(!is_unhandled(&SubmissionStatus::Duplicate {
            duplicate_of: "1".into()
        }));
        assert!(!is_unhandled(&SubmissionStatus::Rejected {
            reason: "na".into()
        }));
    }

    #[test]
    fn report_carries_payload_and_parses_back() {
        let bp = bypass("sql", "' OR 1=1-- x", &["ws_equiv", "keyword_morph"]);
        let (fname, content) = render_report(
            "https://waf.cumulusfire.net",
            "waf.cumulusfire.net",
            "cf:?:?",
            &bp,
            None,
            "cumulusfire",
        );
        assert!(fname.starts_with("sql-"));
        assert!(fname.ends_with(".md"));
        // The exact wire payload must appear verbatim in the report.
        assert!(content.contains("' OR 1=1-- x"));
        // The machine header must round-trip through the submit parser.
        let meta = parse_report_meta(&content).expect("header must parse");
        assert_eq!(meta.team, "cumulusfire");
        assert_eq!(meta.weakness_id, 89);
        assert_eq!(meta.severity, "high");
        // No proof was supplied → marked unverified.
        assert!(!meta.verified);
        assert!(content.contains("UNVERIFIED"));
    }

    #[test]
    fn report_filename_is_stable_and_distinct_per_payload() {
        let a = report_filename("sql", "ws_equiv", "payload-A");
        let b = report_filename("sql", "ws_equiv", "payload-B");
        let a2 = report_filename("sql", "ws_equiv", "payload-A");
        assert_eq!(a, a2, "same inputs → same filename");
        assert_ne!(a, b, "different payloads → different filenames");
    }

    #[test]
    fn curl_repro_escapes_single_quotes() {
        let c = curl_repro("https://x.test", "body_form_q", "a' OR '1'='1");
        // The single quotes in the payload must be shell-escaped so the
        // generated curl line is copy-pasteable without breaking quoting.
        assert!(c.contains("'\\''"));
        assert!(!c.contains("q=a' OR"));
    }

    #[test]
    fn parse_report_meta_rejects_non_report() {
        assert!(parse_report_meta("# just a markdown file\n\nbody").is_none());
        assert!(parse_report_meta("").is_none());
    }

    #[test]
    fn excerpt_bounds_and_strips_control_bytes() {
        let long = "A".repeat(1000);
        let e = excerpt(&long, 400);
        assert!(e.chars().count() <= 401, "bounded to max+ellipsis");
        assert!(e.ends_with('…'));
        let ctrl = excerpt("ok\u{0007}\u{0000}bell", 100);
        assert!(!ctrl.contains('\u{0007}'));
        assert!(ctrl.contains("ok"));
    }

    fn tmp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "wafrift_harvest_test_{}_{}_{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ))
    }

    #[test]
    fn ansi_c_escape_renders_control_bytes_byte_exact() {
        // formfeed (0x0c), tab, single-quote, backslash, the bytes that
        // a WAF bypass payload commonly carries.
        let s = "a\u{0c}b\tc'd\\e";
        assert_eq!(ansi_c_escape(s), "a\\x0cb\\tc\\'d\\\\e");
    }

    #[test]
    fn needs_ansi_c_quoting_detects_nonprintable_only() {
        assert!(needs_ansi_c_quoting("has\u{0c}formfeed"));
        assert!(needs_ansi_c_quoting("\t"));
        assert!(needs_ansi_c_quoting("fullwidth\u{ff1f}")); // non-ASCII unicode
        // Single quotes are printable ASCII, handled by the single-quote
        // form, so they do NOT force ANSI-C quoting.
        assert!(!needs_ansi_c_quoting("plain ' OR 1=1 -- printable"));
    }

    #[test]
    fn curl_repro_uses_ansi_c_for_control_byte_payload() {
        let c = curl_repro("https://x.test", "body_form_q", "a\u{0c}b");
        assert!(
            c.contains("q=$'"),
            "control-byte payload must use ANSI-C $'...' quoting: {c}"
        );
        assert!(c.contains("\\x0c"), "formfeed must render as \\x0c: {c}");
        // A printable payload stays in the readable single-quote form.
        let c2 = curl_repro("https://x.test", "body_form_q", "plain");
        assert!(
            !c2.contains("$'"),
            "printable payload must not use ANSI-C: {c2}"
        );
        assert!(c2.contains("--data-urlencode 'q=plain'"));
    }

    fn verified_proof() -> ReverifyProof {
        ReverifyProof {
            delivery_desc: "POST /post form".into(),
            repro_curl: "curl -sk -X POST 'https://x/post' \\\n  --data-urlencode 'q=...'".into(),
            status: 200,
            latency_ms: 3.0,
            reflected: true,
            body_excerpt: "{\"ok\":true}".into(),
            execution: None,
        }
    }

    #[test]
    fn render_report_elevates_to_exploit_when_execution_proven() {
        let bp = bypass("xss", "<script>alert(1)</script>", &["identity"]);
        let mut proof = verified_proof();
        proof.execution = Some(crate::exec_proof::ExecutionProof {
            executed: true,
            sink: Some("alert".into()),
            message: Some("1".into()),
        });
        let (_f, content) = render_report(
            "https://t/x",
            "t",
            "cf:xss",
            &bp,
            Some(&proof),
            "cumulusfire",
        );
        assert!(
            content.contains("Confirmed xss exploit"),
            "title elevated: {content}"
        );
        assert!(
            content.contains("\"exploit_confirmed\":true"),
            "meta flags exploit"
        );
        assert!(
            content.contains("\"severity\":\"critical\""),
            "severity raised to critical"
        );
        assert!(
            content.contains("Execution proven"),
            "proof section states execution"
        );
        assert!(content.contains("alert(1)"), "names the fired sink + arg");
    }

    #[test]
    fn render_report_stays_bypass_when_no_execution_proof() {
        let bp = bypass("xss", "<script>alert(1)</script>", &["identity"]);
        let proof = verified_proof(); // execution: None
        let (_f, content) = render_report(
            "https://t/x",
            "t",
            "cf:xss",
            &bp,
            Some(&proof),
            "cumulusfire",
        );
        assert!(content.contains("WAF bypass:"), "stays a bypass headline");
        assert!(content.contains("\"exploit_confirmed\":false"));
        assert!(content.contains("\"severity\":\"high\""));
    }

    #[test]
    fn submit_dry_run_returns_zero_without_network() {
        let bp = bypass("sql", "' OR 1=1-- z", &["keyword_morph"]);
        let proof = verified_proof();
        let (fname, content) = render_report(
            "https://waf.cumulusfire.net",
            "waf.cumulusfire.net",
            "cf:?:?",
            &bp,
            Some(&proof),
            "cumulusfire",
        );
        let path = tmp(&fname);
        std::fs::write(&path, content).unwrap();
        // confirm:false → dry-run, never touches the network, exit 0.
        let rc = run_submit_inner(SubmitArgs {
            report: path.clone(),
            confirm: false,
            team: None,
        });
        let _ = std::fs::remove_file(&path);
        assert_eq!(rc, 0, "dry-run submit must succeed without submitting");
    }

    #[test]
    fn submit_confirm_refuses_unverified_report_before_network() {
        let bp = bypass("sql", "' OR 1=1-- z", &["keyword_morph"]);
        // None proof → report marked UNVERIFIED.
        let (fname, content) = render_report(
            "https://waf.cumulusfire.net",
            "waf.cumulusfire.net",
            "cf:?:?",
            &bp,
            None,
            "cumulusfire",
        );
        let path = tmp(&fname);
        std::fs::write(&path, content).unwrap();
        // confirm:true but UNVERIFIED → refuse (exit 2) before any H1 call.
        let rc = run_submit_inner(SubmitArgs {
            report: path.clone(),
            confirm: true,
            team: None,
        });
        let _ = std::fs::remove_file(&path);
        assert_eq!(rc, 2, "must refuse to submit an unverified report");
    }

    #[test]
    fn submit_missing_report_file_errors() {
        let rc = run_submit_inner(SubmitArgs {
            report: tmp("does-not-exist.md"),
            confirm: false,
            team: None,
        });
        assert_eq!(rc, 1);
    }

    #[test]
    fn request_to_curl_get_has_url_no_body() {
        let req = build_request_for_delivery(
            "http://h",
            &DeliveryShape::Query { param: "q".into() },
            "abc",
        );
        let c = request_to_curl(&req);
        assert!(
            c.starts_with("curl -sk -X GET 'http://h/get?q=abc'"),
            "got: {c}"
        );
        assert!(!c.contains("--data-binary"), "GET must have no body: {c}");
    }

    #[test]
    fn request_to_curl_form_body_has_data_binary() {
        let req = build_request_for_delivery(
            "http://h",
            &DeliveryShape::FormBody { param: "q".into() },
            "1 OR 1=1",
        );
        let c = request_to_curl(&req);
        assert!(c.contains("-X POST 'http://h/post'"), "got: {c}");
        assert!(
            c.contains("-H 'content-type: application/x-www-form-urlencoded'"),
            "got: {c}"
        );
        // urlencoded body, single-quoted (printable).
        assert!(c.contains("--data-binary 'q=1%20OR%201%3D1'"), "got: {c}");
    }

    #[test]
    fn request_to_curl_control_bytes_use_ansi_c() {
        // A multipart field carries the payload RAW between boundaries, so
        // a formfeed reaches the body as byte 0x0c, request_to_curl must
        // switch to byte-exact ANSI-C `$'…\x0c…'` quoting so the repro
        // reconstructs the exact bytes that carried the bypass.
        let req = build_request_for_delivery(
            "http://h",
            &DeliveryShape::MultipartField { name: "f".into() },
            "a\u{0c}b",
        );
        let c = request_to_curl(&req);
        assert!(
            c.contains("--data-binary $'"),
            "control byte must use ANSI-C: {c}"
        );
        assert!(
            c.contains("\\x0c"),
            "formfeed must render byte-exact as \\x0c: {c}"
        );
    }

    #[test]
    fn report_uses_proofs_repro_curl_verbatim() {
        // The report's reproduction block must be the EXACT curl captured
        // at re-verify time (faithful shape), not a re-derived guess.
        let bp = bypass("sql", "1 OR 1=1 --", &["hpp_split"]);
        let proof = ReverifyProof {
            delivery_desc: "recorded shape `hpp_split`: faithful re-fire".into(),
            repro_curl: "curl -sk -X GET 'http://t/get?q=v0&q=1%20OR%201%3D1%20--'".into(),
            status: 200,
            latency_ms: 5.0,
            reflected: true,
            body_excerpt: "ok".into(),
            execution: None,
        };
        let (_f, content) =
            render_report("http://t", "t", "cf:?:?", &bp, Some(&proof), "cumulusfire");
        assert!(
            content.contains("Delivery: recorded shape `hpp_split`"),
            "{content}"
        );
        assert!(
            content.contains("curl -sk -X GET 'http://t/get?q=v0&q=1%20OR%201%3D1%20--'"),
            "report must embed the faithful repro curl: {content}"
        );
    }

    #[test]
    fn truncate_for_log_caps_and_strips_control() {
        // Control byte early (index 1) so it's within the kept window and
        // must be stripped; long enough that the ellipsis is appended.
        let s = format!("a\u{0007}{}", "z".repeat(50));
        let t = truncate_for_log(&s, 10);
        assert_eq!(t.chars().count(), 11, "10 chars + ellipsis");
        assert!(t.ends_with('…'));
        assert!(
            !t.contains('\u{0007}'),
            "control byte must be stripped: {t:?}"
        );
        assert!(t.starts_with("a.z"), "BEL → '.', then content: {t:?}");
    }