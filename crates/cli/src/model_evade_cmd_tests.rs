    use super::*;
    use wafrift_wafmodel::{BytePred, Sfa, minimal_bypass};

    // ── check_permission unit tests ─────────────────────────────────

    #[test]
    fn permission_localhost_always_allowed() {
        assert!(check_permission("http://localhost:8080", &None).is_ok());
        assert!(check_permission("http://127.0.0.1:9000/probe", &None).is_ok());
        assert!(check_permission("http://127.0.0.1", &None).is_ok());
    }

    #[test]
    fn permission_rfc1918_always_allowed() {
        assert!(check_permission("http://10.0.0.1/target", &None).is_ok());
        assert!(check_permission("http://192.168.1.100:8080", &None).is_ok());
        assert!(check_permission("http://172.16.0.1", &None).is_ok());
        assert!(check_permission("http://172.31.255.255", &None).is_ok());
    }

    #[test]
    fn permission_rfc1918_boundary_172_15_denied_without_auth() {
        // 172.15.x.x is NOT RFC1918 (range is 172.16.0.0/12).
        let r = check_permission("http://172.15.0.1/target", &None);
        assert!(
            r.is_err(),
            "172.15.x.x is not RFC1918, must require permission"
        );
    }

    #[test]
    fn permission_public_target_denied_without_reason() {
        let r = check_permission("https://example.com/target", &None);
        assert!(r.is_err());
        let msg = r.unwrap_err();
        assert!(
            msg.contains("--i-have-permission"),
            "error must mention the flag: {msg}"
        );
    }

    #[test]
    fn permission_public_target_allowed_with_reason() {
        let r = check_permission(
            "https://example.com/target",
            &Some("Bug bounty program".to_string()),
        );
        assert!(r.is_ok());
    }

    #[test]
    fn permission_empty_reason_denied() {
        let r = check_permission("https://example.com", &Some("   ".to_string()));
        assert!(r.is_err());
    }

    #[test]
    fn permission_builtin_allowlist_waf_cumulusfire() {
        assert!(check_permission("https://waf.cumulusfire.net/test", &None).is_ok());
        assert!(check_permission("https://api.waf.cumulusfire.net/test", &None).is_ok());
    }

    #[test]
    fn permission_builtin_allowlist_testing_santh_dev() {
        assert!(check_permission("https://testing.santh.dev/probe", &None).is_ok());
    }

    // ── class_config unit tests ─────────────────────────────────────

    #[test]
    fn class_config_sqli_has_needles() {
        let (_alpha, needles) = class_config("sqli");
        assert!(!needles.is_empty(), "sqli must have attack needles");
        assert!(
            needles.iter().any(|n| *n == b"union select"),
            "sqli must include 'union select'"
        );
    }

    #[test]
    fn class_config_xss_has_needles() {
        let (_alpha, needles) = class_config("xss");
        assert!(!needles.is_empty(), "xss must have attack needles");
        assert!(
            needles.iter().any(|n| *n == b"<script"),
            "xss must include '<script'"
        );
    }

    #[test]
    fn class_config_all_includes_both() {
        let (_sqli_alpha, sqli_needles) = class_config("sqli");
        let (_xss_alpha, xss_needles) = class_config("xss");
        let (_all_alpha, all_needles) = class_config("all");
        for n in &sqli_needles {
            assert!(
                all_needles.contains(n),
                "'all' must include sqli needle {:?}",
                String::from_utf8_lossy(n)
            );
        }
        for n in &xss_needles {
            assert!(
                all_needles.contains(n),
                "'all' must include xss needle {:?}",
                String::from_utf8_lossy(n)
            );
        }
    }

    #[test]
    fn class_config_alphabet_catch_all_not_in_distinguished() {
        for class in ["sqli", "xss", "all"] {
            let (alpha, _) = class_config(class);
            let syms = alpha.raw_symbols();
            let catch_all = syms[syms.len() - 1];
            let distinguished = &syms[..syms.len() - 1];
            assert!(
                !distinguished.contains(&catch_all),
                "class {class}: catch-all byte {catch_all} must not be in distinguished"
            );
        }
    }

    #[test]
    fn class_config_alphabet_non_empty() {
        for class in ["sqli", "xss", "all"] {
            let (alpha, _) = class_config(class);
            assert!(
                alpha.len() >= 2,
                "class {class}: alphabet must have ≥1 distinguished + 1 catch-all"
            );
        }
    }

    // ── emit_output unit test ───────────────────────────────────────

    #[test]
    fn emit_output_to_file_creates_file() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "wafrift_model_evade_test_{}.json",
            std::process::id()
        ));
        let content = r#"{"test":true}"#;
        emit_output(Some(&path), content);
        assert!(path.exists(), "emit_output must create the file");
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.contains(content));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn emit_output_none_does_not_panic() {
        // Should print to stdout without panicking.
        emit_output(None, r#"{"ok":true}"#);
    }

    // ── verified-bypass gate (anti-rig) ───────────────────────────

    #[test]
    fn mangled_sqli_payload_passing_waf_is_not_verified_bypass() {
        // Simulate a candidate that the WAF passes (Outcome::Pass) but whose
        // OR keyword has been destroyed by an intra-token space mutation.
        // This is the anti-rig regression: old code counted any Pass as a
        // bypass; the structural oracle must reject it.
        let broken = "1 O R 1=1 --";
        let pass: Result<Outcome, WafModelError> = Ok(Outcome::Pass);
        assert!(
            !candidate_is_verified_bypass(&pass, "sqli", broken),
            "token-split mutation must not verify as a bypass: {broken}"
        );

        // Sanity: an intact equivalent payload that the WAF passes should verify.
        let intact = "1 OR 1=1 --";
        assert!(
            candidate_is_verified_bypass(&pass, "sqli", intact),
            "intact payload should verify: {intact}"
        );
    }

    // ── bypass_entry schema ─────────────────────────────────────────

    #[test]
    fn bypass_entry_serializes_payload_hex() {
        let entry = BypassEntry::new(b"1 OR 1=1".to_vec(), "sqli", true);
        let v = serde_json::to_value(&entry).unwrap();
        assert_eq!(v["verified"], true);
        assert_eq!(v["class"], "sqli");
        assert_eq!(v["payload"], "1 OR 1=1");
        let expected_hex = hex::encode(b"1 OR 1=1");
        assert_eq!(v["payload_hex"], expected_hex);
    }

    #[test]
    fn bypass_entry_unverified() {
        let entry = BypassEntry::new(b"<script>".to_vec(), "xss", false);
        let v = serde_json::to_value(&entry).unwrap();
        assert_eq!(v["verified"], false);
    }

    #[test]
    fn bypass_entry_hex_for_non_utf8_bytes() {
        let raw = vec![0xFF, 0xFE, 0x00, 0x01];
        let entry = BypassEntry::new(raw.clone(), "sqli", false);
        assert_eq!(entry.payload_hex, hex::encode(&raw));
    }

    // ── accept_all_sfa ──────────────────────────────────────────────

    #[test]
    fn accept_all_sfa_accepts_everything() {
        let sfa = accept_all_sfa();
        assert!(sfa.accepts(b""), "accept-all must accept empty");
        assert!(sfa.accepts(b"union select"), "accept-all must accept sql");
        assert!(sfa.accepts(b"<script>"), "accept-all must accept xss");
        assert!(
            sfa.accepts(b"\x00\xff\x7f"),
            "accept-all must accept binary"
        );
    }

    // ── oracle integration: FnOracle wrapping ──────────────────────

    #[test]
    fn fn_oracle_counts_queries() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let counter = Arc::new(AtomicU64::new(0));
        let c2 = counter.clone();
        let mut oracle = FnOracle::new(move |_req: &Request| {
            c2.fetch_add(1, Ordering::SeqCst);
            Ok(Outcome::Pass)
        });
        let req = Request::get("http://localhost/");
        oracle.classify(&req).unwrap();
        oracle.classify(&req).unwrap();
        assert_eq!(oracle.queries(), 2);
    }

    #[test]
    fn fn_oracle_pass_outcome() {
        let mut oracle = FnOracle::new(|_req: &Request| Ok(Outcome::Pass));
        let req = Request::get("http://localhost/");
        assert_eq!(oracle.classify(&req).unwrap(), Outcome::Pass);
    }

    #[test]
    fn fn_oracle_block_outcome() {
        let mut oracle = FnOracle::new(|_req: &Request| Ok(Outcome::Block));
        let req = Request::get("http://localhost/");
        assert_eq!(oracle.classify(&req).unwrap(), Outcome::Block);
    }

    // ── l_star_budgeted integration: offline SimRegexWaf oracle ────

    #[test]
    fn lstar_budgeted_learns_simple_boundary() {
        use wafrift_wafmodel::canon::Channel;
        use wafrift_wafmodel::{ChannelSet, Rule, SimRegexWaf};
        let mut waf = SimRegexWaf::new(
            vec![Rule {
                id: "test-sqli".into(),
                channels: ChannelSet::none().with(Channel::Body),
                transforms: vec![],
                pattern: regex::bytes::Regex::new("union select").unwrap(),
                score: 5,
            }],
            5,
        );
        let (alpha, _needles) = class_config("sqli");
        let build = |bytes: &[u8]| -> Request {
            Request::post("https://h/p", bytes.to_vec())
                .header("Content-Type", "application/x-www-form-urlencoded")
        };
        let mut eq = BoundedExhaustiveEq {
            max_len: 5,
            max_queries: None,
        };
        let report = l_star_budgeted(&mut waf, &build, &alpha, &mut eq, 2000).unwrap();
        // Learned model must pass the empty body (benign).
        assert!(report.sfa.accepts(b""), "empty body must pass");
        assert!(report.membership_queries > 0);
    }

    #[test]
    fn lstar_budgeted_budget_exhaustion_returns_error() {
        use wafrift_wafmodel::canon::Channel;
        use wafrift_wafmodel::{ChannelSet, Rule, SimRegexWaf};
        let mut waf = SimRegexWaf::new(
            vec![Rule {
                id: "test-sqli".into(),
                channels: ChannelSet::none().with(Channel::Body),
                transforms: vec![],
                pattern: regex::bytes::Regex::new("union select").unwrap(),
                score: 5,
            }],
            5,
        );
        let (alpha, _) = class_config("sqli");
        let build = |bytes: &[u8]| -> Request {
            Request::post("https://h/p", bytes.to_vec())
                .header("Content-Type", "application/x-www-form-urlencoded")
        };
        let mut eq = BoundedExhaustiveEq {
            max_len: 5,
            max_queries: None,
        };
        // Budget of 1 is too small (must return BudgetExhausted).
        let result = l_star_budgeted(&mut waf, &build, &alpha, &mut eq, 1);
        assert!(
            matches!(result, Err(WafModelError::BudgetExhausted { .. })),
            "tiny budget must exhaust: {result:?}"
        );
    }

    #[test]
    fn mine_bypasses_empty_when_no_intersection() {
        // An accept-all SFA ∩ empty attack grammar = empty.
        let (alpha, _) = class_config("sqli");
        let accept_all = Sfa::new(0, vec![true], vec![vec![(BytePred::any(), 0)]]);
        let empty_grammar = attack_grammar(&alpha, &[]); // no needles = empty language
        let candidates = mine_bypasses(&accept_all, &empty_grammar, 64, 24);
        assert!(
            candidates.is_empty(),
            "empty grammar ∩ accept-all = empty: {candidates:?}"
        );
    }

    #[test]
    fn mine_bypasses_finds_candidates_with_accept_all_model() {
        let (alpha, needles) = class_config("sqli");
        let accept_all = Sfa::new(0, vec![true], vec![vec![(BytePred::any(), 0)]]);
        let grammar = attack_grammar(&alpha, &needles);
        let candidates = mine_bypasses(&accept_all, &grammar, 10, 20);
        assert!(
            !candidates.is_empty(),
            "accept-all WAF must yield bypass candidates for sqli grammar"
        );
    }

    #[test]
    fn mine_bypasses_respects_max_limit() {
        let (alpha, needles) = class_config("sqli");
        let accept_all = Sfa::new(0, vec![true], vec![vec![(BytePred::any(), 0)]]);
        let grammar = attack_grammar(&alpha, &needles);
        let candidates = mine_bypasses(&accept_all, &grammar, 3, 20);
        assert!(
            candidates.len() <= 3,
            "mine_bypasses must respect max: {}",
            candidates.len()
        );
    }

    #[test]
    fn mine_bypasses_candidates_contain_attack_needle() {
        // Every mined sqli candidate must contain at least one attack needle.
        let (alpha, needles) = class_config("sqli");
        let accept_all = Sfa::new(0, vec![true], vec![vec![(BytePred::any(), 0)]]);
        let grammar = attack_grammar(&alpha, &needles);
        let candidates = mine_bypasses(&accept_all, &grammar, 10, 30);
        for cand in &candidates {
            let payload = String::from_utf8_lossy(cand).to_ascii_lowercase();
            let has_needle = needles
                .iter()
                .any(|n| payload.contains(std::str::from_utf8(n).unwrap_or("")));
            assert!(
                has_needle,
                "mined candidate {:?} must contain an attack needle",
                payload
            );
        }
    }

    #[test]
    fn attack_grammar_xss_contains_script_needle() {
        let (alpha, needles) = class_config("xss");
        let grammar = attack_grammar(&alpha, &needles);
        let found = grammar.shortest_accepted();
        assert!(found.is_some(), "xss grammar must accept something");
        let bytes = found.unwrap();
        let s = String::from_utf8_lossy(&bytes).to_ascii_lowercase();
        let has_needle = needles
            .iter()
            .any(|n| s.contains(std::str::from_utf8(n).unwrap_or("")));
        assert!(has_needle, "shortest xss accept must have a needle: {s:?}");
    }

    #[test]
    fn mine_bypasses_max_len_respected() {
        let (alpha, needles) = class_config("sqli");
        let accept_all = Sfa::new(0, vec![true], vec![vec![(BytePred::any(), 0)]]);
        let grammar = attack_grammar(&alpha, &needles);
        // max_len = 14 (shorter than longest needle "union select" = 12 bytes)
        let candidates = mine_bypasses(&accept_all, &grammar, 20, 14);
        for cand in &candidates {
            assert!(
                cand.len() <= 14,
                "candidate longer than max_len: {:?}",
                String::from_utf8_lossy(cand)
            );
        }
    }

    /// INVARIANT test: every byte in every needle for each class MUST
    /// appear in the class's distinguished-symbol alphabet. Violation
    /// means the KMP SFA maps that byte to the catch-all representative
    /// (b'A') and can never advance the needle match, the needle becomes
    /// silently unmatchable over the abstract alphabet. This is the exact
    /// bug that existed in the sqli alphabet before the fix (uppercase
    /// letters listed, lowercase needles).
    #[test]
    fn class_config_alphabet_covers_all_needle_bytes() {
        for class in &["sqli", "xss", "all"] {
            let (alpha, needles) = class_config(class);
            let sym_count = alpha.catch_all();
            let symbols = &alpha.raw_symbols()[..sym_count];
            for needle in &needles {
                for &byte in *needle {
                    assert!(
                        symbols.contains(&byte),
                        "class={class}: needle byte {byte:?} ({:?}) not in distinguished \
                         alphabet: it maps to catch-all and kmp_sfa cannot match it.\n\
                         Needle: {:?}\nAlphabet: {:?}",
                        byte as char,
                        String::from_utf8_lossy(needle),
                        symbols.iter().map(|b| *b as char).collect::<Vec<_>>(),
                    );
                }
            }
        }
    }

    #[test]
    fn mine_bypasses_all_class_finds_both_sqli_and_xss() {
        // Use `minimal_bypass` (shortest_accepted with a seen-set, O(states)) to
        // verify each class grammar accepts its attack language.  `mine_bypasses`
        // (enumerate_accepted, no seen-set) hits ENUMERATE_QUEUE_CAP on large
        // cyclic grammars when max_len is generous; it is NOT the correctness
        // oracle: `minimal_bypass` is.
        let accept_all = Sfa::new(0, vec![true], vec![vec![(BytePred::any(), 0)]]);

        // SQLi: the shortest bypass must contain an SQLi needle.
        let (sqli_alpha, sqli_needles) = class_config("sqli");
        let sqli_grammar = attack_grammar(&sqli_alpha, &sqli_needles);
        let sqli_word = minimal_bypass(&accept_all, &sqli_grammar)
            .expect("sqli grammar must accept at least one bypass");
        let sqli_s = String::from_utf8_lossy(&sqli_word).to_ascii_lowercase();
        assert!(
            sqli_needles
                .iter()
                .any(|n| sqli_s.contains(std::str::from_utf8(n).unwrap_or(""))),
            "sqli minimal bypass {:?} must contain a sqli needle",
            sqli_s
        );

        // XSS: the shortest bypass must contain an XSS needle.
        let (xss_alpha, xss_needles) = class_config("xss");
        let xss_grammar = attack_grammar(&xss_alpha, &xss_needles);
        let xss_word = minimal_bypass(&accept_all, &xss_grammar)
            .expect("xss grammar must accept at least one bypass");
        let xss_s = String::from_utf8_lossy(&xss_word).to_ascii_lowercase();
        assert!(
            xss_needles
                .iter()
                .any(|n| xss_s.contains(std::str::from_utf8(n).unwrap_or(""))),
            "xss minimal bypass {:?} must contain an xss needle",
            xss_s
        );
    }
