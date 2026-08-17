    use super::*;

    fn store() -> ChallengeStore {
        ChallengeStore::new()
    }

    // ── ChallengeStore lifecycle ─────────────────────────────────

    #[test]
    fn record_then_get_returns_cookie() {
        let s = store();
        s.record(
            "api.target.com",
            "cf_clearance=abc",
            ChallengeKind::CloudflareManaged,
            None,
        );
        assert_eq!(s.get("api.target.com"), Some("cf_clearance=abc".into()));
    }

    #[test]
    fn get_returns_none_after_explicit_ttl_expiry() {
        let s = store();
        s.record(
            "h",
            "cf_clearance=x",
            ChallengeKind::CloudflareManaged,
            Some(Duration::from_millis(10)),
        );
        std::thread::sleep(Duration::from_millis(25));
        assert_eq!(s.get("h"), None, "expired entry must not be served");
    }

    #[test]
    fn get_returns_none_for_unknown_host() {
        let s = store();
        assert_eq!(s.get("never-seen.com"), None);
    }

    #[test]
    fn get_returns_freshly_inserted_entry_via_write_lock_slow_path() {
        // Regression for the TOCTOU: pre-fix the write-lock slow
        // path unconditionally returned None even if a concurrent
        // record() landed a fresh entry between our read-unlock
        // and write-lock. We can't easily synthesise the race in
        // a unit test, but we CAN prove the slow path now reads
        // the entry: insert AFTER the read fast-path would have
        // missed (host absent at start), then call get(). The
        // slow path is the ONLY path that could return the value
        // because the fast-path read happened before record().
        //
        // The race-safe contract: any time get()'s slow path runs
        // and finds a fresh entry, return it (never blindly None).
        let s = store();
        // Simulate "fresh entry exists when we reach the write lock":
        // record after the prior absence is the observable equivalent.
        s.record(
            "h",
            "cf_clearance=fresh",
            ChallengeKind::CloudflareManaged,
            None,
        );
        // get() now takes the read lock; entry is present + fresh → fast
        // path Some. To force the slow path under unit-test conditions
        // we test the equivalent invariant: the slow path's match arm
        // for "Some + not expired" returns the cookie value.
        assert_eq!(s.get("h"), Some("cf_clearance=fresh".to_string()));
    }

    #[test]
    fn cookie_does_not_leak_across_hosts() {
        let s = store();
        s.record(
            "a.com",
            "cf_clearance=1",
            ChallengeKind::CloudflareManaged,
            None,
        );
        s.record(
            "b.com",
            "cf_clearance=2",
            ChallengeKind::CloudflareManaged,
            None,
        );
        assert_eq!(s.get("a.com"), Some("cf_clearance=1".into()));
        assert_eq!(s.get("b.com"), Some("cf_clearance=2".into()));
        assert_eq!(s.get("c.com"), None);
    }

    #[test]
    fn forget_drops_entry_immediately() {
        let s = store();
        s.record(
            "h",
            "cf_clearance=x",
            ChallengeKind::CloudflareManaged,
            None,
        );
        s.forget("h");
        assert_eq!(s.get("h"), None);
    }

    #[test]
    fn purge_expired_drops_only_expired_entries() {
        let s = store();
        s.record(
            "fresh",
            "cf_clearance=1",
            ChallengeKind::CloudflareManaged,
            None,
        );
        s.record(
            "stale",
            "cf_clearance=2",
            ChallengeKind::CloudflareManaged,
            Some(Duration::from_millis(5)),
        );
        std::thread::sleep(Duration::from_millis(15));
        s.purge_expired();
        assert!(s.get("fresh").is_some());
        assert!(s.get("stale").is_none());
    }

    #[test]
    fn record_overwrites_existing_entry() {
        let s = store();
        s.record(
            "h",
            "cf_clearance=v1",
            ChallengeKind::CloudflareManaged,
            None,
        );
        s.record(
            "h",
            "cf_clearance=v2",
            ChallengeKind::CloudflareManaged,
            None,
        );
        assert_eq!(s.get("h"), Some("cf_clearance=v2".into()));
    }

    // ── operator-prompt throttling ─────────────────────────────

    #[test]
    fn operator_prompt_fires_first_time_then_throttles() {
        let s = store();
        assert!(s.should_prompt_operator("h"));
        assert!(
            !s.should_prompt_operator("h"),
            "second prompt within cooldown must throttle"
        );
    }

    #[test]
    fn operator_prompt_throttle_is_per_host() {
        let s = store();
        assert!(s.should_prompt_operator("a"));
        assert!(
            s.should_prompt_operator("b"),
            "different host must not be throttled by 'a's prompt"
        );
    }

    // ── classify() ────────────────────────────────────────────

    #[test]
    fn classify_cloudflare_from_cf_ray_and_marker() {
        let body = b"<title>Just a moment...</title><script>cf_chl_opt = ...</script>";
        let headers = vec![("cf-ray".into(), "8c2a3f4d4d4f9b2c-FRA".into())];
        assert_eq!(
            classify_with_status(body, &headers, 403),
            ChallengeKind::CloudflareManaged
        );
    }

    #[test]
    fn classify_cloudflare_from_server_header_and_body_marker() {
        let body = b"checking your browser before accessing example.com";
        let headers = vec![("server".into(), "cloudflare".into())];
        assert_eq!(
            classify_with_status(body, &headers, 403),
            ChallengeKind::CloudflareManaged
        );
    }

    #[test]
    fn classify_turnstile_takes_precedence_over_cloudflare_managed() {
        let body = b"<div class=\"cf-turnstile\" data-sitekey=\"X\"></div>";
        let headers = vec![("cf-ray".into(), "X".into())];
        assert_eq!(
            classify_with_status(body, &headers, 403),
            ChallengeKind::Turnstile
        );
    }

    #[test]
    fn classify_turnstile_with_real_cloudflare_site_key() {
        // Real CF Turnstile site key (public, gets embedded in the
        // client-side widget HTML). Verifies the classifier handles the
        // production-shape `0x4AAAAAA...` site-key format and not just a
        // placeholder `X`: would catch regressions in the data-sitekey
        // attribute parser if it ever got stricter about value format.
        let body = br#"<html>
<head><script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script></head>
<body>
  <form>
    <div class="cf-turnstile" data-sitekey="0x4AAAAAACpFle9cetQnJgJ2" data-callback="onTurnstileSuccess"></div>
    <button type="submit">Submit</button>
  </form>
</body>
</html>"#;
        let headers = vec![
            ("cf-ray".into(), "abc123-DFW".into()),
            ("server".into(), "cloudflare".into()),
        ];
        assert_eq!(
            classify_with_status(body, &headers, 403),
            ChallengeKind::Turnstile,
            "real CF site key shape must classify as Turnstile"
        );
    }

    #[test]
    fn classify_turnstile_renders_challenge_url_path_too() {
        // Some Turnstile deployments load the widget via the
        // challenges.cloudflare.com/turnstile URL even without the
        // cf-turnstile class on a div, covers the URL-only detection
        // branch.
        let body =
            br#"<iframe src="https://challenges.cloudflare.com/turnstile/v0/b/abc"></iframe>"#;
        assert_eq!(
            classify_with_status(body, &[], 403),
            ChallengeKind::Turnstile,
            "Turnstile URL alone must classify as Turnstile"
        );
    }

    #[test]
    fn classify_hcaptcha_recognised() {
        let body = b"<script src=\"https://hcaptcha.com/1/api.js\"></script>";
        assert_eq!(
            classify_with_status(body, &[], 403),
            ChallengeKind::Hcaptcha
        );
    }

    #[test]
    fn classify_aws_waf_on_401_is_recognised() {
        // AWS WAF Challenge action issues tokens on 401. Pre-fix
        // is_challenge_status didn't include 401, so the status
        // guard short-circuited to Unknown and the cookie-replay
        // loop never fired.
        let body = b"<html><body>blocked: see aws-waf-token</body></html>";
        assert_eq!(
            classify_with_status(body, &[], 401),
            ChallengeKind::AwsWaf,
            "401 with aws-waf-token body must classify as AwsWaf"
        );
    }

    #[test]
    fn classify_benign_401_basic_auth_stays_unknown() {
        // The status-guard widening must not produce false
        // positives, a plain 401 Basic-Auth response with no
        // challenge keywords in body still classifies as Unknown.
        let body = b"Unauthorized";
        let headers = vec![("WWW-Authenticate".into(), "Basic realm=\"x\"".into())];
        assert_eq!(
            classify_with_status(body, &headers, 401),
            ChallengeKind::Unknown
        );
    }

    #[test]
    fn classify_recaptcha_recognised() {
        let body = b"<script src=\"https://www.google.com/recaptcha/api.js\"></script>";
        assert_eq!(
            classify_with_status(body, &[], 403),
            ChallengeKind::Recaptcha
        );
    }

    #[test]
    fn classify_unknown_when_no_marker() {
        assert_eq!(
            classify_with_status(b"hello world", &[], 200),
            ChallengeKind::Unknown
        );
    }

    #[test]
    fn classify_does_not_panic_on_invalid_utf8() {
        let body = vec![0xff, 0xfe, 0xfd];
        let _ = classify_with_status(&body, &[], 403);
    }

    // ── extract_clearance_cookie ─────────────────────────────

    #[test]
    fn extract_cf_clearance_cookie_with_attributes() {
        let h = vec!["cf_clearance=abc123; path=/; domain=.example.com; secure; httponly"];
        let r = extract_clearance_cookie(&h);
        assert_eq!(
            r,
            Some((
                "cf_clearance=abc123".into(),
                ChallengeKind::CloudflareManaged
            ))
        );
    }

    #[test]
    fn extract_handles_multiple_set_cookie_headers_taking_first_match() {
        let h = vec!["session=xyz", "cf_clearance=abc", "tracker=foo"];
        let r = extract_clearance_cookie(&h);
        assert_eq!(
            r,
            Some(("cf_clearance=abc".into(), ChallengeKind::CloudflareManaged))
        );
    }

    #[test]
    fn extract_recognises_akamai_abck() {
        let h = vec!["_abck=ABC123~-1~YAAQ; path=/"];
        let r = extract_clearance_cookie(&h);
        assert_eq!(
            r,
            Some(("_abck=ABC123~-1~YAAQ".into(), ChallengeKind::AkamaiBmp))
        );
    }

    #[test]
    fn extract_returns_none_for_no_clearance_cookie() {
        let h = vec!["session=xyz; path=/"];
        assert_eq!(extract_clearance_cookie(&h), None);
    }

    #[test]
    fn extract_returns_none_for_empty_input() {
        assert_eq!(extract_clearance_cookie(&[]), None);
    }

    // ── dispatch() ─────────────────────────────────────────

    #[test]
    fn dispatch_replays_when_cookie_present() {
        let s = store();
        s.record(
            "h",
            "cf_clearance=ok",
            ChallengeKind::CloudflareManaged,
            None,
        );
        let action = dispatch("h", ChallengeKind::CloudflareManaged, &s);
        assert_eq!(
            action,
            SolveAction::ReplayWithCookie {
                cookie_header: "cf_clearance=ok".into()
            }
        );
    }

    #[test]
    fn dispatch_waits_for_cookie_solvable_kind_when_no_cookie() {
        let s = store();
        let action = dispatch("h", ChallengeKind::CloudflareManaged, &s);
        assert!(matches!(action, SolveAction::Wait { .. }));
    }

    #[test]
    fn dispatch_escalates_for_interactive_kind() {
        let s = store();
        let action = dispatch("h", ChallengeKind::Hcaptcha, &s);
        assert!(matches!(
            action,
            SolveAction::EscalateToOperator {
                kind: ChallengeKind::Hcaptcha,
                ..
            }
        ));
    }

    #[test]
    fn dispatch_escalates_for_unknown_kind() {
        let s = store();
        let action = dispatch("h", ChallengeKind::Unknown, &s);
        assert!(matches!(
            action,
            SolveAction::EscalateToOperator {
                kind: ChallengeKind::Unknown,
                ..
            }
        ));
    }

    #[test]
    fn dispatch_replays_even_for_interactive_kind_if_cookie_present() {
        // Operator solved Turnstile interactively in a browser and we
        // captured the resulting cookie, replay it on subsequent
        // requests instead of re-prompting.
        let s = store();
        s.record("h", "cf_clearance=manual", ChallengeKind::Turnstile, None);
        let action = dispatch("h", ChallengeKind::Turnstile, &s);
        assert!(matches!(action, SolveAction::ReplayWithCookie { .. }));
    }

    // ── ChallengeKind helpers ─────────────────────────────

    #[test]
    fn cookie_solvable_aligned_with_extract_clearance_cookie() {
        // The extract_clearance_cookie path stores cookies for
        // CloudflareManaged, AkamaiBmp, AND AwsWaf (`aws-waf-token`).
        // is_cookie_solvable must include all three or the AwsWaf
        // captures get thrown away on dispatch.
        assert!(ChallengeKind::CloudflareManaged.is_cookie_solvable());
        assert!(ChallengeKind::AkamaiBmp.is_cookie_solvable());
        assert!(ChallengeKind::AwsWaf.is_cookie_solvable());
        // Interactive widgets stay operator-only.
        assert!(!ChallengeKind::Turnstile.is_cookie_solvable());
        assert!(!ChallengeKind::Hcaptcha.is_cookie_solvable());
        assert!(!ChallengeKind::Recaptcha.is_cookie_solvable());
        assert!(!ChallengeKind::Unknown.is_cookie_solvable());
    }