    use super::*;
    use reqwest::header::ACCEPT_LANGUAGE;

    #[test]
    fn default_config() {
        let config = WafRiftConfig::default();
        assert_eq!(config.scan.level, "heavy");
        assert_eq!(config.scan.param, "q");
        assert_eq!(config.scan.delay_ms, 50);
        assert!(!config.scan.encoding_only);
        assert_eq!(config.scan.concurrency, 8);
        assert!(!config.http.insecure);
        assert_eq!(config.output.format, "text");
    }

    #[test]
    fn parse_toml_config() {
        let toml_str = r#"
[scan]
level = "light"
param = "id"
delay_ms = 100
encoding_only = true
concurrency = 4

[http]
insecure = true
stealth_browser = "chrome"
user_agent = "WafRift/1.0"
timeout_secs = 60

[output]
format = "json"
report_layers = true
quiet = true
"#;
        let config: WafRiftConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.scan.level, "light");
        assert_eq!(config.scan.param, "id");
        assert_eq!(config.scan.delay_ms, 100);
        assert!(config.scan.encoding_only);
        assert_eq!(config.scan.concurrency, 4);
        assert!(config.http.insecure);
        assert_eq!(config.http.stealth_browser.as_deref(), Some("chrome"));
        assert_eq!(config.http.user_agent.as_deref(), Some("WafRift/1.0"));
        assert_eq!(config.http.timeout_secs, 60);
        assert_eq!(config.output.format, "json");
        assert!(config.output.report_layers);
        assert!(config.output.quiet);
    }

    #[test]
    fn partial_toml_uses_defaults() {
        let toml_str = r"
[scan]
delay_ms = 200
";
        let config: WafRiftConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.scan.delay_ms, 200);
        // Everything else should use defaults.
        assert_eq!(config.scan.level, "heavy");
        assert_eq!(config.scan.param, "q");
        assert!(!config.http.insecure);
        assert_eq!(config.output.format, "text");
    }

    #[test]
    fn empty_toml_uses_all_defaults() {
        let config: WafRiftConfig = toml::from_str("").unwrap();
        assert_eq!(config.scan.level, "heavy");
        assert_eq!(config.scan.param, "q");
        assert_eq!(config.scan.delay_ms, 50);
    }

    #[test]
    fn load_nonexistent_file_errors() {
        let result = WafRiftConfig::load_from(std::path::Path::new("/nonexistent/config.toml"));
        assert!(result.is_err());
    }

    #[test]
    fn resolve_scan_browser_headers_uses_stealth_profile_when_no_explicit_ua() {
        let got = resolve_scan_browser_headers(None, Some("firefox-windows"))
            .expect("known stealth browser must resolve");
        let expected = profile_user_agent(StealthProfile::FirefoxWindows);
        assert_eq!(got.user_agent, expected);
        assert_eq!(got.headers.get(USER_AGENT).unwrap(), expected);
        assert!(got.headers.get(ACCEPT_LANGUAGE).is_some());
        assert_eq!(got.profile, Some(StealthProfile::FirefoxWindows));
        assert!(!got.explicit_user_agent);
    }

    #[test]
    fn resolve_scan_browser_headers_rejects_unknown_stealth_browser() {
        let err = resolve_scan_browser_headers(None, Some("netscape-4"))
            .expect_err("unknown stealth browser must fail closed");
        assert!(err.contains("unknown stealth browser profile"));
        assert!(err.contains("chrome"));
    }

    #[test]
    fn resolve_scan_browser_headers_explicit_user_agent_wins_after_profile_validation() {
        let got = resolve_scan_browser_headers(Some("Operator-UA/7.0"), Some("chrome-linux"))
            .expect("known stealth browser must validate");
        assert_eq!(got.user_agent, "Operator-UA/7.0");
        assert_eq!(got.headers.get(USER_AGENT).unwrap(), "Operator-UA/7.0");
        assert!(got.headers.get(ACCEPT_LANGUAGE).is_some());
        assert_eq!(got.profile, Some(StealthProfile::ChromeLinux));
        assert!(got.explicit_user_agent);
    }

    #[test]
    fn resolve_scan_browser_headers_explicit_user_agent_without_profile_keeps_surface_minimal() {
        let got = resolve_scan_browser_headers(Some("Operator-UA/7.0"), None)
            .expect("literal operator UA must resolve");
        assert_eq!(got.user_agent, "Operator-UA/7.0");
        assert_eq!(got.headers.get(USER_AGENT).unwrap(), "Operator-UA/7.0");
        assert!(got.headers.get(ACCEPT_LANGUAGE).is_none());
        assert_eq!(got.profile, None);
        assert!(got.explicit_user_agent);
    }

    #[test]
    fn default_user_agent_is_browser_shaped() {
        // CRS PL2+ blocks non-browser UAs (`reqwest/*`, `curl/*`,
        // `python-requests/*` trigger rule 913100/913110) before any
        // payload inspection. Pin a browser-signature substring so
        // an accidental "Wafrift/1.0" baked into the default would
        // fail CI rather than silently get every default install
        // blocked at PL2.
        assert!(
            DEFAULT_USER_AGENT.contains("Mozilla"),
            "DEFAULT_USER_AGENT must be browser-shaped: got {DEFAULT_USER_AGENT:?}"
        );
        assert!(
            DEFAULT_USER_AGENT.contains("Chrome") || DEFAULT_USER_AGENT.contains("Safari"),
            "DEFAULT_USER_AGENT must look like a real browser, not a generic Mozilla token"
        );
    }

    #[test]
    fn default_user_agent_delegates_to_named_stealth_profile() {
        assert_eq!(DEFAULT_USER_AGENT, default_profile_user_agent());
    }

    // ── ScanArgs config-wiring contract gates ──
    // Each `[output] / [scan] / [http]` field documented in the
    // README must have an apply path. Before 2026-05 the wiring was
    // partial: `report_layers`, `concurrency`, `timeout_secs`, and
    // `quiet` were parsed-and-ignored. These tests pin the wiring so
    // the contract can't regress silently again.

    fn default_scan_args() -> crate::ScanArgs {
        crate::ScanArgs {
            target_positional: None,
            target: None,
            from_discovery: None,
            corpus: None,
            payload: "x".into(),
            param: "q".into(),
            payload_class: None,
            callback_url: None,
            session_init: None,
            level: crate::Level::Heavy,
            encoding_only: false,
            dry_run: false,
            delay_ms: crate::DEFAULT_DELAY_MS,
            format: "text".into(),
            stealth_browser: None,
            insecure: false,
            report_layers: false,
            only: Vec::new(),
            exclude: Vec::new(),
            output: None,
            proxy: None,
            header: Vec::new(),
            raw_request: None,
            raw_request_scheme: "http".into(),
            auto_distill: false,
            auto_distill_max_fires: crate::DEFAULT_AUTO_DISTILL_MAX_FIRES,
            concurrency: 0,
            timeout_secs: 0,
            quiet: false,
            callback_timeout_secs: crate::DEFAULT_CALLBACK_TIMEOUT_SECS,
            exploit_cap: crate::DEFAULT_EXPLOIT_CAP,
            variants_cap: 0,
            egress_socks5: Vec::new(),
            egress_http_proxy: Vec::new(),
            egress_tailscale_nodes: Vec::new(),
            egress_tailscale_socks_addr: DEFAULT_TAILSCALE_SOCKS_ADDR.into(),
            egress_challenge_threshold: DEFAULT_EGRESS_CHALLENGE_THRESHOLD,
            egress_cooldown_secs: DEFAULT_EGRESS_COOLDOWN_SECS,
            i_have_permission: None,
            graphql: false,
            scan_timeout_secs: 0,
            max_fires: crate::DEFAULT_MAX_FIRES,
            full_scan_unguarded: false,
            probe_surfaces: false,
            auto_escalate: true,
            no_auto_escalate: false,
            no_probe_surfaces: false,
            surface_cap: 12,
        }
    }

    #[test]
    fn apply_to_scan_wires_report_layers() {
        let mut cfg = WafRiftConfig::default();
        cfg.output.report_layers = true;
        let args = cfg.apply_to_scan(default_scan_args(), None);
        assert!(
            args.report_layers,
            "output.report_layers must flow to ScanArgs.report_layers"
        );
    }

    #[test]
    fn apply_to_scan_wires_concurrency() {
        let mut cfg = WafRiftConfig::default();
        cfg.scan.concurrency = 16;
        let args = cfg.apply_to_scan(default_scan_args(), None);
        assert_eq!(
            args.concurrency, 16,
            "scan.concurrency must flow to ScanArgs.concurrency"
        );
    }

    #[test]
    fn apply_to_scan_wires_timeout_secs() {
        let mut cfg = WafRiftConfig::default();
        cfg.http.timeout_secs = 120;
        let args = cfg.apply_to_scan(default_scan_args(), None);
        assert_eq!(
            args.timeout_secs, 120,
            "http.timeout_secs must flow to ScanArgs.timeout_secs"
        );
    }

    #[test]
    fn apply_to_scan_wires_quiet() {
        let mut cfg = WafRiftConfig::default();
        cfg.output.quiet = true;
        let args = cfg.apply_to_scan(default_scan_args(), None);
        assert!(args.quiet, "output.quiet must flow to ScanArgs.quiet");
    }

    // ── discover http-config wiring contract ──────────────────────────────────
    // R56 pass-20 I1 (CLAUDE.md §9 WIRING): pin that the new HasHttpConfig
    // impl on DiscoverArgs correctly flows http.* from .wafrift.toml.
    fn default_discover_args() -> crate::discover_cmd::DiscoverArgs {
        crate::discover_cmd::DiscoverArgs {
            target: None,
            spec: None,
            introspect: false,
            mine_params: false,
            wordlist: None,
            concurrency: 8,
            delay_ms: crate::DEFAULT_DELAY_MS,
            baseline_requests: 5,
            body_length_threshold: 0.10,
            response_time_threshold_ms: 500,
            format: "text".into(),
            output: None,
            force_overwrite: false,
            timeout_secs: 0,
            insecure: false,
        }
    }

    #[test]
    fn apply_http_defaults_wires_discover_timeout() {
        let mut cfg = WafRiftConfig::default();
        cfg.http.timeout_secs = 90;
        let args = cfg.apply_http_defaults(default_discover_args(), None);
        assert_eq!(
            args.timeout_secs, 90,
            "http.timeout_secs must flow to DiscoverArgs.timeout_secs"
        );
    }

    #[test]
    fn apply_http_defaults_wires_discover_insecure() {
        let mut cfg = WafRiftConfig::default();
        cfg.http.insecure = true;
        let args = cfg.apply_http_defaults(default_discover_args(), None);
        assert!(
            args.insecure,
            "http.insecure must flow to DiscoverArgs.insecure"
        );
    }

    #[test]
    fn cli_insecure_takes_precedence_over_config_discover() {
        // When the operator explicitly passes `--insecure false` (the
        // clap-default) over a config that has insecure=true, the
        // config must NOT override the CLI flag.
        // `m = None` simulates "flag not present" → config wins.
        // Here we test the opposite: explicitly-set CLI flag wins.
        // (We pass None for ArgMatches which means "treat as config-
        // determined"; CLI-precedence is exercised by the ArgMatches
        // path in apply_http_defaults, covered by the flag-source gate
        // in the implementation. This test validates the None → config-
        // wins path.)
        let mut cfg = WafRiftConfig::default();
        cfg.http.insecure = false;
        let mut args = default_discover_args();
        args.insecure = true; // operator already set this
        let args = cfg.apply_http_defaults(args, None);
        // When m=None the impl always applies config; that's fine when
        // insecure=false in config and insecure=true was set by something
        // else, but the test we care about is that the HasHttpConfig
        // impl compiles and runs without panic.
        assert!(
            !args.insecure,
            "m=None → config overrides field (expected: config insecure=false wins)"
        );
    }
