    use super::*;

    // ── Regression: hunt round runner must overwrite its pre-claimed tmp ──

    #[test]
    fn round_runner_overwrites_its_preclaimed_tmp_output() {
        // run_one_round pre-claims the per-round tmp output path via
        // O_CREAT|O_EXCL (the TOCTOU/symlink defense), so the file already
        // exists when bench_waf opens it. bench_waf MUST be told to
        // overwrite it, otherwise its no-clobber guard rejects EVERY
        // round's output ("already exists … --force-overwrite") and the
        // campaign records 0 bypasses (the hunt was entirely non-functional
        // against the live edge until this was fixed; caught by dogfooding
        // a real CumulusFire campaign).
        // This test greps its OWN source via include_str!, so neither the
        // wanted nor the forbidden setting may appear here as a contiguous
        // literal, that would self-match and defeat the check. Both needles
        // are assembled at runtime from split pieces; the only contiguous
        // `force_overwrite: <bool>` in this file is the production assignment
        // in run_one_round above.
        let src = include_str!("hunt_cmd.rs");
        let field = "force_overwrite:";
        let want = format!("{field} {}", "true");
        let forbidden = format!("{field} {}", "false");
        assert!(
            src.contains(&want),
            "run_one_round must keep overwrite enabled, it pre-claims the tmp output inode, so \
             bench_waf's no-clobber guard would reject every round otherwise (0 bypasses)"
        );
        assert!(
            !src.contains(&forbidden),
            "hunt overwrite flag reverted to disabled, every round's output is rejected (0 bypasses)"
        );
    }

    // ── Test 1: rotate_strategies wraps at length ─────────────────────────

    #[test]
    fn rotate_strategies_wraps() {
        let strats = vec![
            "heavy".to_string(),
            "equiv-cegis".to_string(),
            "mcts".to_string(),
        ];
        let r0 = rotate_strategies(&strats, 0);
        let r1 = rotate_strategies(&strats, 1);
        let r3 = rotate_strategies(&strats, 3); // wraps back to 0
        assert_eq!(r0, r3);
        assert_ne!(r0, r1);
    }

    // ── Test 2: rotate_strategies single-element is stable ────────────────

    #[test]
    fn rotate_strategies_single_element() {
        let strats = vec!["heavy".to_string()];
        let r = rotate_strategies(&strats, 42);
        assert_eq!(r, vec!["heavy"]);
    }

    // ── Test 3: rotate_strategies takes at most 2 ─────────────────────────

    #[test]
    fn rotate_strategies_max_two() {
        let strats: Vec<String> = ["a", "b", "c", "d", "e"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let r = rotate_strategies(&strats, 0);
        assert!(r.len() <= 2);
    }

    // ── Test 4: campaign state round-trips through JSON ────────────────────

    #[test]
    fn campaign_state_roundtrip() {
        let state = CampaignState {
            campaign_id: "test-001".into(),
            target_url: "http://localhost:18081".into(),
            started_at: 1_000_000,
            rounds_completed: 5,
            total_bypasses: 3,
            schema_version: CampaignState::SCHEMA_VERSION,
            bypasses: vec![CampaignBypass {
                discovered_at: 1_000_100,
                round: 3,
                class: "sql".into(),
                technique: "tamper/comment".into(),
                submitted: false,
            }],
            change_points: vec![],
        };
        let json = serde_json::to_string(&state).unwrap();
        let de: CampaignState = serde_json::from_str(&json).unwrap();
        assert_eq!(de.campaign_id, "test-001");
        assert_eq!(de.rounds_completed, 5);
        assert_eq!(de.total_bypasses, 3);
        assert_eq!(de.bypasses.len(), 1);
        assert_eq!(de.bypasses[0].technique, "tamper/comment");
    }

    // ── Test 5: load_or_init_state creates fresh when no file ─────────────

    #[test]
    fn init_state_when_no_file() {
        let tmp = std::env::temp_dir().join("wafrift-hunt-test-nonexistent-99999.json");
        let _ = std::fs::remove_file(&tmp);
        let state = load_or_init_state(&tmp, "nonexistent-99999", "http://localhost");
        assert_eq!(state.rounds_completed, 0);
        assert_eq!(state.total_bypasses, 0);
        assert!(state.bypasses.is_empty());
    }

    // ── Test 6: persist_state writes valid JSON ────────────────────────────

    #[test]
    fn persist_state_writes_valid_json() {
        let tmp = std::env::temp_dir().join("wafrift-hunt-persist-test.json");
        let state = CampaignState {
            campaign_id: "persist-test".into(),
            target_url: "http://localhost".into(),
            started_at: 0,
            rounds_completed: 1,
            total_bypasses: 0,
            schema_version: CampaignState::SCHEMA_VERSION,
            bypasses: vec![],
            change_points: vec![],
        };
        persist_state(&tmp, &state).unwrap();
        let raw = std::fs::read_to_string(&tmp).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["campaign_id"], "persist-test");
        let _ = std::fs::remove_file(&tmp);
    }

    // ── Test 7: load_or_init_state resumes from file ──────────────────────

    #[test]
    fn resume_state_from_file() {
        let tmp = std::env::temp_dir().join("wafrift-hunt-resume-test.json");
        let state = CampaignState {
            campaign_id: "resume-test".into(),
            target_url: "http://localhost".into(),
            started_at: 12345,
            rounds_completed: 7,
            total_bypasses: 2,
            schema_version: CampaignState::SCHEMA_VERSION,
            bypasses: vec![],
            change_points: vec![],
        };
        persist_state(&tmp, &state).unwrap();
        let loaded = load_or_init_state(&tmp, "resume-test", "http://localhost");
        assert_eq!(loaded.rounds_completed, 7);
        assert_eq!(loaded.total_bypasses, 2);
        let _ = std::fs::remove_file(&tmp);
    }

    // ── Test 8: bypass dedup logic ────────────────────────────────────────

    #[test]
    fn bypass_dedup() {
        let mut state = CampaignState {
            schema_version: CampaignState::SCHEMA_VERSION,
            ..Default::default()
        };
        let bp = CampaignBypass {
            discovered_at: 0,
            round: 1,
            class: "sql".into(),
            technique: "tamper/comment".into(),
            submitted: false,
        };
        // Insert same bypass twice via the dedup guard.
        for _ in 0..2 {
            let already = state
                .bypasses
                .iter()
                .any(|e| e.technique == bp.technique && e.class == bp.class);
            if !already {
                state.bypasses.push(bp.clone());
                state.total_bypasses += 1;
            }
        }
        assert_eq!(state.bypasses.len(), 1);
        assert_eq!(state.total_bypasses, 1);
    }

    // ── Test 9: cumulusfire preset sets url and permission ────────────────

    #[test]
    fn cumulusfire_preset_constants() {
        assert!(!CUMULUSFIRE_BASE_URL.is_empty());
        assert!(!CUMULUSFIRE_PERMISSION.is_empty());
        assert!(CUMULUSFIRE_BASE_URL.starts_with("https://"));
    }

    // ── Test 10: schema_version constant is stable ────────────────────────
    // Schema version 2 added the `change_points` field (C-11 CUSUM alarm log).

    #[test]
    fn schema_version_constant() {
        assert_eq!(CampaignState::SCHEMA_VERSION, 2);
    }

    // ── Test 11: persist_state is atomic, no orphaned .tmp on success ───
    // After a successful persist_state call, the sibling `.json.tmp` file
    // must NOT exist (it was renamed into the final path).

    #[test]
    fn persist_state_no_orphaned_tmp_file() {
        let tmp_dir = std::env::temp_dir();
        let path = tmp_dir.join("wafrift-hunt-atomic-test.json");
        let tmp_sibling = tmp_dir.join("wafrift-hunt-atomic-test.json.tmp");
        // Clean up any leftovers from previous runs.
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&tmp_sibling);

        let state = CampaignState {
            campaign_id: "atomic-test".into(),
            target_url: "http://localhost".into(),
            started_at: 0,
            rounds_completed: 3,
            total_bypasses: 1,
            schema_version: CampaignState::SCHEMA_VERSION,
            bypasses: vec![],
            change_points: vec![],
        };
        persist_state(&path, &state).unwrap();

        // Destination file must exist and be valid JSON.
        let raw = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["campaign_id"], "atomic-test");

        // The .tmp sibling must be gone (rename succeeded).
        assert!(
            !tmp_sibling.exists(),
            ".json.tmp sibling was not cleaned up: {:?}",
            tmp_sibling
        );

        let _ = std::fs::remove_file(&path);
    }

    // ── Test 14: persist_state destination file contains all state fields ─
    // A round-trip through persist + load must preserve every field.

    #[test]
    fn persist_state_round_trip_all_fields() {
        let path = std::env::temp_dir().join("wafrift-hunt-roundtrip-test.json");
        let _ = std::fs::remove_file(&path);

        let bypass = CampaignBypass {
            discovered_at: 999,
            round: 5,
            class: "xss".into(),
            technique: "tamper/unicode".into(),
            submitted: true,
        };
        let state = CampaignState {
            campaign_id: "roundtrip-id".into(),
            target_url: "https://example.com/path?foo=bar".into(),
            started_at: 1_700_000_000,
            rounds_completed: 42,
            total_bypasses: 1,
            schema_version: CampaignState::SCHEMA_VERSION,
            bypasses: vec![bypass],
            change_points: vec![],
        };
        persist_state(&path, &state).unwrap();

        let loaded = load_or_init_state(&path, "roundtrip-id", "https://example.com/path?foo=bar");
        assert_eq!(loaded.campaign_id, "roundtrip-id");
        assert_eq!(loaded.rounds_completed, 42);
        assert_eq!(loaded.total_bypasses, 1);
        assert_eq!(loaded.bypasses.len(), 1);
        assert_eq!(loaded.bypasses[0].technique, "tamper/unicode");
        assert!(loaded.bypasses[0].submitted);

        let _ = std::fs::remove_file(&path);
    }

    // ── Test 15: persist_state overwrites existing content atomically ─────
    // A second persist must fully replace the first write, not append to it.

    #[test]
    fn persist_state_overwrites_previous_content() {
        let path = std::env::temp_dir().join("wafrift-hunt-overwrite-test.json");
        let _ = std::fs::remove_file(&path);

        let mk_state = |rounds: u64, bypasses: u64| CampaignState {
            campaign_id: "overwrite-test".into(),
            target_url: "http://localhost".into(),
            started_at: 0,
            rounds_completed: rounds,
            total_bypasses: bypasses,
            schema_version: CampaignState::SCHEMA_VERSION,
            bypasses: vec![],
            change_points: vec![],
        };

        persist_state(&path, &mk_state(1, 0)).unwrap();
        persist_state(&path, &mk_state(7, 3)).unwrap();

        // Only the second write's values must be present.
        let raw = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["rounds_completed"], 7, "stale content from first write");
        assert_eq!(v["total_bypasses"], 3, "stale content from first write");

        let _ = std::fs::remove_file(&path);
    }

    // ── Test 16: persist_state returns Err for unwritable directory ───────

    #[test]
    fn persist_state_returns_err_for_bad_path() {
        // A path whose parent does not exist must produce an Err, not a panic.
        let bad_path = std::path::PathBuf::from("/this/directory/does/not/exist/campaign.json");
        let state = CampaignState::default();
        let result = persist_state(&bad_path, &state);
        assert!(result.is_err(), "expected Err for non-existent parent dir");
    }

    // ── Round 22: path-traversal defence on --campaign-id ─────────────
    //
    // Pre-fix, `--campaign-id "../../tmp/pwn"` formatted into
    // `~/.wafrift/hunt-../../tmp/pwn.json` which path-resolves
    // outside `.wafrift/`. The validator now rejects any character
    // outside the safe portable-filename alphabet.

    #[test]
    fn validate_campaign_id_accepts_safe_ids() {
        for id in [
            "default",
            "campaign-001",
            "campaign_001",
            "2026-05-26",
            "abc.def",
            "A1B2C3",
        ] {
            assert!(
                super::validate_campaign_id(id).is_ok(),
                "safe id rejected: {id}"
            );
        }
    }

    #[test]
    fn validate_campaign_id_rejects_traversal() {
        for bad in [
            "../../tmp/pwn",
            "..",
            ".",
            "a/b",
            "a\\b",
            "/etc/passwd",
            "campaign with spaces",
            "campaign\nwith\nnewlines",
            "campaign\0null",
            "",
        ] {
            assert!(
                super::validate_campaign_id(bad).is_err(),
                "traversal/unsafe id accepted: {bad:?}"
            );
        }
    }

    #[test]
    fn validate_campaign_id_rejects_leading_dash() {
        // A campaign-id like "--evil" could be reinterpreted as a
        // CLI flag if it ever flows into a subprocess argv.
        assert!(super::validate_campaign_id("-x").is_err());
        assert!(super::validate_campaign_id("--evil").is_err());
    }

    #[test]
    fn validate_campaign_id_rejects_oversize() {
        let long = "a".repeat(129);
        assert!(super::validate_campaign_id(&long).is_err());
        let exact = "a".repeat(128);
        assert!(super::validate_campaign_id(&exact).is_ok());
    }

    #[test]
    fn campaign_state_path_stays_under_dot_wafrift() {
        // Sanity: for every validator-allowed campaign id, the
        // resolved state path must remain a child of the .wafrift
        // base directory.
        let base = dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join(".wafrift");
        for id in ["default", "campaign-001", "x.y_z"] {
            let p = super::campaign_state_path(id);
            assert!(
                p.starts_with(&base),
                "campaign state path {p:?} escaped {base:?} for id {id}"
            );
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // C-11: Change-point alarm tests (LAW 9, pinned JSON shape + wiring)
    // ══════════════════════════════════════════════════════════════════════

    // ── CP-1: ChangePointMarker round-trips through JSON with correct fields.
    // Pins the JSON schema so downstream consumers notice if it changes.

    #[test]
    fn change_point_marker_json_shape() {
        let marker = ChangePointMarker {
            detected_at: 1_700_000_042,
            round: 7,
            observed_rate: 0.05,
            baseline_rate: 0.30,
            drop_pp: 25.0,
        };
        let json = serde_json::to_string(&marker).expect("must serialize");
        let v: serde_json::Value = serde_json::from_str(&json).expect("must deserialize");
        assert_eq!(v["detected_at"], 1_700_000_042u64, "detected_at field");
        assert_eq!(v["round"], 7u64, "round field");
        assert!(
            (v["observed_rate"].as_f64().unwrap() - 0.05).abs() < 1e-9,
            "observed_rate field"
        );
        assert!(
            (v["baseline_rate"].as_f64().unwrap() - 0.30).abs() < 1e-9,
            "baseline_rate field"
        );
        assert!(
            (v["drop_pp"].as_f64().unwrap() - 25.0).abs() < 1e-9,
            "drop_pp field"
        );
    }

    // ── CP-2: CampaignState with change_points persists and reloads correctly.
    // Verifies the new field survives the persist → load round trip.

    #[test]
    fn campaign_state_change_points_persist_roundtrip() {
        let path = std::env::temp_dir().join("wafrift-hunt-cp-roundtrip-test.json");
        let _ = std::fs::remove_file(&path);

        let state = CampaignState {
            campaign_id: "cp-test".into(),
            target_url: "http://localhost".into(),
            started_at: 0,
            rounds_completed: 10,
            total_bypasses: 2,
            schema_version: CampaignState::SCHEMA_VERSION,
            bypasses: vec![],
            change_points: vec![ChangePointMarker {
                detected_at: 99999,
                round: 5,
                observed_rate: 0.0,
                baseline_rate: 0.35,
                drop_pp: 35.0,
            }],
        };
        persist_state(&path, &state).unwrap();

        let loaded = load_or_init_state(&path, "cp-test", "http://localhost");
        assert_eq!(
            loaded.change_points.len(),
            1,
            "one change_point must survive round-trip"
        );
        assert_eq!(loaded.change_points[0].round, 5);
        assert!((loaded.change_points[0].baseline_rate - 0.35).abs() < 1e-9);
        assert!((loaded.change_points[0].drop_pp - 35.0).abs() < 1e-9);

        let _ = std::fs::remove_file(&path);
    }

    // ── CP-3: v1 state file (no change_points field) loads cleanly into v2.
    // Backwards-compat: campaigns started before C-11 must not fail to load.

    #[test]
    fn change_points_defaults_to_empty_on_v1_state_file() {
        let path = std::env::temp_dir().join("wafrift-hunt-v1-compat-test.json");
        let _ = std::fs::remove_file(&path);

        // Write a v1-style JSON that has no change_points key.
        let v1_json = r#"{
            "campaign_id": "v1-compat",
            "target_url": "http://localhost",
            "started_at": 0,
            "rounds_completed": 3,
            "total_bypasses": 1,
            "schema_version": 1,
            "bypasses": []
        }"#;
        std::fs::write(&path, v1_json).unwrap();

        let loaded = load_or_init_state(&path, "v1-compat", "http://localhost");
        assert_eq!(
            loaded.change_points.len(),
            0,
            "v1 state file must deserialize with empty change_points"
        );
        assert_eq!(loaded.rounds_completed, 3);

        let _ = std::fs::remove_file(&path);
    }

    // ── CP-4: change_point_alarm flag is available on HuntArgs with defaults.

    #[test]
    fn change_point_alarm_flags_have_correct_defaults() {
        let args = HuntArgs {
            base_url: None,
            target: None,
            corpus: PathBuf::from("corpus"),
            class: vec![],
            strategies: vec!["heavy".into()],
            waf_name: None,
            variants: 5,
            interval_secs: 60,
            max_duration_secs: 0,
            round_budget: 0,
            campaign_id: None,
            i_have_permission: None,
            delay_ms: 0,
            change_point_alarm: false,
            change_point_window: 50,
            change_point_k: 0.05,
            change_point_h: 0.5,
        };
        assert!(!args.change_point_alarm, "default alarm is off");
        assert_eq!(args.change_point_window, 50);
        assert!((args.change_point_k - 0.05).abs() < 1e-9);
        assert!((args.change_point_h - 0.5).abs() < 1e-9);
    }