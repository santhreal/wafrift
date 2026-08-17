    use super::*;

    #[test]
    fn default_state_no_evasion() {
        let state = HostState::default();
        assert_eq!(state.escalation_level(), EscalationLevel::None);
    }

    #[test]
    fn light_after_two_blocks() {
        let mut state = HostState::default();
        state.record_block();
        state.record_block();
        assert_eq!(state.escalation_level(), EscalationLevel::Light);
    }

    #[test]
    fn medium_after_four_blocks() {
        let mut state = HostState::default();
        for _ in 0..4 {
            state.record_block();
        }
        assert_eq!(state.escalation_level(), EscalationLevel::Medium);
    }

    #[test]
    fn heavy_after_many_blocks() {
        let mut state = HostState::default();
        for _ in 0..10 {
            state.record_block();
        }
        assert_eq!(state.escalation_level(), EscalationLevel::Heavy);
    }

    #[test]
    fn record_success_tracks_technique() {
        let mut state = HostState::default();
        state.record_success(Technique::PayloadEncoding("CaseAlternation".into()));
        assert_eq!(state.successes, 1);
        assert!(state.last_success.is_some());
    }

    #[test]
    fn record_block_for_tracks_technique() {
        let mut state = HostState::default();
        state.record_block_for("CaseAlternation");
        state.record_block_for("CaseAlternation");
        assert_eq!(state.blocks, 2);
        assert_eq!(state.technique_stats[0].2, 2); // 2 attempts
    }

    #[test]
    fn record_block_for_many_one_http_block_multi_technique() {
        let mut state = HostState::default();
        state.record_block_for_many(&["a".to_string(), "b".to_string()]);
        assert_eq!(state.blocks, 1);
        assert_eq!(state.technique_stats.len(), 2);
        assert_eq!(
            state
                .technique_stats
                .iter()
                .find(|(n, _, _)| n == "a")
                .unwrap()
                .2,
            1
        );
        assert_eq!(
            state
                .technique_stats
                .iter()
                .find(|(n, _, _)| n == "b")
                .unwrap()
                .2,
            1
        );
    }

    #[test]
    fn record_success_for_many_compound() {
        let mut state = HostState::default();
        state.record_success_for_many(&[
            Technique::PayloadEncoding("A".into()),
            Technique::PayloadEncoding("B".into()),
        ]);
        assert_eq!(state.successes, 1);
        let sa = state
            .technique_stats
            .iter()
            .find(|(n, _, _)| n == "encoding:A")
            .unwrap();
        assert_eq!(sa.1, 1);
        assert_eq!(sa.2, 1);
    }

    #[test]
    fn best_technique_needs_two_attempts() {
        let mut state = HostState::default();
        state.record_success(Technique::PayloadEncoding("DoubleUrlEncode".into()));
        // One attempt, should not be returned
        assert!(state.best_technique().is_none());
    }

    #[test]
    fn needs_evasion_default() {
        let state = HostState::default();
        assert!(state.needs_evasion()); // Safe default
    }

    #[test]
    fn needs_evasion_after_success_no_blocks() {
        let state = HostState {
            successes: 5,
            ..Default::default()
        };
        assert!(!state.needs_evasion());
    }

    #[test]
    fn confirm_waf_sets_flag() {
        let mut state = HostState::default();
        state.confirm_waf(Some("Cloudflare".into()));
        assert!(state.waf_confirmed);
        assert_eq!(state.waf_name.as_deref(), Some("Cloudflare"));
        assert!(state.needs_evasion());
    }

    // ── Adaptive rotation tests ─────────────────────────────────────

    #[test]
    fn no_winners_before_discovery() {
        let state = HostState::default();
        assert!(!state.has_winners());
        assert!(state.proven_winners.is_empty());
    }

    #[test]
    fn evaluate_pools_promotes_winners() {
        let mut state = HostState {
            technique_stats: vec![
                ("GoodTech".into(), 9, 10), // 90%, should be winner
                ("OkTech".into(), 7, 10),   // 70%, should be winner
                ("BadTech".into(), 1, 10),  // 10%, should be blocklisted
                ("TooFew".into(), 2, 2),    // 100% but only 2 attempts, skip
            ],
            ..Default::default()
        };
        state.evaluate_pools();
        assert!(state.discovery_complete);
        assert!(state.proven_winners.contains(&"GoodTech".to_string()));
        assert!(state.proven_winners.contains(&"OkTech".to_string()));
        assert!(!state.proven_winners.contains(&"BadTech".to_string()));
        assert!(!state.proven_winners.contains(&"TooFew".to_string()));
        assert!(state.blocklisted.contains(&"BadTech".to_string()));
    }

    #[test]
    fn evaluate_pools_skips_insufficient_data() {
        // Only 5 total attempts (not enough to declare discovery).
        let mut state = HostState {
            technique_stats: vec![("T1".into(), 3, 5)],
            ..Default::default()
        };
        state.evaluate_pools();
        assert!(!state.discovery_complete);
        assert!(state.proven_winners.is_empty());
    }

    #[test]
    fn next_winner_round_robins() {
        let mut state = HostState {
            proven_winners: vec!["A".into(), "B".into(), "C".into()],
            discovery_complete: true,
            ..Default::default()
        };

        assert_eq!(state.next_winner().as_deref(), Some("A"));
        assert_eq!(state.next_winner().as_deref(), Some("B"));
        assert_eq!(state.next_winner().as_deref(), Some("C"));
        assert_eq!(state.next_winner().as_deref(), Some("A"));
    }

    #[test]
    fn next_winner_returns_none_when_empty() {
        let mut state = HostState::default();
        assert!(state.next_winner().is_none());
    }

    #[test]
    fn drift_detection_evicts_winner() {
        let mut state = HostState {
            proven_winners: vec!["WinTech".into(), "StillGood".into()],
            discovery_complete: true,
            ..Default::default()
        };

        // Two consecutive blocks on WinTech triggers eviction.
        state.record_block_for("WinTech");
        state.record_block_for("WinTech");

        assert!(!state.proven_winners.contains(&"WinTech".to_string()));
        assert!(state.blocklisted.contains(&"WinTech".to_string()));
        // StillGood survives.
        assert!(state.proven_winners.contains(&"StillGood".to_string()));
    }

    #[test]
    fn success_resets_drift_counter() {
        let mut state = HostState {
            proven_winners: vec!["encoding:Tech".into()],
            discovery_complete: true,
            ..Default::default()
        };

        // One block.
        state.record_block_for("encoding:Tech");
        // Then a success (should reset the drift counter).
        state.record_success(Technique::PayloadEncoding("Tech".into()));

        // Another block (should NOT evict because counter was reset).
        state.record_block_for("encoding:Tech");
        assert!(state.proven_winners.contains(&"encoding:Tech".to_string()));
    }

    #[test]
    fn all_winners_evicted_triggers_rediscovery() {
        let mut state = HostState {
            proven_winners: vec!["OnlyWinner".into()],
            discovery_complete: true,
            blocklisted: vec!["PrevBad".into()],
            technique_stats: vec![("OnlyWinner".into(), 5, 10)],
            ..Default::default()
        };

        // Evict the only winner.
        state.record_block_for("OnlyWinner");
        state.record_block_for("OnlyWinner");

        // Should re-enter discovery mode.
        assert!(!state.discovery_complete);
        assert!(state.proven_winners.is_empty());
        // Blocklist and stats are cleared for a clean re-discovery.
        assert!(state.blocklisted.is_empty());
        assert!(state.technique_stats.is_empty());
    }

    #[test]
    fn full_lifecycle_discover_rotate_drift_rediscover() {
        let mut state = HostState::default();

        // Phase 1: Discovery (simulate 15 technique observations).
        for _ in 0..5 {
            state.record_success(Technique::PayloadEncoding("Winner".into()));
        }
        for _ in 0..5 {
            state.record_block_for("Loser");
        }
        // Add some more to reach threshold.
        for _ in 0..5 {
            state.record_success(Technique::PayloadEncoding("AlsoGood".into()));
        }

        // Should have promoted winners.
        assert!(state.discovery_complete);
        assert!(state.has_winners());
        assert!(
            state
                .proven_winners
                .contains(&"encoding:Winner".to_string())
                || state
                    .proven_winners
                    .contains(&"encoding:AlsoGood".to_string())
        );

        // Phase 2: Rotation (get next winner).
        let w = state.next_winner();
        assert!(w.is_some());

        // Phase 3: Drift (block a winner twice).
        let winner_name = state.proven_winners[0].clone();
        state.record_block_for(&winner_name);
        state.record_block_for(&winner_name);

        // Winner should be evicted.
        assert!(!state.proven_winners.contains(&winner_name));
    }

    #[test]
    fn blocklisted_encoding_not_suggested() {
        let mut state = HostState::default();
        // Blocklist a known encoding strategy name.
        state.blocklisted.push("CaseAlternation".into());
        // next_encoding should skip it.
        if let Some(strategy) = state.next_encoding() {
            assert_ne!(format!("{strategy:?}"), "CaseAlternation");
        }
    }

    // ── Rich signal API tests ───────────────────────────────────────

    #[test]
    fn signal_rate_limit_does_not_penalize_technique() {
        let mut state = HostState::default();
        state.record_signal(
            false,                                     // not hard block
            false,                                     // not soft block
            true,                                      // IS rate limit
            false,                                     // not challenge
            Some("Cloudflare"),                        // matched WAF
            &["DoubleUrlEncode".to_string()],          // prioritize
            &["CaseAlternation".to_string()],          // avoid
            Some("single_pass_url_decode"),            // inspection model
            &["encoding:DoubleUrlEncode".to_string()], // technique keys
        );
        // Rate limit should NOT increase blocks.
        assert_eq!(state.blocks, 0);
        assert_eq!(state.rate_limits, 1);
        // But should still ingest WAF hints.
        assert_eq!(state.waf_name.as_deref(), Some("Cloudflare"));
        assert!(
            state
                .prioritized_techniques
                .contains(&"DoubleUrlEncode".to_string())
        );
    }

    #[test]
    fn signal_challenge_does_not_penalize_technique() {
        let mut state = HostState::default();
        state.record_signal(
            false,
            false,
            false,
            true, // challenge
            Some("Cloudflare"),
            &[],
            &[],
            None,
            &["encoding:UrlEncode".to_string()],
        );
        assert_eq!(state.blocks, 0);
        assert_eq!(state.challenges, 1);
    }

    #[test]
    fn signal_hard_block_records_block_with_technique() {
        let mut state = HostState::default();
        state.record_signal(
            true, // hard block
            false,
            false,
            false,
            Some("ModSecurity CRS"),
            &["CommentObfuscation".to_string()],
            &[],
            Some("multi_regex_scoring"),
            &["encoding:UrlEncode".to_string()],
        );
        assert_eq!(state.blocks, 1);
        assert_eq!(state.waf_name.as_deref(), Some("ModSecurity CRS"));
        assert_eq!(
            state.inspection_model.as_deref(),
            Some("multi_regex_scoring")
        );
        // Technique should have been attributed.
        assert!(
            state
                .technique_stats
                .iter()
                .any(|(n, _, a)| n == "encoding:UrlEncode" && *a == 1)
        );
    }

    #[test]
    fn signal_pass_records_success() {
        let mut state = HostState::default();
        state.record_signal(
            false,
            false,
            false,
            false, // pass
            None,
            &[],
            &[],
            None,
            &[],
        );
        assert_eq!(state.successes, 1);
        assert_eq!(state.blocks, 0);
    }

    #[test]
    fn signal_merges_prioritized_and_avoided() {
        let mut state = HostState::default();
        // First signal.
        state.record_signal(
            true,
            false,
            false,
            false,
            Some("TestWAF"),
            &["A".to_string(), "B".to_string()],
            &["X".to_string()],
            None,
            &[],
        );
        // Second signal with overlapping and new techniques.
        state.record_signal(
            true,
            false,
            false,
            false,
            None,
            &["B".to_string(), "C".to_string()],
            &["X".to_string(), "Y".to_string()],
            None,
            &[],
        );
        // Union (no duplicates).
        assert_eq!(state.prioritized_techniques, vec!["A", "B", "C"]);
        assert_eq!(state.avoided_techniques, vec!["X", "Y"]);
    }

    #[test]
    fn should_skip_technique_checks_both_lists() {
        let mut state = HostState::default();
        state.avoided_techniques.push("CaseAlternation".into());
        state.blocklisted.push("UrlEncode".into());
        assert!(state.should_skip_technique("CaseAlternation"));
        assert!(state.should_skip_technique("UrlEncode"));
        assert!(!state.should_skip_technique("DoubleUrlEncode"));
    }

    #[test]
    fn suggested_techniques_filters_skipped() {
        let state = HostState {
            prioritized_techniques: vec![
                "DoubleUrlEncode".into(),
                "CaseAlternation".into(),
                "UnicodeHomoglyph".into(),
            ],
            avoided_techniques: vec!["CaseAlternation".into()],
            ..HostState::default()
        };
        let suggested = state.suggested_techniques();
        assert_eq!(suggested, vec!["DoubleUrlEncode", "UnicodeHomoglyph"]);
    }

    #[test]
    fn waf_name_not_overwritten_by_subsequent_signals() {
        let mut state = HostState::default();
        state.record_signal(
            true,
            false,
            false,
            false,
            Some("Cloudflare"),
            &[],
            &[],
            None,
            &[],
        );
        state.record_signal(
            true,
            false,
            false,
            false,
            Some("ModSecurity"),
            &[],
            &[],
            None,
            &[],
        );
        // First detection wins (don't flip-flop).
        assert_eq!(state.waf_name.as_deref(), Some("Cloudflare"));
    }

    // ── Overflow guard tests ────────────────────────────────────────────

    #[test]
    fn bump_success_saturates_at_u32_max_not_wraps() {
        // Pre-fix: plain `+= 1` would overflow in debug (panic) or
        // silently wrap to 0 in release after 2^32 successes on the
        // same technique in a long-running proxy session.
        let mut state = HostState::default();
        // Inject a stat entry already at (u32::MAX - 1, u32::MAX - 1)
        // to force the boundary on the very next success.
        state
            .technique_stats
            .push(("encoding:Test".to_string(), u32::MAX - 1, u32::MAX - 1));
        // Record one more success (this used to plain-add, now saturates).
        state.bump_success_for_technique(&Technique::PayloadEncoding("Test".into()));
        let stat = state
            .technique_stats
            .iter()
            .find(|(n, _, _)| n == "encoding:Test")
            .expect("stat entry must exist");
        // Both successes (stat.1) and attempts (stat.2) must saturate, not wrap.
        assert_eq!(stat.1, u32::MAX, "successes must saturate at u32::MAX");
        assert_eq!(stat.2, u32::MAX, "attempts must saturate at u32::MAX");

        // One more: must stay at MAX, not wrap back to 0.
        state.bump_success_for_technique(&Technique::PayloadEncoding("Test".into()));
        let stat2 = state
            .technique_stats
            .iter()
            .find(|(n, _, _)| n == "encoding:Test")
            .expect("stat entry must exist");
        assert_eq!(
            stat2.1,
            u32::MAX,
            "successes must remain at u32::MAX after second saturating add"
        );
        assert_eq!(
            stat2.2,
            u32::MAX,
            "attempts must remain at u32::MAX after second saturating add"
        );
    }

    #[test]
    fn bump_success_and_block_both_use_saturating_arithmetic() {
        // Prove the two paths are symmetric: the block path already
        // had saturating_add; the success path now also has it.
        // Both must reach u32::MAX and stay there.
        let mut state = HostState::default();
        let name = "encoding:Sym".to_string();

        // Start at u32::MAX - 2 so we can hit the boundary in two ops.
        state
            .technique_stats
            .push((name.clone(), u32::MAX - 2, u32::MAX - 2));

        // Two successes take successes+attempts to MAX then stick.
        state.bump_success_for_technique(&Technique::PayloadEncoding("Sym".into()));
        state.bump_success_for_technique(&Technique::PayloadEncoding("Sym".into()));
        // One extra must not wrap.
        state.bump_success_for_technique(&Technique::PayloadEncoding("Sym".into()));

        let stat = state
            .technique_stats
            .iter()
            .find(|(n, _, _)| n == &name)
            .unwrap();
        assert_eq!(stat.1, u32::MAX);
        assert_eq!(stat.2, u32::MAX);
    }

    // ── F133: technique_stats cap on success path ───────────────────────

    #[test]
    fn bump_success_respects_max_technique_stats_cap() {
        // Before F133 the success path had no cap; the block path did.
        // Fill technique_stats to exactly MAX_TECHNIQUE_STATS entries via
        // the block path (which is already capped), then attempt to add a
        // brand-new unique technique via the success path.  The cap must
        // prevent the vector growing beyond MAX_TECHNIQUE_STATS.
        let mut state = HostState::default();

        // Fill to the cap using direct insertion (bypasses both code paths).
        for i in 0..MAX_TECHNIQUE_STATS {
            state.technique_stats.push((format!("dummy:{i}"), 0, 1));
        }
        assert_eq!(state.technique_stats.len(), MAX_TECHNIQUE_STATS);

        // Now attempt to add a new technique via the success path.
        // The name "encoding:NewTech" does NOT exist in technique_stats yet.
        state.bump_success_for_technique(&Technique::PayloadEncoding("NewTech".into()));

        // Vector must NOT have grown.
        assert_eq!(
            state.technique_stats.len(),
            MAX_TECHNIQUE_STATS,
            "technique_stats grew past MAX_TECHNIQUE_STATS on success path"
        );
        // And the new entry must NOT be present.
        assert!(
            !state
                .technique_stats
                .iter()
                .any(|(n, _, _)| n == "encoding:NewTech"),
            "new entry was inserted despite cap being reached"
        );
    }

    #[test]
    fn bump_success_updates_existing_entry_at_capacity() {
        // Even when at capacity, updating an EXISTING entry must still work.
        let mut state = HostState::default();

        // Insert the target entry first.
        state
            .technique_stats
            .push(("encoding:Existing".to_string(), 1, 2));

        // Fill the rest to the cap.
        for i in 0..(MAX_TECHNIQUE_STATS - 1) {
            state.technique_stats.push((format!("filler:{i}"), 0, 1));
        }
        assert_eq!(state.technique_stats.len(), MAX_TECHNIQUE_STATS);

        // Record a success for the already-present entry.
        state.bump_success_for_technique(&Technique::PayloadEncoding("Existing".into()));

        // Stats for the existing entry must have incremented.
        let stat = state
            .technique_stats
            .iter()
            .find(|(n, _, _)| n == "encoding:Existing")
            .expect("entry must exist");
        assert_eq!(stat.1, 2, "success count must increment");
        assert_eq!(stat.2, 3, "attempt count must increment");

        // Length unchanged.
        assert_eq!(state.technique_stats.len(), MAX_TECHNIQUE_STATS);
    }

    #[test]
    fn success_and_block_paths_symmetric_cap_enforcement() {
        // Both paths must refuse to insert beyond MAX_TECHNIQUE_STATS.
        // Fill to cap, then try one of each (neither may grow the vec).
        let mut state = HostState::default();

        for i in 0..MAX_TECHNIQUE_STATS {
            state.technique_stats.push((format!("pre:{i}"), 0, 1));
        }

        // Success path (new technique).
        state.bump_success_for_technique(&Technique::PayloadEncoding("SuccessNew".into()));
        // Block path (new technique name).
        state.bump_block_attempt_for_technique("BlockNew");

        assert_eq!(
            state.technique_stats.len(),
            MAX_TECHNIQUE_STATS,
            "neither path may grow technique_stats past the cap"
        );
    }

    #[test]
    fn record_success_for_many_capped_at_max_technique_stats() {
        // record_success_for_many calls bump_success_for_technique in a loop;
        // the cap must hold even when multiple unique techniques are passed.
        let mut state = HostState::default();

        for i in 0..MAX_TECHNIQUE_STATS {
            state.technique_stats.push((format!("existing:{i}"), 0, 1));
        }

        // Pass four brand-new unique techniques at once.
        state.record_success_for_many(&[
            Technique::PayloadEncoding("Bulk1".into()),
            Technique::PayloadEncoding("Bulk2".into()),
            Technique::PayloadEncoding("Bulk3".into()),
            Technique::PayloadEncoding("Bulk4".into()),
        ]);

        assert_eq!(
            state.technique_stats.len(),
            MAX_TECHNIQUE_STATS,
            "record_success_for_many must not bypass the per-technique cap"
        );
    }