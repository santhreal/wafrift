    use super::*;

    // ── Helper builders ───────────────────────────────────────────────────

    fn blocked_obs(rt_ms: f64) -> ProbeObservation {
        ProbeObservation {
            response_time_ms: rt_ms,
            was_blocked: true,
            body_hash: Some(0xaaaa_aaaa_aaaa_aaaa),
        }
    }

    fn pass_obs(rt_ms: f64) -> ProbeObservation {
        ProbeObservation {
            response_time_ms: rt_ms,
            was_blocked: false,
            body_hash: Some(0xbbbb_bbbb_bbbb_bbbb),
        }
    }

    fn pass_obs_varied(rt_ms: f64, hash: u64) -> ProbeObservation {
        ProbeObservation {
            response_time_ms: rt_ms,
            was_blocked: false,
            body_hash: Some(hash),
        }
    }

    /// Feed `n` identical stationary observations.
    fn feed_stationary(det: &mut DriftDetector, n: usize, rt: f64, blocked: bool, hash: u64) {
        for _ in 0..n {
            det.observe(ProbeObservation {
                response_time_ms: rt,
                was_blocked: blocked,
                body_hash: Some(hash),
            });
        }
    }

    // ── 1. Step change detected (latency only) ────────────────────────────

    #[test]
    fn latency_step_change_detected() {
        let mut det = DriftDetector::new(20, 3.0);
        // Establish baseline: 20 ms, not blocked.
        feed_stationary(&mut det, 30, 20.0, false, 0x1111);
        // Sudden step up to 200 ms (WAF DPI layer spinning up).
        let mut fired = false;
        for _ in 0..30 {
            if det.observe(blocked_obs(200.0)).is_some() {
                fired = true;
                break;
            }
        }
        assert!(fired, "latency step change must be detected");
    }

    // ── 2. Block-rate-only change detected ───────────────────────────────

    #[test]
    fn block_rate_step_change_detected() {
        let mut det = DriftDetector::new(20, 3.0);
        // Baseline: 0% block rate, constant latency.
        feed_stationary(&mut det, 30, 50.0, false, 0x2222);
        // Sudden 100% block rate (new WAF rule deployed).
        let mut fired = false;
        for _ in 0..30 {
            if det.observe(blocked_obs(52.0)).is_some() {
                fired = true;
                break;
            }
        }
        assert!(fired, "block-rate step change must be detected");
    }

    // ── 3. No false positives on stationary Gaussian noise ───────────────

    #[test]
    fn no_false_positives_stationary_noise() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut det = DriftDetector::new(50, 4.5);
        // Use a deterministic pseudo-random sequence (FNV-style hash chain)
        // so this test is reproducible without adding a rand dep.
        let mut seed: u64 = 0xdead_beef_cafe_babe;
        let mut false_positives = 0u32;

        for i in 0u64..500 {
            // LCG: cheap deterministic noise in [40, 60] ms range.
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let noise = ((seed >> 33) % 21) as f64; // 0..20
            let rt = 40.0 + noise;

            let mut h = DefaultHasher::new();
            i.hash(&mut h);
            let hash = h.finish() % 4; // 4 distinct bodies → stable entropy

            let obs = ProbeObservation {
                response_time_ms: rt,
                was_blocked: (seed >> 60) == 0, // ~6% block rate, stable
                body_hash: Some(hash),
            };
            if det.observe(obs).is_some() {
                false_positives += 1;
            }
        }

        // At threshold 4.5σ on stationary noise we expect 0 false positives
        // over 500 samples. Allow 1 for edge-case tolerance.
        assert!(
            false_positives <= 1,
            "too many false positives on stationary noise: {false_positives}"
        );
    }

    // ── 4. LooserNow fires when block rate drops ──────────────────────────

    #[test]
    fn looser_now_fires_on_block_rate_drop() {
        // Use a small window (8) so the baseline flushes quickly after the
        // regime change, and a low threshold (2.0) for fast detection.
        // 80 transition observations is generous, the CUSUM should fire
        // well before that once both latency and block-rate signals agree.
        let mut det = DriftDetector::new(8, 2.0);
        // Baseline: 100% block, high latency.
        feed_stationary(&mut det, 20, 150.0, true, 0xaaaa);
        // WAF reloads: drops to 0% block, low latency.
        let mut regime = None;
        for _ in 0..80 {
            regime = det.observe(pass_obs(30.0));
            if regime.is_some() {
                break;
            }
        }
        assert_eq!(
            regime,
            Some(RegimeChange::LooserNow),
            "must detect LooserNow when block rate drops"
        );
    }

    // ── 5. StricterNow fires when block rate rises ────────────────────────

    #[test]
    fn stricter_now_fires_on_block_rate_rise() {
        // Small window + low threshold for fast detection.
        let mut det = DriftDetector::new(8, 2.0);
        // Baseline: 0% block, low latency.
        feed_stationary(&mut det, 20, 30.0, false, 0x1111);
        // WAF tightens: 100% block, high latency.
        let mut regime = None;
        for _ in 0..80 {
            regime = det.observe(blocked_obs(200.0));
            if regime.is_some() {
                break;
            }
        }
        assert_eq!(
            regime,
            Some(RegimeChange::StricterNow),
            "must detect StricterNow when block rate rises"
        );
    }

    // ── 6. Multi-signal agreement required (single-signal does not fire) ──

    #[test]
    fn single_signal_alone_does_not_fire() {
        // Use a very high threshold so only latency changes; block rate stays
        // constant. With threshold=10 and window=100, two signals firing at
        // once is extremely unlikely from a single-direction latency nudge.
        // We verify the detector stays silent for a small nudge.
        let mut det = DriftDetector::new(50, 10.0);
        feed_stationary(&mut det, 60, 50.0, false, 0xcccc);

        // Tiny latency nudge (not enough to move multiple signals past threshold).
        let mut fired = false;
        for _ in 0..10 {
            if det.observe(pass_obs(55.0)).is_some() {
                fired = true;
                break;
            }
        }
        assert!(
            !fired,
            "tiny single-signal nudge must not fire with high threshold"
        );
    }

    // ── 7. Window-size boundary: detector still works at minimum window ───

    #[test]
    fn minimum_window_size_respected() {
        // window_size=0 is clamped to 8 internally.
        let mut det = DriftDetector::new(0, 2.0);
        assert_eq!(
            det.window_size, 8,
            "window_size must be clamped to minimum 8"
        );

        // Should still detect a gross step change.
        feed_stationary(&mut det, 20, 20.0, false, 0x1234);
        let mut fired = false;
        for _ in 0..30 {
            if det.observe(blocked_obs(500.0)).is_some() {
                fired = true;
                break;
            }
        }
        assert!(
            fired,
            "detector with minimum window must still detect step changes"
        );
    }

    // ── 8. Threshold sensitivity: lower threshold = faster detection ──────

    #[test]
    fn lower_threshold_detects_faster() {
        let mut fast = DriftDetector::new(20, 1.5);
        let mut slow = DriftDetector::new(20, 5.0);

        feed_stationary(&mut fast, 25, 30.0, false, 0x9999);
        feed_stationary(&mut slow, 25, 30.0, false, 0x9999);

        let mut fast_detection = None;
        let mut slow_detection = None;

        for i in 0..50u64 {
            let obs = blocked_obs(200.0);
            if fast_detection.is_none() && fast.observe(obs.clone()).is_some() {
                fast_detection = Some(i);
            }
            if slow_detection.is_none() && slow.observe(obs).is_some() {
                slow_detection = Some(i);
            }
        }

        assert!(fast_detection.is_some(), "low-threshold detector must fire");
        assert!(
            fast_detection <= slow_detection.or(Some(u64::MAX)),
            "low-threshold must detect at least as fast as high-threshold"
        );
    }

    // ── 9. JSON serialization round-trips ────────────────────────────────

    #[test]
    fn json_serialization_round_trips() {
        let mut det = DriftDetector::new(30, 3.5);
        feed_stationary(&mut det, 15, 40.0, false, 0xdead);
        det.observe(blocked_obs(300.0));

        let json = serde_json::to_string(&det).expect("serialization must succeed");
        let restored: DriftDetector =
            serde_json::from_str(&json).expect("deserialization must succeed");

        assert_eq!(restored.window_size, det.window_size);
        assert_eq!(restored.threshold, det.threshold);
        assert_eq!(restored.probe_count, det.probe_count);
    }

    // ── 10. Body-entropy change alone contributes a signal ───────────────

    #[test]
    fn body_entropy_signal_contributes() {
        let mut det = DriftDetector::new(20, 2.0);

        // Baseline: all responses identical body hash (entropy = 0).
        feed_stationary(&mut det, 30, 50.0, false, 0xAAAA_AAAA);

        // Now each response has a unique body hash (high entropy), new
        // challenge pages appearing signals rule change.
        let mut body_entropy_fired = false;
        for i in 0u64..40 {
            let obs = pass_obs_varied(52.0, i * 0xdead_beef + 1);
            // snapshot entropy increasing
            let snap_before = det.signal_snapshot()[3];
            det.observe(obs);
            let snap_after = det.signal_snapshot()[3];
            if snap_after > snap_before + 0.01 {
                body_entropy_fired = true;
                break;
            }
        }
        assert!(
            body_entropy_fired,
            "body entropy signal must increase on hash diversity"
        );
    }

    // ── 11. has_baseline returns false before window/2 probes ────────────

    #[test]
    fn has_baseline_gated_on_probe_count() {
        let mut det = DriftDetector::new(40, 4.0);
        assert!(!det.has_baseline(), "no baseline before any probes");

        for _ in 0..19 {
            det.observe(pass_obs(50.0));
        }
        assert!(!det.has_baseline(), "baseline not ready at 19/40 probes");

        det.observe(pass_obs(50.0)); // 20th probe = window_size/2
        assert!(
            det.has_baseline(),
            "baseline must be ready at window_size/2 probes"
        );
    }

    // ── 12. probe_count saturates at u64::MAX ────────────────────────────

    #[test]
    fn probe_count_saturates_not_wraps() {
        let mut det = DriftDetector::new(8, 4.0);
        // Inject a near-max count directly (can't loop 2^64 times).
        det.probe_count = u64::MAX - 1;
        det.observe(pass_obs(50.0));
        assert_eq!(
            det.probe_count,
            u64::MAX,
            "probe_count must saturate at u64::MAX"
        );
        det.observe(pass_obs(50.0));
        assert_eq!(
            det.probe_count,
            u64::MAX,
            "probe_count must remain at u64::MAX after second saturating add"
        );
    }

    // ── 13. signal_snapshot returns correct structure ─────────────────────

    #[test]
    fn signal_snapshot_structure() {
        let mut det = DriftDetector::default();
        // Zero-state snapshot.
        let snap = det.signal_snapshot();
        assert_eq!(snap.len(), 4);
        for v in &snap {
            assert!(
                v.is_finite(),
                "all signal values must be finite at zero state"
            );
        }

        // After observations the snapshot must update.
        feed_stationary(&mut det, 10, 75.0, true, 0xBEEF);
        let snap2 = det.signal_snapshot();
        // median and p95 must be ~75.0.
        assert!((snap2[0] - 75.0).abs() < 1.0, "median RT must be ~75 ms");
        // block rate must be 1.0 (all blocked).
        assert!((snap2[2] - 1.0).abs() < 0.01, "block rate must be ~1.0");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // BypassRateMonitor tests (C-11: CUSUM bypass-rate change-point)
    // ═══════════════════════════════════════════════════════════════════════

    // ── BRM-1. Empty window: current_rate is None, baseline is None ───────

    #[test]
    fn bypass_monitor_empty_window_returns_none() {
        let monitor = BypassRateMonitor::new(50, 0.05, 0.5);
        assert!(
            monitor.current_rate().is_none(),
            "no rate before window fills"
        );
        assert!(
            monitor.baseline_rate().is_none(),
            "no baseline before window fills"
        );
    }

    // ── BRM-2. Monotone good rate (30% bypass, steady) → NO alarm ─────────

    #[test]
    fn bypass_monitor_steady_rate_no_alarm() {
        let mut monitor = BypassRateMonitor::new(50, 0.05, 0.5);
        // 200 samples at ~30% bypass rate (deterministic: every 3rd is bypass).
        let mut fired = false;
        for i in 0..200usize {
            if let ChangePointEvent::AlarmFired { .. } = monitor.observe(i % 3 == 0) {
                fired = true;
                break;
            }
        }
        assert!(!fired, "steady 33% bypass rate must not fire an alarm");
    }

    // ── BRM-3. Monotone bad rate (0% bypass after baseline) → alarm fires ─

    #[test]
    fn bypass_monitor_zero_rate_fires_alarm() {
        let mut monitor = BypassRateMonitor::new(20, 0.05, 0.5);
        // Establish baseline at 50% bypass (10 bypasses in first 20).
        for i in 0..20usize {
            monitor.observe(i % 2 == 0);
        }
        assert!(monitor.baseline_rate().is_some());
        // Drop to 0% (alarm must fire within 30 more samples).
        let mut fired = false;
        for _ in 0..30 {
            if let ChangePointEvent::AlarmFired { .. } = monitor.observe(false) {
                fired = true;
                break;
            }
        }
        assert!(
            fired,
            "zero bypass rate after 50% baseline must trigger alarm"
        );
    }

    // ── BRM-4. Bimodal pattern: alarm at the break ─────────────────────────

    #[test]
    fn bypass_monitor_bimodal_alarm_at_break() {
        let mut monitor = BypassRateMonitor::new(30, 0.05, 0.5);
        // Phase 1: 60% bypass (steady regime).
        for i in 0..60usize {
            monitor.observe(i % 5 < 3); // 3/5 = 60%
        }
        // Phase 2: 0% bypass (WAF rule update).
        let mut alarm_idx: Option<usize> = None;
        for i in 0..60usize {
            if let ChangePointEvent::AlarmFired { .. } = monitor.observe(false) {
                alarm_idx = Some(i);
                break;
            }
        }
        assert!(
            alarm_idx.is_some(),
            "bimodal pattern must trigger alarm in phase-2 region"
        );
        // Alarm must fire reasonably quickly (within 40 samples of the break).
        assert!(
            alarm_idx.unwrap() < 40,
            "alarm should fire within 40 samples of the regime break"
        );
    }

    // ── BRM-5. High threshold (h=10) does not fire on moderate drop ───────

    #[test]
    fn bypass_monitor_high_threshold_no_fire() {
        let mut monitor = BypassRateMonitor::new(30, 0.05, 10.0);
        // Establish 50% baseline.
        for i in 0..30usize {
            monitor.observe(i % 2 == 0);
        }
        // Drop to 40% (a moderate, not catastrophic, decrease).
        let mut fired = false;
        for i in 0..60usize {
            if let ChangePointEvent::AlarmFired { .. } = monitor.observe(i % 5 < 2) {
                fired = true;
                break;
            }
        }
        assert!(!fired, "h=10 must NOT fire on a moderate rate drop");
    }

    // ── BRM-6. Low threshold (h=0.01) fires near-immediately ─────────────

    #[test]
    fn bypass_monitor_low_threshold_fires_fast() {
        let mut monitor = BypassRateMonitor::new(10, 0.05, 0.01);
        // Establish 100% bypass baseline.
        for _ in 0..10 {
            monitor.observe(true);
        }
        // First blocked sample should fire almost immediately.
        let mut alarm_idx: Option<usize> = None;
        for i in 0..10 {
            if let ChangePointEvent::AlarmFired { .. } = monitor.observe(false) {
                alarm_idx = Some(i);
                break;
            }
        }
        assert!(
            alarm_idx.is_some(),
            "h=0.01 must fire almost immediately on any downward deviation"
        );
        assert!(
            alarm_idx.unwrap() <= 5,
            "h=0.01 must fire within 5 samples of the change (got {:?})",
            alarm_idx
        );
    }

    // ── BRM-7. Reset-after-alarm: baseline re-established at new level ─────

    #[test]
    fn bypass_monitor_reset_after_alarm() {
        // Use window_size=4 so the window fully drains in 4 steps.
        // With h=0.5 and k=0.05, a 100%→0% drop will fire alarm
        // after a few samples, then the window drains within 4 more.
        let mut monitor = BypassRateMonitor::new(4, 0.05, 0.5);
        // Establish 100% bypass baseline.
        for _ in 0..4 {
            monitor.observe(true);
        }
        // Drive to 0%, run enough samples to (a) fire the alarm AND
        // (b) fully flush all `true` values from the window before
        //     the second-alarm check begins.
        let mut first_alarm_fired = false;
        for _ in 0..20 {
            let evt = monitor.observe(false);
            if let ChangePointEvent::AlarmFired { observed_rate, .. } = evt {
                first_alarm_fired = true;
                // After reset, baseline must equal the observed rate.
                let new_baseline = monitor.baseline_rate().unwrap();
                assert!(
                    (new_baseline - observed_rate).abs() < 0.05,
                    "baseline must reset to observed rate after alarm: new_baseline={new_baseline:.3}, observed={observed_rate:.3}"
                );
                // Continue the loop (don't break) so the window drains
                // to all-false before the second-alarm test below.
                // The alarm has fired and baseline has been reset; we
                // need a few more calls to drain the old `true` entries.
            }
        }
        assert!(first_alarm_fired, "first alarm must have fired");
        // After 20 blocked calls on a size-4 window, the window is
        // definitely all-false (0% bypass rate = 0%) and baseline = 0%.

        // Now stay at 0%, no second alarm should fire within 100 samples
        // (CUSUM accumulator stays at 0 when baseline ≈ p_observed).
        let mut second_alarm = false;
        for _ in 0..100 {
            if let ChangePointEvent::AlarmFired { .. } = monitor.observe(false) {
                second_alarm = true;
                break;
            }
        }
        assert!(
            !second_alarm,
            "no second alarm when staying at 0% after baseline reset and window drain"
        );
    }

    // ── BRM-8. ANTI-RIG: alarm fires within 20 attempts of 30%→0% drop ───

    #[test]
    fn bypass_monitor_alarm_within_20_samples_of_drop() {
        // Uses default params (window=50, k=0.05, h=0.5).
        let mut monitor = BypassRateMonitor::new_default();
        // Fill baseline window at exactly 30% bypass rate.
        // 50 samples: 15 bypassed, 35 blocked. Deterministic.
        for i in 0..50usize {
            monitor.observe(i % 10 < 3); // 3/10 = 30%
        }
        let baseline = monitor.baseline_rate().expect("baseline must be set");
        assert!(
            (baseline - 0.3).abs() < 0.05,
            "baseline must be ~30%: got {baseline:.3}"
        );

        // Drop to 0% bypass (alarm MUST fire within 20 samples).
        let mut alarm_idx: Option<usize> = None;
        for i in 0..20 {
            if let ChangePointEvent::AlarmFired { .. } = monitor.observe(false) {
                alarm_idx = Some(i);
                break;
            }
        }
        assert!(
            alarm_idx.is_some(),
            "alarm must fire within 20 samples of a 30%→0% bypass rate drop"
        );
    }

    // ── BRM-9. ANTI-RIG: no alarm on steady 30% for 200 samples ──────────

    #[test]
    fn bypass_monitor_no_alarm_on_steady_30pct_200_samples() {
        let mut monitor = BypassRateMonitor::new_default();
        // 200 samples at exactly 30% bypass rate (deterministic).
        let mut fired = false;
        for i in 0..200usize {
            if let ChangePointEvent::AlarmFired { .. } = monitor.observe(i % 10 < 3) {
                fired = true;
                break;
            }
        }
        assert!(
            !fired,
            "must NOT fire on a perfectly steady 30% bypass rate over 200 samples"
        );
    }

    // ── BRM-10. current_rate tracks the window accurately ─────────────────

    #[test]
    fn bypass_monitor_current_rate_accurate() {
        let mut monitor = BypassRateMonitor::new(10, 0.05, 0.5);
        // Fill with exactly 7 bypassed out of 10.
        for i in 0..10usize {
            monitor.observe(i < 7);
        }
        let rate = monitor
            .current_rate()
            .expect("rate must be available after window fills");
        assert!(
            (rate - 0.7).abs() < 0.01,
            "current_rate must be ~70% but got {rate:.3}"
        );
    }