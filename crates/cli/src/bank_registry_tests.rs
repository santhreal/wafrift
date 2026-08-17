    use super::*;

    fn fresh_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "wafrift-bank-registry-{}-{}",
            label,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn sign_then_verify_round_trip() {
        let dir = fresh_dir("rt");
        let env_path = dir.join("envelope.json");
        std::fs::write(&env_path, br#"{"hosts":["api.example.com"]}"#).unwrap();

        // gen-key
        let key_path = dir.join("signing.hex");
        let code = run_gen_key(GenKeyArgs {
            output: Some(key_path.clone()),
        });
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));

        // sign
        let signed_path = dir.join("envelope.signed.json");
        let code = run_sign(SignArgs {
            envelope: env_path.clone(),
            bundle_name: Some("rt-bundle".into()),
            output: Some(signed_path.clone()),
            signing_key: Some(key_path.clone()),
        });
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
        assert!(signed_path.exists());

        // Trust the signing public key, verify.
        let pk = SigningKey::from_secret_hex(std::fs::read_to_string(&key_path).unwrap().trim())
            .unwrap()
            .verifying_key_hex();
        let trust_path = dir.join("trust.toml");
        let mut tl = TrustList::new();
        tl.allow_hex(&pk, "tester");
        tl.save(&trust_path).unwrap();

        let code = run_verify(VerifyArgs {
            signed: signed_path,
            trust_list: Some(trust_path),
            max_age_days: DEFAULT_BUNDLE_MAX_AGE_DAYS,
            allow_stale: false,
        });
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_rejects_untrusted_publisher() {
        let dir = fresh_dir("untrusted");
        let env_path = dir.join("envelope.json");
        std::fs::write(&env_path, b"{}").unwrap();
        let key_path = dir.join("signing.hex");
        run_gen_key(GenKeyArgs {
            output: Some(key_path.clone()),
        });
        let signed_path = dir.join("envelope.signed.json");
        run_sign(SignArgs {
            envelope: env_path,
            bundle_name: Some("u".into()),
            output: Some(signed_path.clone()),
            signing_key: Some(key_path),
        });
        // Empty trust list (must reject).
        let trust_path = dir.join("trust.toml");
        TrustList::new().save(&trust_path).unwrap();
        let code = run_verify(VerifyArgs {
            signed: signed_path,
            trust_list: Some(trust_path),
            max_age_days: DEFAULT_BUNDLE_MAX_AGE_DAYS,
            allow_stale: false,
        });
        assert_ne!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::SUCCESS),
            "verify must fail under empty trust list"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_rejects_tampered_signed_bundle() {
        let dir = fresh_dir("tampered");
        let env_path = dir.join("envelope.json");
        std::fs::write(&env_path, br#"{"a":1}"#).unwrap();
        let key_path = dir.join("signing.hex");
        run_gen_key(GenKeyArgs {
            output: Some(key_path.clone()),
        });
        let signed_path = dir.join("envelope.signed.json");
        run_sign(SignArgs {
            envelope: env_path,
            bundle_name: Some("t".into()),
            output: Some(signed_path.clone()),
            signing_key: Some(key_path.clone()),
        });

        // Tamper the genome payload after signing, parse the signed
        // bundle JSON, mutate the inner payload bytes, write it back.
        // String-replace on the raw bytes is brittle (depends on the
        // exact serde-json key order), so deserialize / mutate /
        // re-serialize.
        let raw = std::fs::read_to_string(&signed_path).unwrap();
        let mut signed: SignedBundle = serde_json::from_str(&raw).expect("parse signed bundle");
        signed.bundle.genomes[0].payload = format!("EVIL_{}", signed.bundle.genomes[0].payload);
        std::fs::write(&signed_path, serde_json::to_string_pretty(&signed).unwrap()).unwrap();

        // Trust the publisher anyway.
        let pk = SigningKey::from_secret_hex(std::fs::read_to_string(&key_path).unwrap().trim())
            .unwrap()
            .verifying_key_hex();
        let trust_path = dir.join("trust.toml");
        let mut tl = TrustList::new();
        tl.allow_hex(&pk, "tester");
        tl.save(&trust_path).unwrap();

        let code = run_verify(VerifyArgs {
            signed: signed_path,
            trust_list: Some(trust_path),
            max_age_days: DEFAULT_BUNDLE_MAX_AGE_DAYS,
            allow_stale: false,
        });
        assert_ne!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::SUCCESS),
            "verify must reject tampered signed bundle"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// §15 replay defence: a signed bundle from a still-trusted key whose
    /// `created_unix` is older than the freshness window must be REFUSED by
    /// the default `run_verify` path (the production import path previously
    /// called the unprotected `verify()`, so a captured bundle replayed
    /// forever). `--allow-stale` is the documented opt-out.
    #[test]
    fn verify_rejects_stale_bundle_but_allow_stale_overrides() {
        let dir = fresh_dir("stale");
        let env_path = dir.join("envelope.json");
        std::fs::write(&env_path, br#"{"hosts":["api.example.com"]}"#).unwrap();
        let key_path = dir.join("signing.hex");
        run_gen_key(GenKeyArgs {
            output: Some(key_path.clone()),
        });
        let signed_path = dir.join("envelope.signed.json");
        run_sign(SignArgs {
            envelope: env_path,
            bundle_name: Some("stale-bundle".into()),
            output: Some(signed_path.clone()),
            signing_key: Some(key_path.clone()),
        });

        // Back-date created_unix to 60 days ago (beyond the 30-day default).
        let raw = std::fs::read_to_string(&signed_path).unwrap();
        let mut signed: SignedBundle = serde_json::from_str(&raw).expect("parse signed bundle");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        signed.bundle.created_unix = now.saturating_sub(60 * 86_400);
        // Re-sign so the signature matches the back-dated payload (the
        // timestamp is inside the signed canonical bytes, so we must
        // re-sign to isolate the FRESHNESS check from the signature check).
        let sk = SigningKey::from_secret_hex(std::fs::read_to_string(&key_path).unwrap().trim())
            .unwrap();
        let resigned = signed.bundle.sign(&sk).expect("re-sign back-dated bundle");
        std::fs::write(
            &signed_path,
            serde_json::to_string_pretty(&resigned).unwrap(),
        )
        .unwrap();

        // Trust the publisher.
        let pk = sk.verifying_key_hex();
        let trust_path = dir.join("trust.toml");
        let mut tl = TrustList::new();
        tl.allow_hex(&pk, "tester");
        tl.save(&trust_path).unwrap();

        // Default path (freshness ON) must REFUSE the stale bundle.
        let code = run_verify(VerifyArgs {
            signed: signed_path.clone(),
            trust_list: Some(trust_path.clone()),
            max_age_days: DEFAULT_BUNDLE_MAX_AGE_DAYS,
            allow_stale: false,
        });
        assert_ne!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::SUCCESS),
            "default verify must reject a 60-day-old bundle (replay defence)"
        );

        // --allow-stale opts out → the same bundle verifies (signature +
        // trust still hold, only the freshness window is waived).
        let code = run_verify(VerifyArgs {
            signed: signed_path,
            trust_list: Some(trust_path),
            max_age_days: DEFAULT_BUNDLE_MAX_AGE_DAYS,
            allow_stale: true,
        });
        assert_eq!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::SUCCESS),
            "--allow-stale must accept the otherwise-valid stale bundle"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// §15 clock-skew guard: a bundle dated far in the FUTURE (forged
    /// timestamp that would otherwise dodge the age check) is refused.
    #[test]
    fn verify_rejects_future_dated_bundle() {
        let dir = fresh_dir("future");
        let env_path = dir.join("envelope.json");
        std::fs::write(&env_path, br#"{"hosts":["api.example.com"]}"#).unwrap();
        let key_path = dir.join("signing.hex");
        run_gen_key(GenKeyArgs {
            output: Some(key_path.clone()),
        });
        let signed_path = dir.join("envelope.signed.json");
        run_sign(SignArgs {
            envelope: env_path,
            bundle_name: Some("future-bundle".into()),
            output: Some(signed_path.clone()),
            signing_key: Some(key_path.clone()),
        });

        let raw = std::fs::read_to_string(&signed_path).unwrap();
        let mut signed: SignedBundle = serde_json::from_str(&raw).expect("parse signed bundle");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        signed.bundle.created_unix = now.saturating_add(86_400); // +1 day, ≫ 300s skew
        let sk = SigningKey::from_secret_hex(std::fs::read_to_string(&key_path).unwrap().trim())
            .unwrap();
        let resigned = signed.bundle.sign(&sk).expect("re-sign future bundle");
        std::fs::write(
            &signed_path,
            serde_json::to_string_pretty(&resigned).unwrap(),
        )
        .unwrap();

        let pk = sk.verifying_key_hex();
        let trust_path = dir.join("trust.toml");
        let mut tl = TrustList::new();
        tl.allow_hex(&pk, "tester");
        tl.save(&trust_path).unwrap();

        let code = run_verify(VerifyArgs {
            signed: signed_path,
            trust_list: Some(trust_path),
            max_age_days: DEFAULT_BUNDLE_MAX_AGE_DAYS,
            allow_stale: false,
        });
        assert_ne!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::SUCCESS),
            "verify must reject a bundle dated a day in the future (clock-skew/forgery guard)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn trust_add_then_list_round_trip() {
        let dir = fresh_dir("trust");
        let trust_path = dir.join("trust.toml");
        let code = run_trust(TrustArgs {
            action: TrustAction::Add(TrustAddArgs {
                public_key_hex: "abcdef".into(),
                name: "alice".into(),
                trust_list: Some(trust_path.clone()),
            }),
        });
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
        let tl = TrustList::load(&trust_path).unwrap();
        assert!(tl.contains("abcdef"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn trust_remove_drops_publisher() {
        let dir = fresh_dir("trust-rm");
        let trust_path = dir.join("trust.toml");
        run_trust(TrustArgs {
            action: TrustAction::Add(TrustAddArgs {
                public_key_hex: "abc".into(),
                name: "alice".into(),
                trust_list: Some(trust_path.clone()),
            }),
        });
        run_trust(TrustArgs {
            action: TrustAction::Remove(TrustRemoveArgs {
                public_key_hex: "abc".into(),
                trust_list: Some(trust_path.clone()),
            }),
        });
        let tl = TrustList::load(&trust_path).unwrap();
        assert!(!tl.contains("abc"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn gen_key_refuses_to_overwrite_existing_file() {
        let dir = fresh_dir("nokoverwrite");
        let key_path = dir.join("signing.hex");
        std::fs::write(&key_path, "preexisting").unwrap();
        let code = run_gen_key(GenKeyArgs {
            output: Some(key_path.clone()),
        });
        assert_ne!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::SUCCESS),
            "must refuse to overwrite an existing key file"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── pure helpers ──────────────────────────────────────────

    #[test]
    fn envelope_to_genome_wraps_bytes_under_envelope_v1_name() {
        let bytes = br#"{"hosts":["api.example.com"]}"#;
        let bundle = envelope_to_genome(bytes, "test-bundle");
        // Exactly one genome (the v1 atomic-envelope shape).
        assert_eq!(bundle.genomes.len(), 1);
        let g = &bundle.genomes[0];
        // The genome name is `<bundle_name>-envelope-v1`.
        assert!(g.name.contains("envelope-v1"));
        assert!(g.name.contains("test-bundle"));
        // The payload is the envelope bytes as UTF-8.
        assert!(g.payload.contains("api.example.com"));
    }

    #[test]
    fn envelope_to_genome_handles_empty_envelope() {
        let bundle = envelope_to_genome(b"", "empty");
        assert_eq!(bundle.genomes.len(), 1);
        assert!(bundle.genomes[0].payload.is_empty());
    }

    #[test]
    fn envelope_to_genome_preserves_non_utf8_bytes_via_lossy_decode() {
        // Non-UTF8 input survives via lossy decode (replacement chars
        // appear). Anti-rig: we don't panic on hostile-shaped envelopes.
        let bytes: Vec<u8> = vec![0xFF, b'a', 0xFE, b'b'];
        let bundle = envelope_to_genome(&bytes, "bin");
        assert_eq!(bundle.genomes.len(), 1);
        // Replacement chars present.
        assert!(bundle.genomes[0].payload.contains('\u{FFFD}'));
        assert!(bundle.genomes[0].payload.contains('a'));
        assert!(bundle.genomes[0].payload.contains('b'));
    }

    #[test]
    fn write_secret_hex_writes_trailing_newline() {
        // Operators inspect the file directly with `cat`; a trailing
        // newline is the right cat-friendly shape and the file-format
        // contract.
        let dir = fresh_dir("hex-trail");
        let path = dir.join("secret.hex");
        write_secret_hex_atomic(&path, "deadbeef").unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.ends_with('\n'), "must end with newline: {raw:?}");
        assert!(raw.starts_with("deadbeef"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_secret_hex_creates_parent_directories() {
        // If the parent dir doesn't exist, create it. Operators pass
        // `~/.wafrift/signing.hex` on a fresh box.
        let dir = fresh_dir("hex-mkdir");
        let nested = dir.join("a").join("b").join("c");
        let path = nested.join("secret.hex");
        write_secret_hex_atomic(&path, "feedface").unwrap();
        assert!(path.exists());
        assert!(nested.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_signing_key_round_trips_through_disk() {
        let dir = fresh_dir("read-key");
        let path = dir.join("signing.hex");
        let key = SigningKey::generate();
        let hex = key.secret_hex();
        write_secret_hex_atomic(&path, hex).unwrap();
        let loaded = read_signing_key(&path).expect("must load");
        assert_eq!(loaded.secret_hex(), hex);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn write_secret_hex_atomic_is_owner_only_0600() {
        // §15 least-privilege regression: the ed25519 signing key must land
        // on disk 0600, never world/group readable, even transiently. A
        // leaked signing key lets an attacker forge gene-bank envelopes the
        // operator trusts. The atomic `.mode(0o600)` create eliminates the
        // write-then-chmod window; pin the resulting mode here.
        use std::os::unix::fs::PermissionsExt as _;
        let dir = fresh_dir("key-perms");
        let path = dir.join("signing.hex");
        let key = SigningKey::generate();
        write_secret_hex_atomic(&path, key.secret_hex()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "signing key must be 0600, got {:o}",
            mode & 0o777
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_signing_key_strips_trailing_whitespace() {
        // The file ends with `\n` from write_secret_hex; read_signing_key
        // must `.trim()` before calling SigningKey::from_secret_hex,
        // otherwise the from_secret_hex parser rejects the input.
        let dir = fresh_dir("trim");
        let path = dir.join("signing.hex");
        let key = SigningKey::generate();
        let hex = key.secret_hex();
        std::fs::write(&path, format!("  {hex}\n\n  ")).unwrap();
        let loaded = read_signing_key(&path).expect("trimming must succeed");
        assert_eq!(loaded.secret_hex(), hex);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_signing_key_rejects_malformed_hex() {
        let dir = fresh_dir("bad-hex");
        let path = dir.join("signing.hex");
        std::fs::write(&path, "not-real-hex").unwrap();
        let err = read_signing_key(&path).expect_err("malformed must error");
        // Error should describe what went wrong, not panic.
        assert!(!err.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_signing_key_handles_missing_file() {
        let path = std::env::temp_dir().join(format!(
            "wafrift-bank-registry-missing-{}-{}",
            std::process::id(),
            line!()
        ));
        // path intentionally not created.
        let err = read_signing_key(&path).expect_err("missing must error");
        assert!(err.contains("read") || err.to_lowercase().contains("system cannot"));
    }
