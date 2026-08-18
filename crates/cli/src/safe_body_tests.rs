    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Spin up a small TCP server that returns the given body
    /// bytes verbatim under HTTP/1.1, with the given headers
    /// already framed. Returns the URL.
    async fn spawn_server(framed_response: Vec<u8>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let resp = framed_response.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    let _ = sock.write_all(&resp).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        format!("http://{addr}/")
    }

    fn ok_response(body: &[u8]) -> Vec<u8> {
        let mut v = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        v.extend_from_slice(body);
        v
    }

    #[tokio::test]
    async fn read_bounded_returns_body_under_cap() {
        let body = b"hello world";
        let url = spawn_server(ok_response(body)).await;
        let resp = reqwest::get(&url).await.unwrap();
        let got = read_bounded(resp, 1024).await.expect("under cap");
        assert_eq!(&got[..], body);
    }

    #[tokio::test]
    async fn read_bounded_errors_when_body_exceeds_cap() {
        let body = vec![b'A'; 4096];
        let url = spawn_server(ok_response(&body)).await;
        let resp = reqwest::get(&url).await.unwrap();
        let err = read_bounded(resp, 100).await.expect_err("must overrun");
        match err {
            ReadError::Overrun {
                cap_bytes,
                observed_bytes,
            } => {
                assert_eq!(cap_bytes, 100);
                assert!(observed_bytes > 100);
            }
            other => panic!("expected Overrun, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn read_bounded_text_handles_under_cap_utf8() {
        let body = b"normal text body";
        let url = spawn_server(ok_response(body)).await;
        let resp = reqwest::get(&url).await.unwrap();
        let got = read_bounded_text(resp, 1024).await.unwrap();
        assert_eq!(got, "normal text body");
    }

    #[tokio::test]
    async fn read_bounded_text_handles_lossy_utf8() {
        // Body has invalid utf8 bytes, the function must NOT
        // panic and must return replacement-char-substituted
        // string (matches reqwest::Response::text behaviour).
        let body = vec![0xFF, b'a', 0xFE, b'b'];
        let url = spawn_server(ok_response(&body)).await;
        let resp = reqwest::get(&url).await.unwrap();
        let got = read_bounded_text(resp, 1024).await.unwrap();
        assert!(got.contains('\u{FFFD}'));
        assert!(got.contains('a'));
        assert!(got.contains('b'));
    }

    #[tokio::test]
    async fn read_bounded_aborts_mid_stream_when_cap_reached() {
        // Body is intentionally larger than the cap. The early-
        // abort path must not consume the remainder, the network
        // read should stop as soon as the cap is hit. Functionally
        // this is observable by the elapsed time staying short:
        // a 1 GB body would otherwise take >> 1s.
        let body = vec![b'X'; 1_000_000];
        let url = spawn_server(ok_response(&body)).await;
        let resp = reqwest::get(&url).await.unwrap();
        let start = std::time::Instant::now();
        let err = read_bounded(resp, 32).await.expect_err("must overrun");
        let elapsed = start.elapsed();
        assert!(matches!(err, ReadError::Overrun { .. }));
        assert!(
            elapsed < Duration::from_secs(5),
            "early-abort should NOT read the whole body, took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn read_bounded_handles_zero_cap_correctly() {
        // Cap of 0, any non-empty response must overrun. Empty
        // body (Content-Length: 0) is the only success case.
        let url = spawn_server(ok_response(b"")).await;
        let resp = reqwest::get(&url).await.unwrap();
        let got = read_bounded(resp, 0).await.unwrap();
        assert!(got.is_empty());

        let url2 = spawn_server(ok_response(b"x")).await;
        let resp2 = reqwest::get(&url2).await.unwrap();
        let err = read_bounded(resp2, 0).await.expect_err("must overrun");
        assert!(matches!(err, ReadError::Overrun { .. }));
    }

    #[test]
    fn default_max_is_smaller_than_headroom_max() {
        // Anti-rig: a refactor that swapped the two constants
        // would silently lift the cap on every hostile target.
        assert!(DEFAULT_MAX_RESPONSE_BYTES < HEADROOM_MAX_RESPONSE_BYTES);
    }

    #[test]
    fn default_max_is_at_least_one_megabyte() {
        // A cap smaller than 1 MiB would false-positive on
        // legitimate large block pages (some CRS PL4 setups
        // return a several-hundred-KB block page with a long
        // rule trace). 8 MiB is well above that. Lock the
        // floor in so a future "tighten to 64 KiB" refactor
        // doesn't break real-world targets silently.
        assert!(DEFAULT_MAX_RESPONSE_BYTES >= 1024 * 1024);
    }

    #[test]
    fn read_error_overrun_display_includes_both_numbers() {
        // Operator must see WHAT cap was exceeded BY HOW MUCH
        //: abbreviated errors are debugging hostile.
        let e = ReadError::Overrun {
            cap_bytes: 8388608,
            observed_bytes: 12345678,
        };
        let s = format!("{e}");
        assert!(s.contains("8388608"));
        assert!(s.contains("12345678"));
        assert!(s.contains("decompression-bomb"));
    }

    #[test]
    fn read_error_transport_display_includes_underlying_message() {
        let e = ReadError::Transport("connection reset".into());
        let s = format!("{e}");
        assert!(s.contains("connection reset"));
    }

    #[test]
    fn read_bounded_text_file_returns_contents_under_cap() {
        let tmp = std::env::temp_dir().join(format!("wafrift-sb-{}.txt", std::process::id()));
        std::fs::write(&tmp, "hello world").unwrap();
        let got = read_bounded_text_file(&tmp, 1024).unwrap();
        assert_eq!(got, "hello world");
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn read_bounded_text_file_overruns_when_too_big() {
        let tmp = std::env::temp_dir().join(format!("wafrift-sb-big-{}.txt", std::process::id()));
        std::fs::write(&tmp, vec![b'X'; 4096]).unwrap();
        let err = read_bounded_text_file(&tmp, 100).expect_err("must overrun");
        match err {
            ReadError::Overrun {
                cap_bytes,
                observed_bytes,
            } => {
                assert_eq!(cap_bytes, 100);
                assert!(observed_bytes > 100);
            }
            other => panic!("expected Overrun, got {other:?}"),
        }
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn read_bounded_text_file_handles_missing_file() {
        // Path that doesn't exist: must Transport-error, not panic.
        let err = read_bounded_text_file(
            std::path::Path::new("/nonexistent/wafrift/path/does/not/exist"),
            1024,
        )
        .expect_err("must fail");
        assert!(matches!(err, ReadError::Transport(_)));
        let msg = format!("{err}");
        assert!(
            msg.contains("open") || msg.contains("does not exist") || msg.contains("system cannot")
        );
    }

    #[test]
    fn read_bounded_text_file_handles_lossy_utf8() {
        // Mixed valid + invalid UTF-8 bytes, must not panic, must
        // emit replacement chars for the bad sequences.
        let tmp = std::env::temp_dir().join(format!("wafrift-sb-utf8-{}.bin", std::process::id()));
        std::fs::write(&tmp, [0x68, 0x69, 0xFF, 0xFE, 0x21]).unwrap();
        let got = read_bounded_text_file(&tmp, 1024).unwrap();
        assert!(got.contains("hi"));
        assert!(got.contains('\u{FFFD}'));
        assert!(got.contains('!'));
        let _ = std::fs::remove_file(&tmp);
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn read_bounded_defends_against_real_gzip_bomb() {
        // `#[serial]` because this test spawns a real HTTP server +
        // a reqwest client.  Under parallel cargo-test the localhost
        // socket churn produces spurious failures on Windows.
        // PROOF that the fix works: build a tiny gzip payload that
        // expands to ~100 MiB at decode time, serve it with
        // Content-Encoding: gzip, and confirm `read_bounded`
        // aborts at the cap. Reqwest's gzip decoder sits BEHIND
        // the bytes_stream chain, so this exercises the full
        // defence path.
        use std::io::Write as _;
        // Build the bomb: 100 MiB of zeros, gzip-compressed.
        // 100 MiB of zeros gzip to ~100 KiB (super compressible);
        // the cap of 8 MiB is well below 100 MiB, so the stream
        // MUST abort.
        let bomb_uncompressed = vec![0u8; 100 * 1024 * 1024];
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        enc.write_all(&bomb_uncompressed).unwrap();
        let bomb_gzip = enc.finish().unwrap();
        assert!(
            bomb_gzip.len() < 1_000_000,
            "the bomb's whole point: compressed << uncompressed (got {} bytes)",
            bomb_gzip.len()
        );

        // Serve it with Content-Encoding: gzip + Content-Length.
        let mut framed = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Encoding: gzip\r\n\
             Content-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
            bomb_gzip.len()
        )
        .into_bytes();
        framed.extend_from_slice(&bomb_gzip);

        let url = spawn_server(framed).await;
        let resp = reqwest::Client::builder()
            .gzip(true)
            .build()
            .unwrap()
            .get(&url)
            .send()
            .await
            .unwrap();
        let start = std::time::Instant::now();
        let err = read_bounded(resp, DEFAULT_MAX_RESPONSE_BYTES)
            .await
            .expect_err("MUST abort on bomb");
        let elapsed = start.elapsed();
        match err {
            ReadError::Overrun {
                cap_bytes,
                observed_bytes,
            } => {
                assert_eq!(cap_bytes, DEFAULT_MAX_RESPONSE_BYTES);
                assert!(
                    observed_bytes > DEFAULT_MAX_RESPONSE_BYTES,
                    "must have seen MORE than the cap before bailing"
                );
            }
            other => panic!("expected Overrun, got {other:?}"),
        }
        assert!(
            elapsed < Duration::from_secs(60),
            "the abort must be fast (under 1 min even under loaded CI). \
             bomb fully expanded would take much longer; \
             actual elapsed={elapsed:?}"
        );
    }

    #[test]
    fn max_operator_input_bytes_is_at_least_64_kib_but_under_16_mib() {
        // Floor: a refactor to 1 KiB would break legitimate big-curl
        // pastes (Burp pastes with many cookies + headers cross 16 KiB).
        // Ceiling: anything bigger than 16 MiB defeats the DoS defence
        // on a typical laptop.
        assert!(MAX_OPERATOR_INPUT_BYTES >= 64 * 1024);
        assert!(MAX_OPERATOR_INPUT_BYTES <= 16 * 1024 * 1024);
    }

    // ── boundary conditions on read_bounded ───────────────────
    //
    // Off-by-one is exactly the kind of bug a P0 researcher would
    // hunt for. Each of the next three tests targets one bound
    // (cap == len, cap == len-1, cap == len+1) explicitly.

    #[tokio::test]
    async fn read_bounded_succeeds_when_cap_equals_exact_body_length() {
        let body = b"1234567890"; // 10 bytes
        let url = spawn_server(ok_response(body)).await;
        let resp = reqwest::get(&url).await.unwrap();
        let got = read_bounded(resp, 10).await.expect("cap == len must pass");
        assert_eq!(&got[..], body);
    }

    #[tokio::test]
    async fn read_bounded_overruns_when_cap_is_one_byte_under_body_length() {
        let body = b"1234567890"; // 10 bytes
        let url = spawn_server(ok_response(body)).await;
        let resp = reqwest::get(&url).await.unwrap();
        let err = read_bounded(resp, 9)
            .await
            .expect_err("cap = len-1 must overrun");
        match err {
            ReadError::Overrun {
                cap_bytes,
                observed_bytes,
            } => {
                assert_eq!(cap_bytes, 9);
                assert!(observed_bytes >= 10);
            }
            other => panic!("expected Overrun, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn read_bounded_succeeds_when_cap_is_one_byte_over_body_length() {
        let body = b"1234567890"; // 10 bytes
        let url = spawn_server(ok_response(body)).await;
        let resp = reqwest::get(&url).await.unwrap();
        let got = read_bounded(resp, 11).await.expect("cap = len+1 must pass");
        assert_eq!(&got[..], body);
    }

    #[tokio::test]
    async fn read_bounded_returns_empty_vec_for_empty_body_with_positive_cap() {
        let url = spawn_server(ok_response(b"")).await;
        let resp = reqwest::get(&url).await.unwrap();
        let got = read_bounded(resp, 1)
            .await
            .expect("empty body always under cap");
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn read_bounded_returns_empty_vec_for_empty_body_with_zero_cap() {
        // The previous case + cap = 0. Empty body still must pass
        // because the cap check is acc.len + chunk.len > max, at
        // empty body there are no chunks to compare.
        let url = spawn_server(ok_response(b"")).await;
        let resp = reqwest::get(&url).await.unwrap();
        let got = read_bounded(resp, 0)
            .await
            .expect("empty body + zero cap is valid");
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn read_bounded_single_byte_body_with_one_byte_cap_succeeds() {
        let url = spawn_server(ok_response(b"x")).await;
        let resp = reqwest::get(&url).await.unwrap();
        let got = read_bounded(resp, 1)
            .await
            .expect("one-byte cap covers one-byte body");
        assert_eq!(&got[..], b"x");
    }

    // ── read_bounded_text boundary cases ──────────────────────

    #[tokio::test]
    async fn read_bounded_text_propagates_overrun_error() {
        // The text wrapper must NOT swallow Overrun into the
        // string path (overruns are control-flow critical).
        let body = vec![b'X'; 4096];
        let url = spawn_server(ok_response(&body)).await;
        let resp = reqwest::get(&url).await.unwrap();
        let err = read_bounded_text(resp, 16).await.expect_err("must overrun");
        assert!(matches!(err, ReadError::Overrun { .. }));
    }

    #[tokio::test]
    async fn read_bounded_text_empty_body_returns_empty_string() {
        let url = spawn_server(ok_response(b"")).await;
        let resp = reqwest::get(&url).await.unwrap();
        let got = read_bounded_text(resp, 1024).await.unwrap();
        assert!(got.is_empty());
    }

    // ── read_bounded_text_file boundary cases ─────────────────

    #[test]
    fn read_bounded_text_file_succeeds_at_exact_cap() {
        let tmp = std::env::temp_dir().join(format!(
            "wafrift-sb-exact-{}-{}.txt",
            std::process::id(),
            line!()
        ));
        std::fs::write(&tmp, vec![b'A'; 100]).unwrap();
        let got = read_bounded_text_file(&tmp, 100).expect("cap == file size must pass");
        assert_eq!(got.len(), 100);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn read_bounded_text_file_overruns_one_byte_above_cap() {
        let tmp = std::env::temp_dir().join(format!(
            "wafrift-sb-above-{}-{}.txt",
            std::process::id(),
            line!()
        ));
        std::fs::write(&tmp, vec![b'A'; 101]).unwrap();
        let err = read_bounded_text_file(&tmp, 100).expect_err("101 over cap 100");
        assert!(matches!(err, ReadError::Overrun { .. }));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn read_bounded_text_file_empty_file_returns_empty_string_with_zero_cap() {
        // The path that the previous test catches a missing file
        // on; here we verify the cap-check still respects an
        // existing empty file.
        let tmp = std::env::temp_dir().join(format!(
            "wafrift-sb-empty-{}-{}.txt",
            std::process::id(),
            line!()
        ));
        std::fs::write(&tmp, b"").unwrap();
        let got = read_bounded_text_file(&tmp, 0).expect("empty file always passes");
        assert!(got.is_empty());
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn read_bounded_text_file_one_byte_file_with_zero_cap_overruns() {
        let tmp = std::env::temp_dir().join(format!(
            "wafrift-sb-zero-{}-{}.txt",
            std::process::id(),
            line!()
        ));
        std::fs::write(&tmp, b"x").unwrap();
        let err = read_bounded_text_file(&tmp, 0).expect_err("1 byte > 0 cap");
        match err {
            ReadError::Overrun {
                cap_bytes,
                observed_bytes,
            } => {
                assert_eq!(cap_bytes, 0);
                assert!(observed_bytes >= 1);
            }
            other => panic!("expected Overrun, got {other:?}"),
        }
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn read_bounded_text_file_binary_with_nul_bytes_lossy_decoded() {
        // NUL is valid UTF-8, must NOT be replaced. Verifies the
        // lossy decode preserves the NUL between two valid chars.
        let tmp = std::env::temp_dir().join(format!(
            "wafrift-sb-nul-{}-{}.bin",
            std::process::id(),
            line!()
        ));
        std::fs::write(&tmp, [b'a', 0, b'b']).unwrap();
        let got = read_bounded_text_file(&tmp, 1024).unwrap();
        assert_eq!(got, "a\0b");
        let _ = std::fs::remove_file(&tmp);
    }

    // ── ReadError invariants ──────────────────────────────────

    #[test]
    fn read_error_debug_includes_variant_name() {
        let e = ReadError::Overrun {
            cap_bytes: 100,
            observed_bytes: 200,
        };
        let d = format!("{e:?}");
        assert!(d.contains("Overrun"));

        let e2 = ReadError::Transport("X".into());
        let d2 = format!("{e2:?}");
        assert!(d2.contains("Transport"));
    }

    #[test]
    fn read_error_implements_std_error_trait() {
        // Anti-rig: a refactor that removed `impl Error for ReadError`
        // would silently drop the `?`-propagation behaviour in
        // callers that use `Box<dyn Error>`.
        fn assert_impl<E: std::error::Error + 'static>(_: &E) {}
        let e = ReadError::Overrun {
            cap_bytes: 0,
            observed_bytes: 1,
        };
        assert_impl(&e);
    }

    #[test]
    fn read_error_overrun_display_mentions_bomb_defence_in_message() {
        // Operator should immediately understand WHY the read
        // aborted, phrase the message in attack terms, not bland
        // "limit reached".
        let e = ReadError::Overrun {
            cap_bytes: 100,
            observed_bytes: 200,
        };
        let s = format!("{e}");
        assert!(
            s.to_lowercase().contains("decompression-bomb"),
            "must blame the bomb explicitly: {s}"
        );
    }

    // ── Bomb defence on alternate compression types ───────────

    #[tokio::test]
    async fn read_bounded_defends_against_real_brotli_bomb() {
        // Mirror of the gzip-bomb test for brotli. Reqwest's brotli
        // decoder sits behind bytes_stream too; the cap must apply
        // there as well or the defence has a hole.
        let bomb_uncompressed = vec![0u8; 16 * 1024 * 1024];
        let compressed = wafrift_encoding::compression::compress(
            &bomb_uncompressed,
            wafrift_encoding::compression::Algorithm::Brotli,
        )
        .unwrap();
        assert!(
            compressed.body.len() < 256 * 1024,
            "brotli bomb compresses >> 64x: got {} bytes",
            compressed.body.len()
        );
        let mut framed = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Encoding: br\r\n\
             Content-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
            compressed.body.len()
        )
        .into_bytes();
        framed.extend_from_slice(&compressed.body);
        let url = spawn_server(framed).await;
        let resp = reqwest::Client::builder()
            .brotli(true)
            .build()
            .unwrap()
            .get(&url)
            .send()
            .await
            .unwrap();
        let err = read_bounded(resp, DEFAULT_MAX_RESPONSE_BYTES)
            .await
            .expect_err("brotli bomb must abort at cap");
        assert!(matches!(err, ReadError::Overrun { .. }));
    }

    // ── Multi-chunk semantics ─────────────────────────────────

    #[tokio::test]
    async fn read_bounded_handles_body_arriving_in_many_small_chunks() {
        // Some servers split a small response across multiple TCP
        // writes; the cap check must NOT be confused by chunk
        // boundaries (e.g. mistakenly comparing chunk size alone
        // against the cap).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut read = [0u8; 4096];
            let _ = sock.read(&mut read).await;
            // Header
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\n")
                .await;
            // Body in 1-byte chunks
            for b in b"sixteen byte body" {
                let _ = sock.write_all(&[*b]).await;
                let _ = sock.flush().await;
            }
            let _ = sock.shutdown().await;
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        let url = format!("http://{addr}/");
        let resp = reqwest::get(&url).await.unwrap();
        let got = read_bounded(resp, 32).await.expect("32 > 16");
        // Content-Length=16 but body sent is "sixteen byte body"
        // which is 17 bytes, reqwest reads ONLY the declared
        // content length, so the result is exactly 16 bytes.
        assert_eq!(got.len(), 16);
        assert!(got.starts_with(b"sixteen byte bod"));
    }

    #[tokio::test]
    async fn read_bounded_cap_check_fires_within_first_chunk_when_chunk_above_cap() {
        // 1 MB body arrives in one chunk. Cap of 1024 must abort
        // on the first chunk read, chunk.len() pushes the running
        // total over the cap in a single comparison.
        let body = vec![b'X'; 1_000_000];
        let url = spawn_server(ok_response(&body)).await;
        let resp = reqwest::get(&url).await.unwrap();
        let err = read_bounded(resp, 1024)
            .await
            .expect_err("first-chunk overrun");
        assert!(matches!(err, ReadError::Overrun { .. }));
    }

mod round19_bounded_input_audit {
    //! Round 19: cross-file audit that every remaining `cli/src/*` site
    //! reading operator-controlled paths now goes through the bounded
    //! reader. Each test embeds the source via include_str! and asserts
    //! the bounded call is present + the banned unbounded call is gone.
    //!
    //! Banned literals are built with concat!() so the test source
    //! itself does not contain the needle, include_str! self-reference
    //! would otherwise turn the negative assertion into a tautology.

    // hunt_cmd ────────────────────────────────────────────────────────

    #[test]
    fn hunt_bench_output_read_is_bounded() {
        let src = include_str!("hunt_cmd.rs");
        let needle = "safe_body::read_bounded_text_file(&tmp, HUNT_BENCH_OUTPUT_MAX_BYTES)";
        assert!(
            src.contains(needle),
            "hunt_cmd.rs bench-output read must be bounded"
        );
        // Production pattern is `let raw = match … {`; tests use
        // `.unwrap()`. Scope the banned needle so we don't false-trip
        // on test fixtures that legitimately read tmp paths raw.
        let banned = concat!("let raw = match std::fs::", "read_to_", "string(&tmp) {");
        assert!(
            !src.contains(banned),
            "unbounded hunt bench-output read regression"
        );
    }

    #[test]
    fn hunt_campaign_state_read_is_bounded() {
        let src = include_str!("hunt_cmd.rs");
        let needle = "safe_body::read_bounded_text_file(path, HUNT_CAMPAIGN_STATE_MAX_BYTES)";
        assert!(
            src.contains(needle),
            "hunt_cmd.rs campaign-state read must be bounded"
        );
        let banned = concat!("std::fs::", "read_to_", "string(path)");
        assert!(
            !src.contains(banned),
            "unbounded hunt campaign-state read regression"
        );
    }

    // seed ────────────────────────────────────────────────────────────

    #[test]
    fn seed_gene_bank_read_is_bounded() {
        let src = include_str!("seed.rs");
        let needle = concat!(
            "safe_body::read_bounded_text_file(\n",
            "        &path,\n",
            "        crate::safe_body::GENE_BANK_FILE_MAX_BYTES,\n",
            "    )"
        );
        assert!(
            src.contains(needle),
            "seed.rs gene-bank read must be bounded"
        );
        // The seed.rs file's test block intentionally reads tmp files via
        // raw std::fs::read_to_string for assertion convenience, match
        // only the production-path pattern of `fs::read_to_string(&path)`.
        let banned = concat!(
            "\n    let mut bank = match fs::",
            "read_to_",
            "string(&path)"
        );
        assert!(
            !src.contains(banned),
            "unbounded seed gene-bank read regression"
        );
    }

    // replay ──────────────────────────────────────────────────────────

    #[test]
    fn replay_gene_bank_read_is_bounded() {
        let src = include_str!("replay.rs");
        // Whitespace-robust: prove the gene-bank read goes through the bounded
        // reader WITH the gene-bank cap, without pinning rustfmt's exact
        // argument wrapping (single-line vs multi-line are equivalent and both
        // legitimate). The two banned-pattern checks below still reject any
        // unbounded regression.
        assert!(
            src.contains("read_bounded_text_file") && src.contains("GENE_BANK_FILE_MAX_BYTES"),
            "replay.rs proxy gene-bank read must be bounded via read_bounded_text_file(GENE_BANK_FILE_MAX_BYTES)"
        );
        let banned = concat!("\n    let raw = fs::", "read_to_", "string(&path)");
        assert!(
            !src.contains(banned),
            "unbounded replay gene-bank read regression"
        );
    }

    // evade stdin ─────────────────────────────────────────────────────

    #[test]
    fn evade_stdin_payload_read_is_bounded() {
        let src = include_str!("evade_cmd.rs");
        let needle = "safe_body::read_bounded_stdin_bytes(EVADE_STDIN_PAYLOAD_MAX_BYTES)";
        assert!(
            src.contains(needle),
            "evade_cmd.rs --stdin must use bounded reader"
        );
        let banned = concat!("io::stdin()\n", "            .", "read_to_end(&mut buf)");
        assert!(
            !src.contains(banned),
            "unbounded evade --stdin read regression"
        );
    }

    // stdin-bytes primitive overrun behaviour ─────────────────────────
    //
    // We can't easily drive real stdin from a unit test, but we can
    // assert the byte-counting path of read_bounded_stdin_bytes against
    // an in-process source by reusing the same accounting logic the
    // file reader uses. Sanity-check the parallel function lives at the
    // same depth as read_bounded_text_stdin.

    #[test]
    fn stdin_bytes_primitive_exists_and_signature_matches() {
        let src = include_str!("safe_body.rs");
        let needle =
            "pub(crate) fn read_bounded_stdin_bytes(max_bytes: usize) -> Result<Vec<u8>, ReadError>";
        assert!(
            src.contains(needle),
            "read_bounded_stdin_bytes signature changed, evade_cmd.rs depends on it"
        );
    }

    // Shared gene-bank cap sanity ─────────────────────────────────────

    #[test]
    fn gene_bank_cap_is_sane() {
        assert!(
            super::GENE_BANK_FILE_MAX_BYTES >= 16 * 1024 * 1024,
            "GENE_BANK_FILE_MAX_BYTES tightened below 16 MiB, could reject mature banks"
        );
    }

    // Round 25: OOM/bomb fix anti-regression for response body reads.
    //
    // Each test pins that the fixed file now uses read_bounded (not
    // the unbounded .bytes().await) for responses from operator-
    // controlled targets. The banned literal is built with concat!()
    // so the test source itself doesn't contain the needle.

    #[test]
    fn detect_phase_baseline_body_read_is_bounded() {
        let src = include_str!("scan/detect_phase.rs");
        let needle = "safe_body::read_bounded(";
        assert!(
            src.contains(needle),
            "detect_phase.rs baseline body read must be bounded"
        );
        // The banned literal: the old single-call unbounded read.
        let banned = concat!(
            "baseline_response.",
            "bytes().",
            "await.",
            "unwrap_or_default().",
            "to_vec()"
        );
        assert!(
            !src.contains(banned),
            "unbounded detect_phase baseline body read regression"
        );
    }

    #[test]
    fn graphql_phase_probe_body_read_is_bounded() {
        let src = include_str!("scan/graphql_phase.rs");
        let needle = "safe_body::read_bounded_text(response, GRAPHQL_PROBE_BODY_CAP)";
        assert!(
            src.contains(needle),
            "graphql_phase.rs probe body read must be bounded"
        );
        let banned = concat!("response.", "text().", "await");
        assert!(
            !src.contains(banned),
            "unbounded graphql_phase probe body read regression"
        );
    }

    #[test]
    fn raw_runner_fire_one_body_read_is_bounded() {
        let src = include_str!("scan/raw_runner.rs");
        let needle = "safe_body::read_bounded(resp, crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES)";
        assert!(
            src.contains(needle),
            "raw_runner.rs fire_one body read must be bounded"
        );
    }

    #[test]
    fn header_diff_fetch_body_read_is_bounded() {
        let src = include_str!("diff/header_diff_cmd.rs");
        let needle = "safe_body::read_bounded(resp, crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES)";
        assert!(
            src.contains(needle),
            "header_diff_cmd.rs body read must be bounded"
        );
    }

    #[test]
    fn body_diff_fetch_body_read_is_bounded() {
        let src = include_str!("diff/body_diff_cmd.rs");
        let needle = "safe_body::read_bounded(resp, crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES)";
        assert!(
            src.contains(needle),
            "body_diff_cmd.rs body read must be bounded"
        );
    }

    #[test]
    fn cache_diff_fetch_body_read_is_bounded() {
        let src = include_str!("diff/cache_diff_cmd.rs");
        let needle = "safe_body::read_bounded(resp, crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES)";
        assert!(
            src.contains(needle),
            "cache_diff_cmd.rs body read must be bounded"
        );
    }

    #[test]
    fn cors_diff_drain_body_read_is_bounded() {
        let src = include_str!("diff/cors_diff_cmd.rs");
        let needle = "safe_body::read_bounded(resp, crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES)";
        assert!(
            src.contains(needle),
            "cors_diff_cmd.rs drain must be bounded"
        );
        // The old unbounded drain.
        let banned = concat!("let _ = resp.", "bytes().", "await");
        assert!(
            !src.contains(banned),
            "unbounded cors_diff drain regression"
        );
    }

    #[test]
    fn gql_diff_fetch_body_read_is_bounded() {
        let src = include_str!("diff/gql_diff_cmd.rs");
        let needle = "safe_body::read_bounded(resp, crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES)";
        assert!(
            src.contains(needle),
            "gql_diff_cmd.rs body read must be bounded"
        );
    }

    #[test]
    fn jwt_diff_fetch_body_read_is_bounded() {
        let src = include_str!("diff/jwt_diff_cmd.rs");
        let needle = "safe_body::read_bounded(resp, crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES)";
        assert!(
            src.contains(needle),
            "jwt_diff_cmd.rs body read must be bounded"
        );
    }

    #[test]
    fn method_diff_fetch_body_read_is_bounded() {
        let src = include_str!("diff/method_diff_cmd.rs");
        let needle = "safe_body::read_bounded(resp, crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES)";
        assert!(
            src.contains(needle),
            "method_diff_cmd.rs body read must be bounded"
        );
    }

    #[test]
    fn distill_cmd_body_read_is_bounded() {
        let src = include_str!("distill_cmd.rs");
        let needle = "safe_body::read_bounded(resp, crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES)";
        assert!(
            src.contains(needle),
            "distill_cmd.rs body read must be bounded"
        );
    }

    #[test]
    fn parser_diff_common_body_read_is_bounded() {
        let src = include_str!("diff/parser_diff_common.rs");
        let needle = "safe_body::read_bounded(";
        assert!(
            src.contains(needle),
            "parser_diff_common.rs body read must be bounded"
        );
    }

    #[test]
    fn harvest_cmd_h1_api_error_body_read_is_bounded() {
        // The H1 submission path moved from hunt_cmd to harvest_cmd when
        // auto-submit was removed (filing is now the guarded `wafrift
        // submit`). The bounded-read invariant moved with it.
        let src = include_str!("harvest_cmd.rs");
        let needle = "safe_body::read_bounded_text(resp, 64 * 1024)";
        assert!(
            src.contains(needle),
            "harvest_cmd.rs H1 API error body read must be bounded"
        );
    }

    // Round 26: operator-supplied FILE reads (TOCTOU + OOM axis).
    //
    // Each test pins that the fixed file now uses read_bounded_text_file
    // (not the unbounded std::fs::read_to_string) for paths derived from
    // operator flags.

    #[test]
    fn smuggle_fire_priority_corpus_read_is_bounded() {
        let src = include_str!("smuggle/smuggle_fire_cmd.rs");
        let needle = "safe_body::read_bounded_text_file(path, CORPUS_MAX_BYTES)";
        assert!(
            src.contains(needle),
            "smuggle_fire_cmd.rs load_priority_techniques must use bounded file read"
        );
        // Old unbounded pattern must be absent.
        let banned = concat!("std::fs::", "read_to_string(path)");
        assert!(
            !src.contains(banned),
            "smuggle_fire_cmd.rs must not use unbounded fs::read_to_string. OOM regression"
        );
    }

    #[test]
    fn exploit_seed_payloads_read_is_bounded() {
        // `wafrift exploit --seed-payloads <path>` is operator-supplied input;
        // an unbounded read is an OOM (/dev/zero) + TOCTOU (symlink swap) hole.
        let src = include_str!("exploit_cmd.rs");
        let needle = "safe_body::read_bounded_text_file(path, EXPLOIT_SEED_PAYLOADS_MAX_BYTES)";
        assert!(
            src.contains(needle),
            "exploit_cmd.rs load_seed_payloads must use the bounded file reader"
        );
        // The banned unbounded pattern must be gone from the production path.
        let banned = concat!("std::fs::", "read_to_", "string(path)");
        assert!(
            !src.contains(banned),
            "exploit_cmd.rs must not use unbounded fs::read_to_string. OOM/TOCTOU regression"
        );
    }

    #[test]
    fn bank_genome_dir_read_is_bounded() {
        let src = include_str!("bank.rs");
        let needle = "safe_body::read_bounded_text_file(";
        assert!(
            src.contains(needle),
            "bank.rs read_genome_dir must use bounded file read"
        );
    }

    #[test]
    fn bench_waf_history_file_read_is_bounded() {
        let src = include_str!("bench_waf.rs");
        let needle = "safe_body::read_bounded_text_file(";
        assert!(
            src.contains(needle),
            "bench_waf.rs history-file reads must use bounded file read"
        );
        // Both --history-file and --history-merge must be fixed.
        let count = src.matches(needle).count();
        assert!(
            count >= 2,
            "bench_waf.rs must have at least 2 bounded reads (--history-file and --history-merge), found {count}"
        );
    }
}
