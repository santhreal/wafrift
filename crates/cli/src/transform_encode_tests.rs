    use super::*;

    const P: &str = "<img src=x onerror=alert(1)>";

    /// Encode the sample payload through a named catalog transform, exercises
    /// the real public path (`AppTransform::encode`) the operator hits.
    fn enc(name: &str) -> String {
        by_name(name).expect("known transform").encode(P)
    }

    // ── round-trip: every encoder is the inverse of the app decoder ──────────

    #[test]
    fn b64_round_trips() {
        use base64::Engine;
        let e = enc("b64");
        let d = base64::engine::general_purpose::STANDARD
            .decode(&e)
            .unwrap();
        assert_eq!(String::from_utf8(d).unwrap(), P);
        // Carries no literal XSS token for the WAF to match.
        assert!(!e.contains('<') && !e.contains("onerror") && !e.contains("alert"));
    }

    #[test]
    fn b64url_round_trips_with_padding_restored() {
        use base64::Engine;
        let e = enc("b64url");
        assert!(!e.contains('+') && !e.contains('/') && !e.contains('='));
        // Restore padding the way the origin does, then decode.
        let mut s = e.replace('-', "+").replace('_', "/");
        while !s.len().is_multiple_of(4) {
            s.push('=');
        }
        let d = base64::engine::general_purpose::STANDARD
            .decode(&s)
            .unwrap();
        assert_eq!(String::from_utf8(d).unwrap(), P);
    }

    #[test]
    fn hex_round_trips() {
        let e = enc("hex");
        assert_eq!(String::from_utf8(hex::decode(&e).unwrap()).unwrap(), P);
        assert!(e.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn hex0x_has_prefix_and_round_trips() {
        let e = enc("hex0x");
        assert!(e.starts_with("0x"));
        let d = hex::decode(e.trim_start_matches("0x")).unwrap();
        assert_eq!(String::from_utf8(d).unwrap(), P);
    }

    #[test]
    fn rot13_is_its_own_inverse_and_hides_keywords() {
        let e = enc("rot13");
        // Decoding (== applying rot13 again) restores the payload.
        assert_eq!(encode_stages(&[Stage::Rot13], &e), P);
        // The signature keywords are gone from the encoded form.
        assert!(!e.contains("onerror") && !e.contains("alert") && !e.contains("img"));
        // Structure (the non-letters) is preserved (that's the point).
        assert!(e.contains('<') && e.contains('=') && e.contains('>'));
    }

    #[test]
    fn b32_matches_known_vector() {
        // RFC4648 test vectors (pins the hand-rolled stage primitive).
        assert_eq!(encode_stages(&[Stage::B32], "f"), "MY======");
        assert_eq!(encode_stages(&[Stage::B32], "fo"), "MZXQ====");
        assert_eq!(encode_stages(&[Stage::B32], "foo"), "MZXW6===");
        assert_eq!(encode_stages(&[Stage::B32], "foob"), "MZXW6YQ=");
        assert_eq!(encode_stages(&[Stage::B32], "fooba"), "MZXW6YTB");
        assert_eq!(encode_stages(&[Stage::B32], "foobar"), "MZXW6YTBOI======");
    }

    #[test]
    fn b32_payload_round_trips_via_origin_rule() {
        // Decode the way the origin does (uppercase, pad to /8) using a tiny
        // reference decoder, proving the encoder feeds the b32 sink.
        let e = enc("b32");
        assert_eq!(b32_decode(&e), P);
        assert!(!e.contains('<') && !e.contains("alert"));
    }

    // Reference RFC4648 decoder for the test only.
    fn b32_decode(s: &str) -> String {
        const A: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut bits = 0u64;
        let mut nbits = 0u32;
        let mut out = Vec::new();
        for c in s.bytes().filter(|&c| c != b'=') {
            let v = A.iter().position(|&a| a == c).expect("valid b32 char") as u64;
            bits = (bits << 5) | v;
            nbits += 5;
            if nbits >= 8 {
                nbits -= 8;
                out.push((bits >> nbits) as u8);
            }
        }
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn deflate_b64_round_trips_via_zlib() {
        // Inflate the way the origin does: base64-decode, then zlib-inflate.
        use base64::Engine;
        use flate2::read::ZlibDecoder;
        use std::io::Read;
        let e = enc("zb64");
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&e)
            .expect("valid base64");
        let mut z = ZlibDecoder::new(&raw[..]);
        let mut out = String::new();
        z.read_to_string(&mut out).expect("valid zlib stream");
        assert_eq!(out, P);
        // Opaque: no XSS literal survives compression+base64.
        assert!(!e.contains('<') && !e.contains("onerror") && !e.contains("alert"));
    }

    #[test]
    fn deflate_hex_round_trips_and_is_clean_alphabet() {
        // Inflate the way the origin does: hex-decode, then zlib-inflate.
        use flate2::read::ZlibDecoder;
        use std::io::Read;
        let e = enc("zhex");
        // The whole point: a PL4-clean alphabet, only [0-9a-f], no +/= for CRS
        // to flag.
        assert!(
            e.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        let raw = hex::decode(&e).expect("valid hex");
        let mut z = ZlibDecoder::new(&raw[..]);
        let mut out = String::new();
        z.read_to_string(&mut out).expect("valid zlib stream");
        assert_eq!(out, P);
        assert!(!e.contains('<') && !e.contains("alert"));
    }

    #[test]
    fn zb64_and_zhex_share_one_deflate_differing_only_in_alphabet() {
        // The dedup invariant: both compression transforms run the SAME deflate
        // primitive and differ ONLY in the terminal text stage. Decoding each
        // outer alphabet must yield byte-identical compressed streams, proof
        // there is one `deflate`, not two divergent hand-rolled copies.
        use base64::Engine;
        let from_b64 = base64::engine::general_purpose::STANDARD
            .decode(enc("zb64"))
            .expect("valid base64");
        let from_hex = hex::decode(enc("zhex")).expect("valid hex");
        assert_eq!(
            from_b64, from_hex,
            "zb64 and zhex must compress identically; only the alphabet differs"
        );
    }

    #[test]
    fn b58_matches_known_vector_and_round_trips() {
        // Canonical Bitcoin-base58 vector pins the hand-rolled stage primitive.
        assert_eq!(
            encode_stages(&[Stage::B58], "Hello World!"),
            "2NEpo7TZRRrLZSi2U"
        );
        // Round-trip through a reference decoder proves it feeds the b58 sink.
        assert_eq!(b58_decode(&enc("b58")), P);
        let e = enc("b58");
        assert!(!e.contains('<') && !e.contains("alert"));
    }

    // Reference base58 decoder for the test only (base-58 → base-256).
    fn b58_decode(s: &str) -> String {
        const A: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        let zeros = s.bytes().take_while(|&c| c == b'1').count();
        let mut bytes: Vec<u8> = Vec::new();
        for c in s.bytes() {
            let mut carry = A.iter().position(|&a| a == c).expect("valid b58 char") as u32;
            for b in bytes.iter_mut() {
                carry += (*b as u32) * 58;
                *b = (carry & 0xff) as u8;
                carry >>= 8;
            }
            while carry > 0 {
                bytes.push((carry & 0xff) as u8);
                carry >>= 8;
            }
        }
        let mut out = vec![0u8; zeros];
        out.extend(bytes.iter().rev());
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn b64x2_is_two_base64_layers() {
        use base64::Engine;
        let e = enc("b64x2");
        let once = base64::engine::general_purpose::STANDARD
            .decode(&e)
            .expect("outer base64");
        let twice = base64::engine::general_purpose::STANDARD
            .decode(&once)
            .expect("inner base64");
        assert_eq!(String::from_utf8(twice).unwrap(), P);
        // After ONE decode the value is still an opaque base64 blob, a WAF that
        // peels a single layer gains no XSS signature.
        let after_one = String::from_utf8(once).unwrap();
        assert!(!after_one.contains('<') && !after_one.contains("alert"));
    }

    // ── pipeline machinery: composition is associative & data-driven ─────────

    #[test]
    fn pipeline_composes_left_to_right_innermost_first() {
        // A two-stage pipeline must equal applying the stages by hand, in order:
        // [Deflate, Hex] == hex(deflate(P)). This is the law every composite row
        // relies on; it also guards against an accidental fold reversal.
        let piped = encode_stages(&[Stage::Deflate, Stage::Hex], P);
        let by_hand = hex::encode(deflate(P.as_bytes()));
        assert_eq!(piped, by_hand);
        // And the catalog's `zhex` is exactly that pipeline.
        assert_eq!(enc("zhex"), piped);
    }

    // ── new primitives: base62, raw-deflate, gzip + the cleanliness contract ──

    #[test]
    fn b62_is_pure_alphanumeric_and_round_trips() {
        let e = enc("b62");
        assert!(
            e.bytes().all(|b| b.is_ascii_alphanumeric()),
            "b62 must be pure alphanumeric: {e}"
        );
        assert_eq!(
            pl4_special_chars(&e),
            0,
            "b62 must carry zero PL4 special chars"
        );
        assert_eq!(b62_decode(&e), P);
        assert!(!e.contains('<') && !e.contains("alert"));
    }

    #[test]
    fn b62_known_vectors_pin_gmp_alphabet_order() {
        // Independent of the round-trip decoder (which shares the alphabet):
        // single-byte values pin the GMP digit order `0-9A-Za-z`.
        assert_eq!(encode_stages(&[Stage::B62], "\u{01}"), "1"); // value 1 → '1'
        assert_eq!(encode_stages(&[Stage::B62], "\u{0a}"), "A"); // value 10 → 'A'
        assert_eq!(encode_stages(&[Stage::B62], "\0"), "0"); // leading zero byte → '0'
    }

    // Reference base62 decoder for the test only (base-62 → base-256).
    fn b62_decode(s: &str) -> String {
        const A: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        let zeros = s.bytes().take_while(|&c| c == b'0').count();
        let mut bytes: Vec<u8> = Vec::new();
        for c in s.bytes() {
            let mut carry = A.iter().position(|&a| a == c).expect("valid b62 char") as u32;
            for b in bytes.iter_mut() {
                carry += (*b as u32) * 62;
                *b = (carry & 0xff) as u8;
                carry >>= 8;
            }
            while carry > 0 {
                bytes.push((carry & 0xff) as u8);
                carry >>= 8;
            }
        }
        let mut out = vec![0u8; zeros];
        out.extend(bytes.iter().rev());
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn deflate_raw_round_trips_via_raw_inflate() {
        // pako.inflateRaw / zlib.decompress(data,-15): no zlib header.
        use flate2::read::DeflateDecoder;
        use std::io::Read;
        let e = encode_stages(&[Stage::DeflateRaw, Stage::Hex], P);
        let raw = hex::decode(&e).expect("valid hex");
        let mut z = DeflateDecoder::new(&raw[..]);
        let mut out = String::new();
        z.read_to_string(&mut out)
            .expect("valid raw-deflate stream");
        assert_eq!(out, P);
    }

    #[test]
    fn gzip_round_trips_via_gunzip() {
        use flate2::read::GzDecoder;
        use std::io::Read;
        let e = encode_stages(&[Stage::Gzip, Stage::Hex], P);
        let raw = hex::decode(&e).expect("valid hex");
        let mut z = GzDecoder::new(&raw[..]);
        let mut out = String::new();
        z.read_to_string(&mut out).expect("valid gzip stream");
        assert_eq!(out, P);
    }

    #[test]
    fn zrawb64_round_trips_via_b64_then_raw_inflate() {
        // The named real-world idiom: atob() then pako.inflateRaw().
        use base64::Engine;
        use flate2::read::DeflateDecoder;
        use std::io::Read;
        let e = enc("zrawb64");
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&e)
            .expect("valid base64");
        let mut z = DeflateDecoder::new(&raw[..]);
        let mut out = String::new();
        z.read_to_string(&mut out)
            .expect("valid raw-deflate stream");
        assert_eq!(out, P);
        assert!(!e.contains('<') && !e.contains("alert"));
    }

    #[test]
    fn pl4_special_chars_is_the_measured_alphabet_contract() {
        // The measured form of the PL4 alphabet finding. Pure-alphanumeric /
        // bignum alphabets score 0 (the cleanest at PL4).
        for clean in ["b62", "hex", "b58"] {
            assert_eq!(
                pl4_special_chars(&enc(clean)),
                0,
                "{clean} must be special-char-free"
            );
        }
        // base64 (`+`/`/` + `=` padding) and padded base32 (`=`) DETERMINISTICALLY
        // carry special chars CRS's character rules can count, measurably > 0,
        // which is why they bypass PL4 less reliably than the clean trio. (b64url
        // is intentionally NOT asserted here: its `-`/`_` only appear when a
        // 6-bit group hits index 62/63, so its count is payload-dependent, the
        // very reason its bench bypass sits at ≈89%, between clean and base64.)
        for dirty in ["b64", "b32"] {
            assert!(
                pl4_special_chars(&enc(dirty)) > 0,
                "{dirty} must carry special chars"
            );
        }
        assert_eq!(pl4_special_chars(""), 0);
    }

    // ── --transform-chain parser: operator-facing pipeline grammar ───────────

    #[test]
    fn parse_chain_builds_innermost_first_pipeline() {
        assert_eq!(
            parse_chain("deflate.hex").unwrap(),
            vec![Stage::Deflate, Stage::Hex]
        );
        assert_eq!(
            parse_chain("b64.b64").unwrap(),
            vec![Stage::B64, Stage::B64]
        );
        assert_eq!(parse_chain("b58").unwrap(), vec![Stage::B58]);
    }

    #[test]
    fn parse_chain_matches_the_named_catalog_equivalents() {
        // The chain grammar must reproduce the hand-named composites exactly
        // proof the catalog rows ARE just pinned chains. `deflate.hex` ≡ zhex,
        // `deflate.b64` ≡ zb64, `b64.b64` ≡ b64x2.
        for (chain, name) in [
            ("deflate.hex", "zhex"),
            ("deflate.b64", "zb64"),
            ("b64.b64", "b64x2"),
        ] {
            let via_chain = encode_stages(&parse_chain(chain).unwrap(), P);
            assert_eq!(
                via_chain,
                enc(name),
                "chain `{chain}` must equal catalog `{name}`"
            );
        }
    }

    #[test]
    fn parse_chain_tolerates_whitespace_and_empty_segments() {
        assert_eq!(
            parse_chain("  deflate . hex  ").unwrap(),
            vec![Stage::Deflate, Stage::Hex]
        );
    }

    #[test]
    fn parse_chain_unknown_stage_is_error_naming_token_and_valid_set() {
        let err = parse_chain("deflate.nope").unwrap_err();
        assert!(err.contains("nope"), "must name the bad token: {err}");
        assert!(err.contains("deflate"), "must list the valid set: {err}");
    }

    #[test]
    fn parse_chain_empty_is_error() {
        assert!(parse_chain("").is_err());
        assert!(parse_chain("   ").is_err());
        assert!(parse_chain("..").is_err());
    }

    #[test]
    fn parse_chain_rejects_binary_terminal_stage() {
        // THE AUDIT GUARD: a pipeline ending in `deflate` emits raw bytes; left
        // unchecked it would panic encode_stages' UTF-8 finalisation on operator
        // input. parse_chain must reject it with the fix in the message.
        for bad in ["deflate", "hex.deflate", "b64.deflate"] {
            let err = parse_chain(bad).unwrap_err();
            assert!(
                err.contains("must end in a text stage") && err.contains("deflate"),
                "binary-terminal chain `{bad}` must fail closed with the fix: {err}"
            );
        }
        // And the validated chains never panic encode_stages (the invariant the
        // guard enforces) (exercise a few terminal-encoder shapes).
        for ok in ["deflate.hex", "deflate.b64", "deflate.b58", "rot13", "b32"] {
            let _ = encode_stages(&parse_chain(ok).unwrap(), P); // must not panic
        }
    }

    #[test]
    fn stage_token_round_trips_through_from_token() {
        for tok in stage_token_names() {
            let s = Stage::from_token(tok).expect("known token");
            assert_eq!(s.token(), tok, "token round-trip must be stable for {tok}");
        }
    }

    #[test]
    fn pipeline_generalises_beyond_the_catalog() {
        // The Stage machinery is general: an ad-hoc clean-alphabet chain the
        // catalog doesn't ship (deflate → base58) still round-trips. Proves the
        // axis is composition, not a fixed list, a future `--transform-chain`
        // can mix primitives without new bespoke encoders.
        let e = encode_stages(&[Stage::Deflate, Stage::B58], P);
        // base58-decode then zlib-inflate.
        use flate2::read::ZlibDecoder;
        use std::io::Read;
        let raw = b58_decode_bytes(&e);
        let mut z = ZlibDecoder::new(&raw[..]);
        let mut out = String::new();
        z.read_to_string(&mut out).expect("valid zlib stream");
        assert_eq!(out, P);
        // Clean alphabet end-to-end: no base64 special chars to trip CRS PL4.
        assert!(!e.contains('+') && !e.contains('/') && !e.contains('='));
    }

    // Byte-returning base58 decoder for the generalisation test.
    fn b58_decode_bytes(s: &str) -> Vec<u8> {
        const A: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        let zeros = s.bytes().take_while(|&c| c == b'1').count();
        let mut bytes: Vec<u8> = Vec::new();
        for c in s.bytes() {
            let mut carry = A.iter().position(|&a| a == c).expect("valid b58 char") as u32;
            for b in bytes.iter_mut() {
                carry += (*b as u32) * 58;
                *b = (carry & 0xff) as u8;
                carry >>= 8;
            }
            while carry > 0 {
                bytes.push((carry & 0xff) as u8);
                carry >>= 8;
            }
        }
        let mut out = vec![0u8; zeros];
        out.extend(bytes.iter().rev());
        out
    }

    // ── resolve / catalog ────────────────────────────────────────────────────

    #[test]
    fn resolve_all_returns_every_transform_in_order() {
        let got = resolve("all").unwrap();
        let names: Vec<_> = got.iter().map(|t| t.name).collect();
        assert_eq!(names, all_names());
    }

    #[test]
    fn resolve_comma_list_preserves_catalog_order_not_input_order() {
        // Input order is intentionally scrambled; output follows catalog order
        // so reports and sweeps are deterministic.
        let got = resolve("hex,b64").unwrap();
        let names: Vec<_> = got.iter().map(|t| t.name).collect();
        assert_eq!(names, vec!["b64", "hex"]);
    }

    #[test]
    fn resolve_dedups_repeated_names() {
        let got = resolve("b64,b64,hex,b64").unwrap();
        assert_eq!(got.len(), 2);
    }

    #[test]
    fn resolve_unknown_name_is_error_naming_the_token() {
        let err = resolve("b64,nope").unwrap_err();
        assert!(err.contains("nope"), "error must name the bad token: {err}");
        assert!(err.contains("b64"), "error must list the valid set: {err}");
    }

    #[test]
    fn resolve_empty_or_whitespace_is_error() {
        assert!(resolve("").is_err());
        assert!(resolve("   ").is_err());
        assert!(resolve(",,").is_err());
    }

    #[test]
    fn catalog_names_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for t in APP_TRANSFORMS {
            assert!(seen.insert(t.name), "duplicate transform name: {}", t.name);
        }
    }

    #[test]
    fn every_transform_has_a_nonempty_stage_pipeline() {
        // A row with no stages would emit the raw payload (a signature the WAF
        // catches) (fail closed against that).
        for t in APP_TRANSFORMS {
            assert!(
                !t.stages.is_empty(),
                "transform {} has an empty stage pipeline",
                t.name
            );
        }
    }

    #[test]
    fn every_transform_has_a_matching_origin_ctx() {
        // The ctx each transform names must be one the lab origin actually
        // decodes (guards against a transform whose decoder doesn't exist).
        let origin_ctxs = [
            "b64", "hex", "b32", "rot13", "jsesc", "entity", "zb64", "zhex", "b58", "b64x2", "b62",
            "zrawb64",
        ];
        for t in APP_TRANSFORMS {
            assert!(
                origin_ctxs.contains(&t.ctx),
                "transform {} names ctx {} with no origin decoder",
                t.name,
                t.ctx
            );
        }
    }

    #[test]
    fn every_encoder_strips_the_alert_signature() {
        // The whole point: no transform's output may carry a literal the WAF's
        // XSS rules match. (rot13 keeps angle brackets but loses the keywords,
        // which is what slips the regex/libinjection scoring.)
        for t in APP_TRANSFORMS {
            let e = t.encode(P);
            assert!(
                !e.contains("alert(") && !e.contains("onerror="),
                "transform {} leaked a signature token: {e}",
                t.name
            );
        }
    }
