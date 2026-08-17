    use super::*;

    fn h(name: &str, value: &str) -> (String, String) {
        (name.to_string(), value.to_string())
    }

    // ── Fixture bodies ────────────────────────────────────────────────────

    fn body_managed_1020() -> Vec<u8> {
        b"<!DOCTYPE html><html><body>\
          <h1>Sorry, you have been blocked</h1>\
          <p>You are unable to access example.com</p>\
          <!-- error code: 1020 -->\
          <div>Cloudflare Ray ID: 8a1b2c3d4e5f6a7b</div>\
          </body></html>"
            .to_vec()
    }

    fn body_bot_challenge() -> Vec<u8> {
        b"<!DOCTYPE html><html><body>\
          <script>var jschl_vc='abc123';challenge-platform init jschl</script>\
          <div>Cloudflare Ray ID: 9a2b3c4d5e6f7a8b</div>\
          </body></html>"
            .to_vec()
    }

    fn body_turnstile() -> Vec<u8> {
        b"<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>\
          <div class=\"cf-turnstile\" data-sitekey=\"0x4AAAAAAA\"></div>\
          <script src=\"https://challenges.cloudflare.com/turnstile/v0/api.js\"></script>\
          <div>Cloudflare Ray ID: 7c8d9e0f1a2b3c4d</div>\
          </body></html>"
            .to_vec()
    }

    fn body_under_attack() -> Vec<u8> {
        b"<!DOCTYPE html><html><body>\
          <h1>DDoS Protection by Cloudflare</h1>\
          <p>Please enable JavaScript. Ray ID: 6d7e8f9a0b1c2d3e-ORD</p>\
          <script>under attack mode enabled</script>\
          </body></html>"
            .to_vec()
    }

    fn body_browser_check() -> Vec<u8> {
        b"<!DOCTYPE html><html><body>\
          <h2>Checking your browser before accessing example.com.</h2>\
          <p>This process is automatic. Browser Integrity Check.</p>\
          <p>One more step: Please complete the security check.</p>\
          </body></html>"
            .to_vec()
    }

    fn body_rate_limited() -> Vec<u8> {
        b"<html><body>\
          <h1>Too Many Requests</h1>\
          <p>You have sent too many requests. Rate limit exceeded.</p>\
          </body></html>"
            .to_vec()
    }

    fn body_old_rule_comment() -> Vec<u8> {
        b"<!DOCTYPE html><html><body>\
          <h1>Sorry, you have been blocked</h1>\
          <!-- 951220 -->\
          <div>Cloudflare Ray ID: 1a2b3c4d5e6f7a8b-FRA</div>\
          </body></html>"
            .to_vec()
    }

    fn body_cve_log4shell() -> Vec<u8> {
        b"<!DOCTYPE html><html><body>\
          <h1>You have been blocked</h1>\
          <p>This request triggered rule: CVE-2021-44228 (Log4Shell).</p>\
          <!-- error code: 1020 -->\
          </body></html>"
            .to_vec()
    }

    fn body_wordpress_ruleset() -> Vec<u8> {
        b"<!DOCTYPE html><html><body>\
          <h1>Sorry, you have been blocked</h1>\
          <p>WordPress security rule triggered.</p>\
          <!-- error code: 1020 -->\
          </body></html>"
            .to_vec()
    }

    fn body_owasp() -> Vec<u8> {
        b"<html><body>\
          <h1>Access Denied</h1>\
          <p>OWASP Core Rule Set blocked your request.</p>\
          </body></html>"
            .to_vec()
    }

    fn body_empty() -> Vec<u8> {
        vec![]
    }

    fn body_403_no_markers() -> Vec<u8> {
        b"<html><body><p>Forbidden</p></body></html>".to_vec()
    }

    fn body_managed_challenge_platform() -> Vec<u8> {
        b"<!DOCTYPE html><html><body>\
          <script src=\"/cdn-cgi/challenge-platform/h/g/orchestrate/managed/v1\"></script>\
          <div>Cloudflare Ray ID: 2b3c4d5e6f7a8b9c-SEA</div>\
          </body></html>"
            .to_vec()
    }

    // ── Test: Managed Ruleset block (1020) ────────────────────────────────

    #[test]
    fn managed_1020_block_class_and_ruleset() {
        let hdrs = vec![
            h("cf-ray", "8a1b2c3d4e5f6a7b-SJC"),
            h("cf-mitigated", "block"),
            h("server", "cloudflare"),
        ];
        let sig = parse_cf_block(&hdrs, &body_managed_1020());
        assert_eq!(sig.block_class, BlockClass::ManagedRulesetBlock);
        assert_eq!(sig.edge_pop.as_deref(), Some("SJC"));
        assert_eq!(sig.cf_ray.as_deref(), Some("8a1b2c3d4e5f6a7b-SJC"));
        assert_eq!(sig.mitigated_reason.as_deref(), Some("block"));
        assert_eq!(sig.ruleset_hint.as_deref(), Some("waf-managed-rule"));
        assert_eq!(sig.rule_attribution, "cf:SJC:waf-managed-rule");
        assert!(sig.is_cloudflare_response());
    }

    // ── Test: Bot Challenge (jschl) ───────────────────────────────────────

    #[test]
    fn bot_challenge_jschl_class() {
        let hdrs = vec![
            h("cf-ray", "9a2b3c4d5e6f7a8b-LHR"),
            h("server", "cloudflare"),
        ];
        let sig = parse_cf_block(&hdrs, &body_bot_challenge());
        assert_eq!(sig.block_class, BlockClass::BotChallenge);
        assert_eq!(sig.edge_pop.as_deref(), Some("LHR"));
        assert!(sig.is_cloudflare_response());
    }

    // ── Test: Turnstile CAPTCHA ───────────────────────────────────────────

    #[test]
    fn turnstile_captcha_class() {
        let hdrs = vec![
            h("cf-ray", "7c8d9e0f1a2b3c4d-AMS"),
            h("cf-mitigated", "challenge"),
            h("server", "cloudflare"),
        ];
        let sig = parse_cf_block(&hdrs, &body_turnstile());
        assert_eq!(sig.block_class, BlockClass::Captcha);
        assert_eq!(sig.edge_pop.as_deref(), Some("AMS"));
    }

    // ── Test: Under Attack Mode ───────────────────────────────────────────

    #[test]
    fn under_attack_browser_check_class() {
        let hdrs = vec![
            h("cf-ray", "6d7e8f9a0b1c2d3e-ORD"),
            h("server", "cloudflare"),
        ];
        let sig = parse_cf_block(&hdrs, &body_under_attack());
        assert_eq!(sig.block_class, BlockClass::BrowserCheck);
        assert_eq!(sig.edge_pop.as_deref(), Some("ORD"));
    }

    // ── Test: Browser Integrity Check ─────────────────────────────────────

    #[test]
    fn browser_integrity_check_class() {
        let hdrs = vec![
            h("server", "cloudflare"),
            h("cf-ray", "5e6f7a8b9c0d1e2f-CDG"),
        ];
        let sig = parse_cf_block(&hdrs, &body_browser_check());
        assert_eq!(sig.block_class, BlockClass::BrowserCheck);
        assert_eq!(sig.edge_pop.as_deref(), Some("CDG"));
    }

    // ── Test: Rate Limited ────────────────────────────────────────────────

    #[test]
    fn rate_limited_via_retry_after_header() {
        let hdrs = vec![
            h("cf-ray", "4d5e6f7a8b9c0d1e-NRT"),
            h("retry-after", "30"),
            h("server", "cloudflare"),
        ];
        let sig = parse_cf_block(&hdrs, &body_rate_limited());
        assert_eq!(sig.block_class, BlockClass::RateLimited);
        assert_eq!(sig.edge_pop.as_deref(), Some("NRT"));
    }

    #[test]
    fn rate_limited_via_body_markers_only() {
        let hdrs = vec![h("cf-ray", "3c4d5e6f7a8b9c0d-SIN")];
        let sig = parse_cf_block(&hdrs, &body_rate_limited());
        assert_eq!(sig.block_class, BlockClass::RateLimited);
    }

    // ── Test: Old rule comment ID ─────────────────────────────────────────

    #[test]
    fn old_rule_comment_id_extracted() {
        let hdrs = vec![
            h("cf-ray", "1a2b3c4d5e6f7a8b-FRA"),
            h("cf-mitigated", "block"),
            h("server", "cloudflare"),
        ];
        let sig = parse_cf_block(&hdrs, &body_old_rule_comment());
        assert_eq!(sig.block_class, BlockClass::ManagedRulesetBlock);
        assert_eq!(sig.ruleset_hint.as_deref(), Some("951220"));
        assert_eq!(sig.rule_attribution, "cf:FRA:951220");
    }

    // ── Test: CVE attribution (Log4Shell) ─────────────────────────────────

    #[test]
    fn cve_log4shell_ruleset_hint() {
        let hdrs = vec![
            h("cf-ray", "0a1b2c3d4e5f6a7b-MIA"),
            h("cf-mitigated", "block"),
        ];
        let sig = parse_cf_block(&hdrs, &body_cve_log4shell());
        // CVE should win over error code in ruleset hint
        assert_eq!(sig.ruleset_hint.as_deref(), Some("CVE-2021-44228"));
        assert_eq!(sig.block_class, BlockClass::ManagedRulesetBlock);
    }

    // ── Test: WordPress ruleset ───────────────────────────────────────────

    #[test]
    fn wordpress_ruleset_hint() {
        let hdrs = vec![
            h("cf-ray", "ba9c8d7e6f5a4b3c-YYZ"),
            h("cf-mitigated", "block"),
        ];
        let sig = parse_cf_block(&hdrs, &body_wordpress_ruleset());
        // Error code 1020 → "waf-managed-rule" takes priority over body-text
        // "wordpress" in this fixture because the error code prefix wins
        assert_eq!(sig.ruleset_hint.as_deref(), Some("waf-managed-rule"));
    }

    // ── Test: WordPress with no error code ───────────────────────────────

    #[test]
    fn wordpress_ruleset_hint_no_error_code() {
        let body = b"<html><body><h1>You have been blocked</h1>\
                     <p>WordPress security rule triggered.</p></body></html>";
        let hdrs = vec![
            h("cf-ray", "aa1b2c3d4e5f6a7b-ATL"),
            h("cf-mitigated", "block"),
        ];
        let sig = parse_cf_block(&hdrs, body);
        assert_eq!(sig.ruleset_hint.as_deref(), Some("wordpress"));
        assert_eq!(sig.block_class, BlockClass::ManagedRulesetBlock);
    }

    // ── Test: OWASP in body ───────────────────────────────────────────────

    #[test]
    fn owasp_ruleset_hint() {
        let hdrs = vec![h("cf-ray", "bb1c2d3e4f5a6b7c-LAX")];
        let sig = parse_cf_block(&hdrs, &body_owasp());
        assert_eq!(sig.ruleset_hint.as_deref(), Some("owasp"));
        assert_eq!(sig.block_class, BlockClass::ManagedRulesetBlock);
    }

    // ── Test: Empty body ─────────────────────────────────────────────────

    #[test]
    fn empty_body_unknown_class() {
        let hdrs = vec![
            h("cf-ray", "cc1d2e3f4a5b6c7d-DFW"),
            h("server", "cloudflare"),
        ];
        let sig = parse_cf_block(&hdrs, &body_empty());
        assert_eq!(sig.block_class, BlockClass::Unknown);
        assert_eq!(sig.ruleset_hint, None);
        assert_eq!(sig.rule_attribution, "cf:DFW:?");
    }

    // ── Test: No CF headers at all ────────────────────────────────────────

    #[test]
    fn non_cloudflare_response_not_detected() {
        let hdrs = vec![h("server", "nginx"), h("content-type", "text/html")];
        let sig = parse_cf_block(&hdrs, b"<html><body>Forbidden</body></html>");
        assert!(!sig.is_cloudflare_response());
        assert_eq!(sig.edge_pop, None);
        assert_eq!(sig.cf_ray, None);
        assert_eq!(sig.block_class, BlockClass::Unknown);
        assert_eq!(sig.rule_attribution, "cf:?:?");
    }

    // ── Test: cf-mitigated without cf-ray ────────────────────────────────

    #[test]
    fn mitigated_header_without_ray() {
        let hdrs = vec![h("cf-mitigated", "block"), h("server", "cloudflare")];
        let sig = parse_cf_block(&hdrs, &body_403_no_markers());
        assert!(sig.is_cloudflare_response());
        assert_eq!(sig.edge_pop, None);
        assert_eq!(sig.block_class, BlockClass::ManagedRulesetBlock);
        assert_eq!(sig.rule_attribution, "cf:?:?");
    }

    // ── Test: cf-ray with invalid POP suffix ─────────────────────────────

    #[test]
    fn cf_ray_invalid_pop_no_edge_pop() {
        // POP longer than 3 chars → None
        let hdrs = vec![h("cf-ray", "8a1b2c3d4e5f6a7b-SJCXX")];
        let sig = parse_cf_block(&hdrs, b"");
        assert_eq!(sig.cf_ray.as_deref(), Some("8a1b2c3d4e5f6a7b-SJCXX"));
        assert_eq!(sig.edge_pop, None);
    }

    #[test]
    fn cf_ray_numeric_pop_no_edge_pop() {
        // POP containing digits → None (not a valid IATA code)
        let hdrs = vec![h("cf-ray", "8a1b2c3d4e5f6a7b-S1C")];
        let sig = parse_cf_block(&hdrs, b"");
        assert_eq!(sig.edge_pop, None);
    }

    // ── Test: cf-mitigated = challenge + body has no challenge markers ─────

    #[test]
    fn challenge_mitigated_no_body_markers_is_bot_challenge() {
        let hdrs = vec![
            h("cf-ray", "dd1e2f3a4b5c6d7e-SVO"),
            h("cf-mitigated", "challenge"),
        ];
        let sig = parse_cf_block(&hdrs, b"<html><body>Please wait...</body></html>");
        // No turnstile, no under-attack → falls to BotChallenge default
        assert_eq!(sig.block_class, BlockClass::BotChallenge);
    }

    // ── Test: challenge-platform body marker ─────────────────────────────

    #[test]
    fn challenge_platform_body_marker_is_bot_challenge() {
        let hdrs = vec![h("cf-ray", "ee1f2a3b4c5d6e7f-GRU")];
        let sig = parse_cf_block(&hdrs, &body_managed_challenge_platform());
        assert_eq!(sig.block_class, BlockClass::BotChallenge);
    }

    // ── Test: error code 1015 (rate limit) ────────────────────────────────

    #[test]
    fn error_code_1015_rate_limited() {
        let body =
            b"<html><body><!-- error code: 1015 --><h1>You have been blocked</h1></body></html>";
        let hdrs = vec![
            h("cf-ray", "ff1a2b3c4d5e6f7a-GIG"),
            h("cf-mitigated", "block"),
        ];
        let sig = parse_cf_block(&hdrs, body);
        // Error code 1015 maps to "rate-limited" ruleset hint
        assert_eq!(sig.ruleset_hint.as_deref(), Some("rate-limited"));
        // cf-mitigated: block still wins for block_class
        assert_eq!(sig.block_class, BlockClass::ManagedRulesetBlock);
    }

    // ── Test: error code 1010 (browser integrity / manual review) ─────────

    #[test]
    fn error_code_1010_browser_integrity() {
        let body = b"<html><body><!-- error code: 1010 --><h1>Access denied</h1></body></html>";
        let hdrs = vec![
            h("cf-ray", "a01b2c3d4e5f6a7b-MAD"),
            h("cf-mitigated", "block"),
        ];
        let sig = parse_cf_block(&hdrs, body);
        assert_eq!(sig.ruleset_hint.as_deref(), Some("browser-integrity"));
    }

    // ── Test: error code 1009 (IP banned) ────────────────────────────────

    #[test]
    fn error_code_1009_ip_banned() {
        let body = b"<html><body><!-- error code: 1009 --><h1>Access denied</h1></body></html>";
        let hdrs = vec![
            h("cf-ray", "b11c2d3e4f5a6b7c-ICN"),
            h("cf-mitigated", "block"),
        ];
        let sig = parse_cf_block(&hdrs, body);
        assert_eq!(sig.ruleset_hint.as_deref(), Some("ip-banned"));
        assert_eq!(sig.block_class, BlockClass::ManagedRulesetBlock);
    }

    // ── Test: managed_challenge mitigated header ───────────────────────────

    #[test]
    fn managed_challenge_header_is_bot_challenge() {
        let hdrs = vec![
            h("cf-ray", "c21d3e4f5a6b7c8d-PEK"),
            h("cf-mitigated", "managed_challenge"),
        ];
        let sig = parse_cf_block(&hdrs, b"<html><body></body></html>");
        assert_eq!(sig.block_class, BlockClass::BotChallenge);
        assert_eq!(sig.mitigated_reason.as_deref(), Some("managed_challenge"));
    }

    // ── Test: jschallenge mitigated header ────────────────────────────────

    #[test]
    fn jschallenge_header_is_bot_challenge() {
        let hdrs = vec![
            h("cf-ray", "d31e4f5a6b7c8d9e-HKG"),
            h("cf-mitigated", "jschallenge"),
        ];
        let sig = parse_cf_block(
            &hdrs,
            b"<html><body>Please complete the challenge.</body></html>",
        );
        assert_eq!(sig.block_class, BlockClass::BotChallenge);
    }

    // ── Test: rate-limit mitigated header ────────────────────────────────

    #[test]
    fn rate_limit_mitigated_header() {
        let hdrs = vec![
            h("cf-ray", "e41f5a6b7c8d9e0f-BOM"),
            h("cf-mitigated", "rate-limit"),
        ];
        let sig = parse_cf_block(&hdrs, b"<html><body><p>Slow down.</p></body></html>");
        assert_eq!(sig.block_class, BlockClass::RateLimited);
    }

    // ── Test: unknown cf-mitigated value falls back to body ──────────────

    #[test]
    fn unknown_mitigated_value_falls_back_to_body() {
        let hdrs = vec![
            h("cf-ray", "f51a6b7c8d9e0f1a-BCN"),
            h("cf-mitigated", "redirect"),
        ];
        let sig = parse_cf_block(&hdrs, &body_turnstile());
        // Unknown mitigated value → body signals → Captcha from turnstile
        assert_eq!(sig.block_class, BlockClass::Captcha);
    }

    // ── Test: rule attribution format ────────────────────────────────────

    #[test]
    fn rule_attribution_format_with_all_fields() {
        let hdrs = vec![
            h("cf-ray", "8a1b2c3d4e5f6a7b-SJC"),
            h("cf-mitigated", "block"),
        ];
        let sig = parse_cf_block(&hdrs, &body_managed_1020());
        assert!(sig.rule_attribution.starts_with("cf:SJC:"));
        assert!(sig.rule_attribution.contains(':'));
    }

    // ── Test: CVE-2017-5638 (Apache Struts) ──────────────────────────────

    #[test]
    fn cve_apache_struts_extracted() {
        let body =
            b"<html><body><p>Blocked: CVE-2017-5638 Apache Struts exploit.</p></body></html>";
        let hdrs = vec![h("cf-ray", "901a2b3c4d5e6f7a-ARN")];
        let sig = parse_cf_block(&hdrs, body);
        assert_eq!(sig.ruleset_hint.as_deref(), Some("CVE-2017-5638"));
    }

    // ── Test: CVE-2014-6271 (Shellshock) ─────────────────────────────────

    #[test]
    fn cve_shellshock_extracted() {
        let body = b"<html><body><p>Shellshock CVE-2014-6271 detected.</p></body></html>";
        let hdrs = vec![h("cf-ray", "a11b2c3d4e5f6a7b-CPH")];
        let sig = parse_cf_block(&hdrs, body);
        assert_eq!(sig.ruleset_hint.as_deref(), Some("CVE-2014-6271"));
    }

    // ── Test: Turnstile body + cf-mitigated: block = Captcha wins? ────────
    // cf-mitigated: block sets ManagedRulesetBlock regardless of Turnstile,
    // because Turnstile can be a secondary verification after a block.
    // The block class comes from mitigated, not body.

    #[test]
    fn block_mitigated_with_turnstile_body_is_managed_block() {
        let hdrs = vec![
            h("cf-ray", "b21c3d4e5f6a7b8c-DUB"),
            h("cf-mitigated", "block"),
        ];
        let sig = parse_cf_block(&hdrs, &body_turnstile());
        // Header wins: block → ManagedRulesetBlock
        assert_eq!(sig.block_class, BlockClass::ManagedRulesetBlock);
    }

    // ── Test: only server: cloudflare header (no cf-ray) ──────────────────

    #[test]
    fn server_cloudflare_only_is_unknown_without_cf_ray() {
        let hdrs = vec![h("server", "cloudflare")];
        let sig = parse_cf_block(&hdrs, b"<html><body>Forbidden</body></html>");
        // No cf-ray, no cf-mitigated → is_cloudflare_response = false
        assert!(!sig.is_cloudflare_response());
        assert_eq!(sig.edge_pop, None);
    }

    // ── Test: body with "access denied" phrase ────────────────────────────

    #[test]
    fn access_denied_phrase_is_managed_block() {
        let hdrs = vec![
            h("cf-ray", "c31d4e5f6a7b8c9d-ZRH"),
            h("server", "cloudflare"),
        ];
        let body = b"<html><body><h1>Access Denied</h1><p>This site is protected by Cloudflare.</p></body></html>";
        let sig = parse_cf_block(&hdrs, body);
        assert_eq!(sig.block_class, BlockClass::ManagedRulesetBlock);
    }

    // ── Test: ERRORPAGESSTATUS pattern ────────────────────────────────────

    #[test]
    fn errorpagesstatus_pattern_extracted() {
        let body = b"<!-- ::ERRORPAGESSTATUS::1020 -->";
        let hdrs = vec![
            h("cf-ray", "d41e5f6a7b8c9d0e-VIE"),
            h("cf-mitigated", "block"),
        ];
        let sig = parse_cf_block(&hdrs, body);
        assert_eq!(sig.ruleset_hint.as_deref(), Some("waf-managed-rule"));
    }

    // ── Test: data-translate error_code pattern ───────────────────────────

    #[test]
    fn data_translate_error_code_pattern() {
        let body = b"<span data-translate=\"error_code\">1006</span>";
        let hdrs = vec![
            h("cf-ray", "e51f6a7b8c9d0e1f-WAW"),
            h("cf-mitigated", "block"),
        ];
        let sig = parse_cf_block(&hdrs, body);
        assert_eq!(sig.ruleset_hint.as_deref(), Some("ip-banned"));
    }

    // ── Test: log4shell text in body ──────────────────────────────────────

    #[test]
    fn log4shell_text_in_body() {
        let body = b"<html><body><p>Request blocked: log4shell exploit detected.</p></body></html>";
        let hdrs = vec![h("cf-ray", "f61a7b8c9d0e1f2a-PRG")];
        let sig = parse_cf_block(&hdrs, body);
        assert_eq!(sig.ruleset_hint.as_deref(), Some("log4shell"));
    }

    // ── Test: spring4shell text in body ───────────────────────────────────

    #[test]
    fn spring4shell_text_in_body() {
        let body = b"<html><body><p>spring4shell CVE-2022-22965 blocked.</p></body></html>";
        let hdrs = vec![h("cf-ray", "071b8c9d0e1f2a3b-HEL")];
        // CVE wins over body text pattern "spring4shell" because extract_cve_id runs first
        let sig = parse_cf_block(&hdrs, body);
        assert_eq!(sig.ruleset_hint.as_deref(), Some("CVE-2022-22965"));
    }

    // ── Test: heartbleed text in body ─────────────────────────────────────

    #[test]
    fn heartbleed_text_in_body() {
        let body = b"<html><body><p>Heartbleed attack detected by WAF.</p></body></html>";
        let hdrs = vec![h("cf-ray", "181c9d0e1f2a3b4c-OSL")];
        let sig = parse_cf_block(&hdrs, body);
        assert_eq!(sig.ruleset_hint.as_deref(), Some("heartbleed"));
    }

    // ── Test: sqli text in body ───────────────────────────────────────────

    #[test]
    fn sqli_text_in_body() {
        let body = b"<html><body><p>SQL Injection attempt blocked.</p></body></html>";
        let hdrs = vec![h("cf-ray", "292d0e1f2a3b4c5d-LIS")];
        let sig = parse_cf_block(&hdrs, body);
        assert_eq!(sig.ruleset_hint.as_deref(), Some("sqli"));
    }

    // ── Test: cross-site scripting text ───────────────────────────────────

    #[test]
    fn xss_text_in_body() {
        let body = b"<html><body><p>Cross-Site Scripting blocked.</p></body></html>";
        let hdrs = vec![h("cf-ray", "3a3e1f2a3b4c5d6e-BUH")];
        let sig = parse_cf_block(&hdrs, body);
        assert_eq!(sig.ruleset_hint.as_deref(), Some("xss"));
    }

    // ── Test: command injection text ──────────────────────────────────────

    #[test]
    fn cmdi_text_in_body() {
        let body = b"<html><body><p>Command Injection detected.</p></body></html>";
        let hdrs = vec![h("cf-ray", "4b4f2a3b4c5d6e7f-KBP")];
        let sig = parse_cf_block(&hdrs, body);
        assert_eq!(sig.ruleset_hint.as_deref(), Some("cmdi"));
    }

    // ── Test: path traversal text ─────────────────────────────────────────

    #[test]
    fn path_traversal_text_in_body() {
        let body = b"<html><body><p>Path traversal attempt blocked by firewall.</p></body></html>";
        let hdrs = vec![h("cf-ray", "5c5a3b4c5d6e7f8a-KGL")];
        let sig = parse_cf_block(&hdrs, body);
        assert_eq!(sig.ruleset_hint.as_deref(), Some("path-traversal"));
    }

    // ── Test: local file inclusion text ──────────────────────────────────

    #[test]
    fn lfi_text_in_body() {
        let body = b"<html><body><p>Local file inclusion blocked.</p></body></html>";
        let hdrs = vec![h("cf-ray", "6d6b4c5d6e7f8a9b-ADD")];
        let sig = parse_cf_block(&hdrs, body);
        assert_eq!(sig.ruleset_hint.as_deref(), Some("lfi"));
    }

    // ── Test: SSRF text in body ───────────────────────────────────────────

    #[test]
    fn ssrf_text_in_body() {
        let body = b"<html><body><p>SSRF attack blocked by CF WAF.</p></body></html>";
        let hdrs = vec![h("cf-ray", "7e7c5d6e7f8a9b0c-ABV")];
        let sig = parse_cf_block(&hdrs, body);
        assert_eq!(sig.ruleset_hint.as_deref(), Some("ssrf"));
    }

    // ── Test: SSTI text in body ───────────────────────────────────────────

    #[test]
    fn ssti_text_in_body() {
        let body = b"<html><body><p>Server-Side Template Injection blocked.</p></body></html>";
        let hdrs = vec![h("cf-ray", "8f8d6e7f8a9b0c1d-ABJ")];
        let sig = parse_cf_block(&hdrs, body);
        assert_eq!(sig.ruleset_hint.as_deref(), Some("ssti"));
    }

    // ── Test: retry-after takes priority over body rate-limit text ────────

    #[test]
    fn retry_after_priority_over_cf_mitigated_block() {
        let hdrs = vec![
            h("cf-ray", "9a9e7f8a9b0c1d2e-ABK"),
            h("cf-mitigated", "block"),
            h("retry-after", "60"),
        ];
        let sig = parse_cf_block(&hdrs, &body_managed_1020());
        // retry-after wins regardless of cf-mitigated: block
        assert_eq!(sig.block_class, BlockClass::RateLimited);
    }

    // ── Test: rule comment takes priority over body text pattern ──────────

    #[test]
    fn rule_comment_takes_priority_over_body_text_owasp() {
        let body = b"<html><body><!-- 942100 --> OWASP SQL injection blocked.</body></html>";
        let hdrs = vec![h("cf-ray", "ab1f8a9b0c1d2e3f-ABL")];
        let sig = parse_cf_block(&hdrs, body);
        // Rule comment "942100" takes priority over "owasp" body text
        assert_eq!(sig.ruleset_hint.as_deref(), Some("942100"));
    }

    // ── Test: case-insensitive header name matching ────────────────────────

    #[test]
    fn case_insensitive_cf_ray_header() {
        let hdrs = vec![
            h("CF-Ray", "bc2a9b0c1d2e3f4a-ABM"),
            h("CF-MITIGATED", "block"),
        ];
        let sig = parse_cf_block(&hdrs, &body_managed_1020());
        assert_eq!(sig.edge_pop.as_deref(), Some("ABM"));
        assert_eq!(sig.mitigated_reason.as_deref(), Some("block"));
    }

    // ── Test: cf-ray with no dash (malformed) ────────────────────────────

    #[test]
    fn malformed_cf_ray_no_dash() {
        let hdrs = vec![h("cf-ray", "8a1b2c3d4e5f6a7b")];
        let sig = parse_cf_block(&hdrs, b"");
        // rsplit('-') on a no-dash string returns the whole string → len != 3 → None
        assert_eq!(sig.edge_pop, None);
        assert_eq!(sig.cf_ray.as_deref(), Some("8a1b2c3d4e5f6a7b"));
    }

    // ── Test: multiple rule comments in body (first wins) ─────────────────

    #[test]
    fn multiple_rule_comments_first_wins() {
        let body = b"<html><body><!-- 942100 --> text <!-- 941101 --> more</body></html>";
        let hdrs = vec![h("cf-ray", "cd3b0c1d2e3f4a5b-ABN")];
        let sig = parse_cf_block(&hdrs, body);
        assert_eq!(sig.ruleset_hint.as_deref(), Some("942100"));
    }

    // ── Test: modsecurity text in body ────────────────────────────────────

    #[test]
    fn modsecurity_text_in_body() {
        let body = b"<html><body><p>ModSecurity rule triggered.</p></body></html>";
        let hdrs = vec![h("cf-ray", "de4c1d2e3f4a5b6c-ABO")];
        let sig = parse_cf_block(&hdrs, body);
        assert_eq!(sig.ruleset_hint.as_deref(), Some("modsecurity"));
    }

    // ── Test: error code 1016 (origin DNS) ────────────────────────────────

    #[test]
    fn error_code_1016_origin_dns() {
        let body = b"<!-- error code: 1016 --><h1>Origin DNS error</h1>";
        let hdrs = vec![
            h("cf-ray", "ef5d2e3f4a5b6c7d-ABP"),
            h("server", "cloudflare"),
        ];
        let sig = parse_cf_block(&hdrs, body);
        assert_eq!(sig.ruleset_hint.as_deref(), Some("origin-dns"));
    }

    // ── Test: Drupal ruleset from body ────────────────────────────────────

    #[test]
    fn drupal_ruleset_from_body() {
        let body = b"<html><body><p>Drupal security rule triggered.</p></body></html>";
        let hdrs = vec![h("cf-ray", "f06e3f4a5b6c7d8e-ABQ")];
        let sig = parse_cf_block(&hdrs, body);
        assert_eq!(sig.ruleset_hint.as_deref(), Some("drupal"));
    }

    // ── Test: is_cloudflare_response semantics ────────────────────────────

    #[test]
    fn is_cloudflare_with_cf_ray_only() {
        let hdrs = vec![h("cf-ray", "017f4a5b6c7d8e9f-ABR")];
        let sig = parse_cf_block(&hdrs, b"");
        assert!(sig.is_cloudflare_response());
    }

    #[test]
    fn is_cloudflare_with_cf_mitigated_only() {
        let hdrs = vec![h("cf-mitigated", "block")];
        let sig = parse_cf_block(&hdrs, b"");
        assert!(sig.is_cloudflare_response());
    }

    // ── Test: manual review error codes ───────────────────────────────────

    #[test]
    fn error_1011_hotlinking_maps_to_hotlinking() {
        let body = b"<!-- error code: 1011 --><h1>Access denied</h1>";
        let hdrs = vec![
            h("cf-ray", "129a5b6c7d8e9f0a-ABS"),
            h("cf-mitigated", "block"),
        ];
        let sig = parse_cf_block(&hdrs, body);
        assert_eq!(sig.ruleset_hint.as_deref(), Some("hotlinking"));
    }

    #[test]
    fn error_1012_access_denied() {
        let body = b"<!-- error code: 1012 --><h1>Access denied</h1>";
        let hdrs = vec![
            h("cf-ray", "23ab6c7d8e9f0a1b-ABT"),
            h("cf-mitigated", "block"),
        ];
        let sig = parse_cf_block(&hdrs, body);
        assert_eq!(sig.ruleset_hint.as_deref(), Some("access-denied"));
    }

    // ── Test: challenge-loop error code ───────────────────────────────────

    #[test]
    fn error_1025_challenge_loop() {
        let body = b"<!-- error code: 1025 --><h1>Challenge loop detected</h1>";
        let hdrs = vec![h("cf-ray", "34bc7d8e9f0a1b2c-ABU")];
        let sig = parse_cf_block(&hdrs, body);
        assert_eq!(sig.ruleset_hint.as_deref(), Some("challenge-loop"));
    }

    // ── Bug fix tests: cf-mitigated:block must not be overridden by body
    //    rate-limit text (weak signal).  Retry-After (strong) still wins. ────

    #[test]
    fn block_mitigated_with_rate_limit_body_text_stays_managed_block() {
        // A block page that mentions "too many requests" in its body (e.g. a
        // CF custom block page template that includes rate-limit copy) must NOT
        // be reclassified as RateLimited when cf-mitigated: block is present.
        let body = b"<html><body>\
            <h1>Sorry, you have been blocked</h1>\
            <p>Too many requests from this IP. Please contact support.</p>\
            </body></html>";
        let hdrs = vec![
            h("cf-ray", "45cd8e9f0a1b2c3d-AMS"),
            h("cf-mitigated", "block"),
        ];
        let sig = parse_cf_block(&hdrs, body);
        // cf-mitigated: block must win over body text "too many requests"
        assert_eq!(
            sig.block_class,
            BlockClass::ManagedRulesetBlock,
            "cf-mitigated:block must not be overridden by body rate-limit text"
        );
    }

    #[test]
    fn block_mitigated_with_rate_limit_phrase_stays_managed_block() {
        // "rate limit" in the body footer should not override cf-mitigated: block
        let body = b"<html><body>\
            <h1>Access Denied</h1>\
            <p>This site enforces a rate limit on suspicious traffic.</p>\
            </body></html>";
        let hdrs = vec![
            h("cf-ray", "56de9f0a1b2c3d4e-CDG"),
            h("cf-mitigated", "block"),
        ];
        let sig = parse_cf_block(&hdrs, body);
        assert_eq!(sig.block_class, BlockClass::ManagedRulesetBlock);
    }

    #[test]
    fn no_mitigated_header_rate_limit_body_is_rate_limited() {
        // Without cf-mitigated, body "too many requests" is the only signal
        // and should correctly produce RateLimited.
        let body = b"<html><body><h1>Too Many Requests</h1></body></html>";
        let hdrs = vec![h("cf-ray", "67ef0a1b2c3d4e5f-DFW")];
        let sig = parse_cf_block(&hdrs, body);
        assert_eq!(sig.block_class, BlockClass::RateLimited);
    }

    #[test]
    fn retry_after_overrides_block_mitigated_to_rate_limited() {
        // Retry-After header (strong) must still win even over cf-mitigated: block
        // this is the "temporary ban with retry directive" CF pattern.
        let hdrs = vec![
            h("cf-ray", "78f00b1c2d3e4f5a-EWR"),
            h("cf-mitigated", "block"),
            h("retry-after", "120"),
        ];
        let sig = parse_cf_block(&hdrs, b"<html><body>Blocked.</body></html>");
        assert_eq!(sig.block_class, BlockClass::RateLimited);
    }

    #[test]
    fn unknown_mitigated_with_rate_limit_body_is_rate_limited() {
        // An unknown cf-mitigated value falls back to body signals,
        // where body-text rate-limit IS authoritative.
        let body =
            b"<html><body><h1>Too Many Requests</h1><p>rate-limit exceeded</p></body></html>";
        let hdrs = vec![
            h("cf-ray", "890a1c2d3e4f5a6b-HKG"),
            h("cf-mitigated", "redirect"),
        ];
        let sig = parse_cf_block(&hdrs, body);
        assert_eq!(sig.block_class, BlockClass::RateLimited);
    }

    // ── Adversarial fixture tests ─────────────────────────────────────────

    #[test]
    fn malformed_utf8_body_does_not_panic() {
        // Responses with invalid UTF-8 sequences (truncated multi-byte,
        // overlong encodings, surrogate pairs) must not panic.  The parser
        // must fall back gracefully to an empty body.
        let body: Vec<u8> = vec![0xff, 0xfe, 0x00, 0x41, 0x42, 0x43, 0x80, 0x81];
        let hdrs = vec![
            h("cf-ray", "9a1b2c3d4e5f6a7b-IAD"),
            h("cf-mitigated", "block"),
        ];
        let sig = parse_cf_block(&hdrs, &body);
        // Must not panic; block_class may be Unknown (body unreadable) or
        // ManagedRulesetBlock (from cf-mitigated header alone).
        assert!(sig.is_cloudflare_response());
        // cf-mitigated: block wins even when body is garbage
        assert_eq!(sig.block_class, BlockClass::ManagedRulesetBlock);
    }

    #[test]
    fn nul_bytes_in_body_do_not_panic() {
        // NUL bytes embedded in an otherwise valid body must not crash the
        // parser.  Some WAFs inject NUL bytes as anti-scraping measures.
        let mut body = b"<html><body>Sorry, you have been blocked\x00\x00</body></html>".to_vec();
        body.push(0x00);
        let hdrs = vec![h("cf-ray", "ab2c3d4e5f6a7b8c-ORD")];
        let sig = parse_cf_block(&hdrs, &body);
        // NUL bytes after valid UTF-8 are ignored by str::from_utf8 fallback
        // but from_utf8_lossy keeps the valid prefix: "blocked" phrase fires.
        assert!(sig.is_cloudflare_response());
    }

    #[test]
    fn empty_header_value_does_not_panic() {
        // Empty cf-ray and cf-mitigated values must not cause panics or
        // incorrect edge_pop extraction.
        let hdrs = vec![
            h("cf-ray", ""),
            h("cf-mitigated", ""),
            h("server", "cloudflare"),
        ];
        let sig = parse_cf_block(&hdrs, b"");
        // Empty cf-ray: rsplit('-').next() returns "" which has len 0 != 3 → None
        assert_eq!(sig.edge_pop, None);
        // Empty cf-mitigated: stored as empty string, not None
        assert_eq!(sig.mitigated_reason.as_deref(), Some(""));
    }

    #[test]
    fn mixed_encoding_body_cf_error_extraction() {
        // Bodies with latin-1 / windows-1252 high bytes mixed into otherwise
        // ASCII content, str::from_utf8 will fail, should fall back to empty
        // body rather than returning garbage extracted codes.
        let mut body = b"<!-- error code: 1020 -->".to_vec();
        body.extend_from_slice(&[0xc0, 0x80]); // overlong NUL in modified UTF-8
        body.extend_from_slice(b"<h1>blocked</h1>");
        let hdrs = vec![
            h("cf-ray", "bc3d4e5f6a7b8c9d-MIA"),
            h("cf-mitigated", "block"),
        ];
        let sig = parse_cf_block(&hdrs, &body);
        // Even with mixed encoding, the parser must not panic.
        // It may or may not extract the error code depending on from_utf8 result.
        assert!(sig.is_cloudflare_response());
        assert_eq!(sig.block_class, BlockClass::ManagedRulesetBlock);
    }

    #[test]
    fn very_long_body_does_not_stack_overflow() {
        // 512 KB of repeated block-page content, must complete without stack
        // overflow and return a result within bounded time.
        let chunk = b"<html><body><p>Sorry, you have been blocked.</p>";
        let body: Vec<u8> = chunk.iter().cloned().cycle().take(512 * 1024).collect();
        let hdrs = vec![
            h("cf-ray", "cd4e5f6a7b8c9d0e-LHR"),
            h("cf-mitigated", "block"),
        ];
        let sig = parse_cf_block(&hdrs, &body);
        assert_eq!(sig.block_class, BlockClass::ManagedRulesetBlock);
    }

    #[test]
    fn cve_id_with_insufficient_digit_count_is_not_extracted() {
        // CVE IDs with fewer than 4 trailing digits must not fire. "CVE-2021-123"
        // is not a valid CVE ID (needs >= 4 digits in the sequence number).
        let body = b"<html><body><p>Matched CVE-2021-123 heuristic.</p></body></html>";
        let hdrs = vec![h("cf-ray", "de5f6a7b8c9d0e1f-SYD")];
        let sig = parse_cf_block(&hdrs, body);
        // Should not extract CVE-2021-123 (only 3 digit suffix)
        assert_ne!(sig.ruleset_hint.as_deref(), Some("CVE-2021-123"));
    }

    #[test]
    fn cf_ray_with_only_a_dash_produces_no_edge_pop() {
        // cf-ray = "-" → rsplit('-') yields ["", ""] → first = "" → len 0 ≠ 3 → None
        let hdrs = vec![h("cf-ray", "-")];
        let sig = parse_cf_block(&hdrs, b"");
        assert_eq!(sig.edge_pop, None);
        assert_eq!(sig.cf_ray.as_deref(), Some("-"));
    }

    #[test]
    fn multiple_cf_ray_headers_last_one_wins() {
        // HTTP/2 allows duplicate header names; the parser processes them in
        // order so the last `cf-ray` entry wins (same as most HTTP stacks).
        let hdrs = vec![h("cf-ray", "first-SJC"), h("cf-ray", "second-LHR")];
        let sig = parse_cf_block(&hdrs, b"");
        // The last cf-ray processed overwrites the earlier one.
        assert_eq!(sig.cf_ray.as_deref(), Some("second-LHR"));
        assert_eq!(sig.edge_pop.as_deref(), Some("LHR"));
    }