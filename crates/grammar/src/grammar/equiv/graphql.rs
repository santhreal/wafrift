//! GraphQL injection equivalence + the joint
//! `(payload × delivery)` generator.
//!
//! GraphQL queries are whitespace-insensitive between tokens, alias
//! names don't affect resolver semantics, the `query` keyword and
//! operation name are optional for queries, and string literals support
//! `\uXXXX` escapes that decode to the same character. These four
//! equivalences are the WAF bypass surface: a WAF that pattern-matches
//! `__schema` misses `__\u0073chema`; a WAF that keys on `query` misses
//! the shorthand `{...}`; a WAF that counts top-level fields misses
//! alias-renamed duplicates.
//!
//! Every member is re-verified by [`still_executes_graphql`], which
//! checks that the same fields, arguments, and operation type survive
//! the rewrite.

use super::{DeliveryShape, Dialect, EquivConfig, EquivPayload, Rng};

/// Significant tokens of a GraphQL query: field names, argument names,
/// argument values, directive names, and the operation keyword. These
/// must survive every equiv rewrite.
fn sig_tokens(payload: &str) -> Vec<String> {
    // Extract the query string from a JSON-wrapped payload.
    let query = extract_query(payload);
    let mut toks = Vec::new();
    let mut chars = query.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        if c == '"' {
            // String literal: capture the raw content.
            chars.next();
            let mut s = String::from("\"");
            while let Some(&sc) = chars.peek() {
                chars.next();
                s.push(sc);
                if sc == '\\' {
                    if let Some(&nc) = chars.peek() {
                        s.push(nc);
                        chars.next();
                    }
                    continue;
                }
                if sc == '"' {
                    break;
                }
            }
            toks.push(s);
            continue;
        }
        if c.is_alphanumeric() || c == '_' || c == '$' {
            let mut s = String::new();
            while let Some(&sc) = chars.peek() {
                if sc.is_alphanumeric() || sc == '_' || sc == '$' {
                    s.push(sc);
                    chars.next();
                } else {
                    break;
                }
            }
            // Skip operation keywords and operation names: `query`
            // and `mutation` keywords are optional (shorthand form),
            // and the operation name (identifier immediately after
            // the keyword) is cosmetic. Including them would reject
            // the valid `query_shorthand` rewrite.
            if s == "query" || s == "mutation" {
                // Skip the operation name if present (next identifier).
                while let Some(&ws) = chars.peek() {
                    if ws.is_whitespace() {
                        chars.next();
                    } else {
                        break;
                    }
                }
                if let Some(&nc) = chars.peek()
                    && (nc.is_alphabetic() || nc == '_')
                {
                    while let Some(&sc) = chars.peek() {
                        if sc.is_alphanumeric() || sc == '_' {
                            chars.next();
                        } else {
                            break;
                        }
                    }
                }
                continue;
            }
            if !s.is_empty() {
                toks.push(s);
            }
            continue;
        }
        // Skip punctuation (braces, parens, colons, etc.)
        chars.next();
    }
    toks
}

/// Pull the `query` value out of a JSON-wrapped GraphQL payload.
/// If the payload is not JSON-wrapped (raw GraphQL), return as-is.
fn extract_query(payload: &str) -> &str {
    let trimmed = payload.trim();
    // JSON-wrapped: {"query":"..."} or {"query": "..."}
    if trimmed.starts_with('{') {
        // Find "query" key and extract its string value.
        if let Some(qidx) = trimmed.find("\"query\"") {
            let after = &trimmed[qidx + 7..];
            // Skip whitespace and colon.
            let after = after.trim_start();
            let after = after.strip_prefix(':').unwrap_or(after).trim_start();
            if let Some(rest) = after.strip_prefix('"') {
                // Find the closing quote (handle escaped quotes).
                let mut end = 0;
                let bytes = rest.as_bytes();
                let mut i = 0;
                while i < bytes.len() {
                    if bytes[i] == b'\\' {
                        i += 2;
                        continue;
                    }
                    if bytes[i] == b'"' {
                        end = i;
                        break;
                    }
                    i += 1;
                }
                return &rest[..end];
            }
        }
    }
    // GET-shaped: ?query=...
    if let Some(rest) = trimmed.strip_prefix("?query=") {
        return rest;
    }
    // Raw GraphQL or array-batched: return as-is.
    trimmed
}

/// True iff `cand` still executes the same GraphQL operation as
/// `original`. Checks that the significant tokens (field names,
/// arguments, string values) survive the rewrite, and that the
/// operation type (query/mutation/introspection) is preserved.
#[must_use]
pub fn still_executes_graphql(original: &str, cand: &str) -> bool {
    if cand.trim().is_empty() {
        return false;
    }
    let orig_query = extract_query(original);
    let cand_query = extract_query(cand);

    // Introspection queries must still contain __schema or __type.
    let orig_has_introspection = orig_query.contains("__schema") || orig_query.contains("__type");
    if orig_has_introspection {
        // Check both raw and unicode-escaped forms.
        let cand_has = cand_query.contains("__schema")
            || cand_query.contains("__type")
            || cand_query.contains("__\\u0073chema")
            || cand_query.contains("__\\u0074ype")
            || cand_query.contains("__\\u0073ch\\u0065ma")
            || cand_query.contains("__\\u0074y\\u0070e");
        if !cand_has {
            return false;
        }
    }

    let orig_sig = sig_tokens(original);
    let cand_sig = sig_tokens(cand);

    // All significant tokens from the original must appear in the
    // candidate (order-independent for fields, but we check set
    // containment since field order in GraphQL doesn't change
    // semantics).
    if orig_sig.is_empty() {
        return false;
    }
    for tok in &orig_sig {
        if !cand_sig.contains(tok) {
            return false;
        }
    }

    // Operation type must be preserved: if original has `mutation`,
    // candidate must too (or be a shorthand that the server treats
    // as a mutation — but shorthand is query-only, so a mutation
    // shorthand is invalid GraphQL).
    let orig_is_mutation = orig_query.contains("mutation");
    let cand_is_mutation = cand_query.contains("mutation");
    if orig_is_mutation && !cand_is_mutation {
        return false;
    }

    true
}

// ── rewrites (GraphQL-evaluation-equivalent) ───────────────────────

/// Insert or remove whitespace between tokens. GraphQL is
/// whitespace-insensitive: `{user(id:1){name}}` ≡
/// `{ user ( id : 1 ) { name } }`.
fn rw_ws_equiv(payload: &str, rng: &mut Rng) -> Option<String> {
    let query = extract_query(payload);
    let mut out = String::with_capacity(query.len() + 16);
    let chars: Vec<char> = query.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        // Insert whitespace after structural tokens with some probability.
        if (c == '{' || c == '(' || c == ',' || c == ':')
            && rng.chance(1, 2)
            && i + 1 < chars.len()
            && !chars[i + 1].is_whitespace()
        {
            out.push(c);
            out.push(' ');
            i += 1;
            continue;
        }
        // Insert whitespace before structural tokens.
        if (c == '{' || c == '}' || c == '(' || c == ')')
            && rng.chance(1, 3)
            && !out.ends_with(' ')
            && !out.is_empty()
        {
            out.push(' ');
        }
        out.push(c);
        i += 1;
    }
    if out == query {
        return None;
    }
    // Re-wrap if the original was JSON-wrapped.
    rewrap(payload, &out)
}

/// Rename aliases: `a:user(id:1){name}` → `b:user(id:1){name}`.
/// The alias name only affects the response key, not the query
/// semantics. WAFs that count top-level fields by alias name miss
/// the renamed variant.
fn rw_alias_rename(payload: &str, rng: &mut Rng) -> Option<String> {
    let query = extract_query(payload);
    // Find alias patterns: `identifier:identifier`
    let mut result = query.to_string();
    let mut found = false;
    // Simple approach: find `X:field` where X is a lowercase identifier
    // and replace X with a random identifier.
    let mut start = 0;
    while start < result.len() {
        // Look for pattern: identifier followed by `:` followed by identifier.
        let rest = &result[start..];
        if let Some(colon_idx) = rest.find(':') {
            // Check if this is an alias (identifier:before_colon is a simple
            // identifier, and after_colon is also an identifier).
            let before = &rest[..colon_idx];
            let after = &rest[colon_idx + 1..].trim_start();
            if is_identifier(before)
                && !before.is_empty()
                && after
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_alphabetic() || c == '_')
            {
                // Check this isn't an argument (arg: value) — arguments
                // have the identifier as a known argument name. We
                // distinguish by checking if the colon is inside parens
                // (argument context) vs at the top level (alias context).
                let depth = rest[..colon_idx].chars().filter(|&c| c == '(').count()
                    - rest[..colon_idx].chars().filter(|&c| c == ')').count();
                if depth == 0 {
                    // Alias context: rename.
                    let new_name = random_alias(rng);
                    result = format!("{}{}{}", &result[..start], new_name, &rest[colon_idx..]);
                    found = true;
                    start += new_name.len() + colon_idx;
                    continue;
                }
            }
            start += colon_idx + 1;
        } else {
            break;
        }
    }
    if !found {
        return None;
    }
    rewrap(payload, &result)
}

/// Query shorthand: `query Q{...}` → `{...}`. The `query` keyword
/// and operation name are optional for queries. WAFs that key on
/// the `query` keyword miss the shorthand form.
fn rw_query_shorthand(payload: &str, _rng: &mut Rng) -> Option<String> {
    let query = extract_query(payload);
    // Match `query Identifier {` or `query Identifier{`.
    let trimmed = query.trim_start();
    if let Some(rest) = trimmed.strip_prefix("query") {
        let rest = rest.trim_start();
        // Skip the operation name (identifier).
        let name_end = rest
            .find(|c: char| c.is_whitespace() || c == '{')
            .unwrap_or(0);
        let after_name = &rest[name_end..].trim_start();
        if after_name.starts_with('{') {
            // Remove `query Name` prefix.
            let new_query = after_name.to_string();
            return rewrap(payload, &new_query);
        }
    }
    None
}

/// Unicode-escape string contents: `__schema` → `__\u0073chema`.
/// GraphQL string literals support `\uXXXX` escapes. WAFs that
/// pattern-match `__schema` miss the escaped form.
fn rw_string_escape(payload: &str, rng: &mut Rng) -> Option<String> {
    let query = extract_query(payload);
    let mut result = String::with_capacity(query.len() + 32);
    let mut chars = query.chars().peekable();
    let mut modified = false;
    while let Some(c) = chars.next() {
        if c == '\\' && chars.peek().is_some() {
            // Preserve existing escapes.
            result.push(c);
            if let Some(&nc) = chars.peek() {
                result.push(nc);
                chars.next();
            }
            continue;
        }
        // Escape ASCII letters with \uXXXX with some probability.
        if c.is_ascii_alphabetic() && rng.chance(1, 8) {
            result.push_str(&format!("\\u{:04x}", c as u32));
            modified = true;
        } else {
            result.push(c);
        }
    }
    if !modified {
        return None;
    }
    rewrap(payload, &result)
}

/// Re-wrap a rewritten query back into the original payload format
/// (JSON-wrapped, GET-shaped, or raw).
fn rewrap(original: &str, new_query: &str) -> Option<String> {
    let trimmed = original.trim();
    if trimmed.starts_with('{') && trimmed.contains("\"query\"") {
        // JSON-wrapped: replace the query string value.
        // Find the query value boundaries.
        if let Some(qidx) = trimmed.find("\"query\"") {
            let after = &trimmed[qidx + 7..];
            let after = after.trim_start();
            let after = after.strip_prefix(':').unwrap_or(after).trim_start();
            if let Some(rest) = after.strip_prefix('"') {
                let mut end = 0;
                let bytes = rest.as_bytes();
                let mut i = 0;
                while i < bytes.len() {
                    if bytes[i] == b'\\' {
                        i += 2;
                        continue;
                    }
                    if bytes[i] == b'"' {
                        end = i;
                        break;
                    }
                    i += 1;
                }
                // Escape the new query for JSON.
                let escaped = new_query.replace('\\', "\\\\").replace('"', "\\\"");
                let result = format!(
                    "{}\"query\":\"{}\"{}",
                    &trimmed[..qidx],
                    escaped,
                    &rest[end + 1..]
                );
                return Some(result);
            }
        }
    }
    if trimmed.starts_with("?query=") {
        return Some(format!("?query={}", new_query));
    }
    // Raw GraphQL or unknown format: return the query directly.
    Some(new_query.to_string())
}

fn is_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| c.is_alphanumeric() || c == '_')
        && s.chars()
            .next()
            .is_some_and(|c| c.is_alphabetic() || c == '_')
}

fn random_alias(rng: &mut Rng) -> String {
    const NAMES: &[&str] = &["x", "y", "z", "q", "r", "s", "a2", "b2", "c2", "d2"];
    rng.pick(NAMES).to_string()
}

#[must_use]
pub fn generate(payload: &str, cfg: &EquivConfig) -> Vec<EquivPayload> {
    let mut rng = Rng::new(cfg.seed);
    let all = super::sql::delivery_set(&cfg.param);
    let (deliveries, single_forced) = match cfg.force_delivery {
        Some(i) if i < all.len() => (vec![all[i].clone()], true),
        _ => (all, false),
    };
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out: Vec<EquivPayload> = Vec::with_capacity(cfg.max);

    if !still_executes_graphql(payload, payload) {
        return out;
    }

    for d in &deliveries {
        if !cfg.vary_delivery && !single_forced && !matches!(d, DeliveryShape::JsonBody { .. }) {
            continue;
        }
        let key = format!("{}\u{1}{}", payload, d.label());
        if seen.insert(key) {
            out.push(EquivPayload {
                payload: payload.to_string(),
                delivery: d.clone(),
                dialect: Dialect::Generic,
                rules: vec!["identity"],
            });
        }
    }

    let mut attempts = 0;
    while out.len() < cfg.max
        && attempts < cfg.max * super::ATTEMPT_BUDGET_MULTIPLIER + super::ATTEMPT_BUDGET_FLOOR
    {
        attempts += 1;
        let mut s = payload.to_string();
        let mut rules: Vec<&'static str> = Vec::with_capacity(8);
        if rng.chance(3, 5)
            && let Some(n) = rw_ws_equiv(&s, &mut rng)
        {
            s = n;
            rules.push("ws_equiv");
        }
        if rng.chance(2, 5)
            && let Some(n) = rw_alias_rename(&s, &mut rng)
        {
            s = n;
            rules.push("alias_rename");
        }
        if rng.chance(1, 3)
            && let Some(n) = rw_query_shorthand(&s, &mut rng)
        {
            s = n;
            rules.push("query_shorthand");
        }
        if rng.chance(2, 5)
            && let Some(n) = rw_string_escape(&s, &mut rng)
        {
            s = n;
            rules.push("string_escape");
        }
        if rules.is_empty() {
            continue;
        }
        if !still_executes_graphql(payload, &s) {
            continue;
        }
        let d = if cfg.vary_delivery || single_forced {
            rng.pick(&deliveries).clone()
        } else {
            DeliveryShape::JsonBody {
                param: cfg.param.clone(),
                content_type: None,
            }
        };
        let key = format!("{s}\u{1}{}", d.label());
        if !seen.insert(key) {
            continue;
        }
        out.push(EquivPayload {
            payload: s,
            delivery: d,
            dialect: Dialect::Generic,
            rules,
        });
    }

    out.truncate(cfg.max);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(seed: u64, max: usize) -> EquivConfig {
        EquivConfig {
            seed,
            max,
            verify: true,
            vary_delivery: true,
            param: "query".into(),
            force_delivery: None,
        }
    }

    #[test]
    fn still_executes_graphql_accepts_identity() {
        let p = r#"{"query":"{ __schema { types { name } } }"}"#;
        assert!(still_executes_graphql(p, p));
    }

    #[test]
    fn still_executes_graphql_rejects_empty() {
        let p = r#"{"query":"{ __schema { types { name } } }"}"#;
        assert!(!still_executes_graphql(p, ""));
        assert!(!still_executes_graphql(p, r#"{"query":""}"#));
    }

    #[test]
    fn still_executes_graphql_rejects_missing_introspection() {
        let orig = r#"{"query":"{ __schema { types { name } } }"}"#;
        let cand = r#"{"query":"{ user { name } }"}"#;
        assert!(!still_executes_graphql(orig, cand));
    }

    #[test]
    fn still_executes_graphql_preserves_mutation() {
        let orig = r#"{"query":"mutation { deleteUser(id:1){ok} }"}"#;
        // Removing `mutation` keyword changes the operation type.
        let cand = r#"{"query":"{ deleteUser(id:1){ok} }"}"#;
        assert!(!still_executes_graphql(orig, cand));
    }

    #[test]
    fn ws_equiv_preserves_semantics() {
        let p = r#"{"query":"{user(id:1){name}}"}"#;
        let mut rng = Rng::new(42);
        let rewritten = rw_ws_equiv(p, &mut rng).unwrap();
        assert!(still_executes_graphql(p, &rewritten));
    }

    #[test]
    fn alias_rename_preserves_semantics() {
        let p = r#"{"query":"{ a:user(id:1){name} b:user(id:2){name} }"}"#;
        let mut rng = Rng::new(42);
        if let Some(rewritten) = rw_alias_rename(p, &mut rng) {
            assert!(still_executes_graphql(p, &rewritten));
        }
    }

    #[test]
    fn query_shorthand_strips_keyword() {
        let p = r#"{"query":"query Search { user(id:1){name} }"}"#;
        let mut rng = Rng::new(42);
        let rewritten = rw_query_shorthand(p, &mut rng).unwrap();
        assert!(rewritten.contains("user"));
        assert!(!rewritten.contains("query Search"));
        assert!(still_executes_graphql(p, &rewritten));
    }

    #[test]
    fn string_escape_preserves_introspection() {
        let p = r#"{"query":"{ __schema { types { name } } }"}"#;
        let mut rng = Rng::new(42);
        if let Some(rewritten) = rw_string_escape(p, &mut rng) {
            assert!(still_executes_graphql(p, &rewritten));
        }
    }

    #[test]
    fn generator_is_deterministic_and_bounded() {
        let p = r#"{"query":"{ __schema { types { name } } }"}"#;
        let a = generate(p, &cfg(42, 16));
        let b = generate(p, &cfg(42, 16));
        assert_eq!(a.len(), b.len());
        assert!(a.len() <= 16);
        assert!(!a.is_empty());
        for m in &a {
            assert!(still_executes_graphql(p, &m.payload));
        }
    }

    #[test]
    fn generator_emits_diverse_rules() {
        let p = r#"{"query":"{ a:user(id:1){name} b:user(id:2){name} }"}"#;
        let out = generate(p, &cfg(42, 32));
        let rules: std::collections::HashSet<&str> =
            out.iter().flat_map(|m| m.rules.iter().copied()).collect();
        // At least 2 distinct rewrite rules beyond identity.
        assert!(rules.len() >= 2, "rules: {:?}", rules);
    }

    #[test]
    fn generator_handles_raw_graphql() {
        let p = "{ __schema { types { name } } }";
        let out = generate(p, &cfg(42, 8));
        assert!(!out.is_empty());
        for m in &out {
            assert!(still_executes_graphql(p, &m.payload));
        }
    }

    #[test]
    fn generator_handles_get_shaped() {
        let p = "?query=%7B%20__schema%20%7B%20types%20%7B%20name%20%7D%20%7D%20%7D";
        let out = generate(p, &cfg(42, 8));
        // GET-shaped payloads may not produce rewrites (the query is
        // URL-encoded), but the identity member should be present.
        assert!(!out.is_empty());
    }

    #[test]
    fn generator_never_panics_on_arbitrary_input() {
        for input in [
            "",
            "x",
            "{}",
            "null",
            r#"{"query":null}"#,
            r#"{"query":"}""#,
            "🦀",
        ] {
            let _ = generate(input, &cfg(42, 8));
        }
    }
}
