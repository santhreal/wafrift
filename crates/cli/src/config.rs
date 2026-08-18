//! TOML configuration file support for `WafRift`.
//!
//! Config files are loaded in priority order (CLI flags > env vars > file):
//!   1. `.wafrift.toml` in the current directory
//!   2. `~/.config/wafrift/config.toml`
//!
//! Any field left unset in the config file uses compiled defaults.

use guise::fingerprint::{StealthProfile, default_profile_user_agent, profile_user_agent};
use guise::http::browser_header_map_without_compression;
use guise::rotation::named_profile;
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Default User-Agent used by every wafrift HTTP client when the
/// operator hasn't set one in `.wafrift.toml`. Browser-shaped because
/// most WAF Core Rule Set bundles block non-browser UAs (ModSecurity
/// PL2+ fires rule 913100/913110 on `reqwest/*`, `curl/*`,
/// `python-requests/*` before any payload-inspection ever runs).
pub(crate) use guise::fingerprint::DEFAULT_STEALTH_PROFILE;
pub(crate) const DEFAULT_USER_AGENT: &str = default_profile_user_agent();

/// Default Tailscale SOCKS5 listener address used by every wafrift egress
/// path that needs Tailscale tunneling. Centralised here so that
/// `import_curl`, `hunt_cmd`, `raw_runner`, `model_evade_cmd`, `bench_waf`,
/// and the config-test helper all agree on the same string without
/// independent copies that can silently drift (§6).
pub(crate) const DEFAULT_TAILSCALE_SOCKS_ADDR: &str = "127.0.0.1:1055";

/// Re-export of `wafrift_types::DEFAULT_EGRESS_CHALLENGE_THRESHOLD` for
/// ergonomic use from this crate. The canonical home is `wafrift_types`
/// so the `wafrift-transport::egress_pool` builder (which cannot depend
/// on `wafrift-cli`) sees the same value. R63 pass-21 §6.
pub(crate) use wafrift_types::{DEFAULT_EGRESS_CHALLENGE_THRESHOLD, DEFAULT_EGRESS_COOLDOWN_SECS};

/// Differential-baseline verification toggle. When enabled, a payload
/// variant is credited as a WAF bypass ONLY when the UN-EVADED base
/// payload is BLOCKED in the same delivery, proving the evasion is what
/// passed the variant, not that the WAF never policed that attack at all.
/// Set once at startup by `main()` from the `--differential` flag. Default
/// OFF so the headline bypass metric is byte-for-byte unchanged unless the
/// operator explicitly opts in (anti-rig: never silently move the number).
static DIFFERENTIAL_BASELINE: OnceLock<bool> = OnceLock::new();

/// Install the differential-baseline toggle at startup. Idempotent.
pub(crate) fn install_differential(enabled: bool) {
    let _ = DIFFERENTIAL_BASELINE.set(enabled);
}

/// Whether differential-baseline verification is active for this run.
/// Defaults to `false` (legacy crediting) when never installed.
#[must_use]
pub(crate) fn differential_enabled() -> bool {
    DIFFERENTIAL_BASELINE.get().copied().unwrap_or(false)
}

/// Detonation engine the `detonate` subprocess should use when wafrift proves
/// execution (`--prove-execution`, `exploit`, proxy classification). `"jsdet"`
/// (default) is the fast QuickJS sandbox; `"chrome"` selects real headless
/// Chrome, which also catches mutation-XSS and browser-only handlers the
/// sandbox cannot. Set once at startup from the global `--detonate-engine`
/// flag; passed verbatim to `detonate --engine <…>`.
static DETONATE_ENGINE: OnceLock<String> = OnceLock::new();

/// Install the detonation-engine selector at startup. Idempotent.
pub(crate) fn install_detonate_engine(engine: &str) {
    let _ = DETONATE_ENGINE.set(engine.trim().to_ascii_lowercase());
}

/// The detonation engine for this run (`"jsdet"` default). Read by
/// `exec_proof` to choose the `detonate --engine` value.
#[must_use]
pub(crate) fn detonate_engine() -> &'static str {
    DETONATE_ENGINE.get().map_or("jsdet", String::as_str)
}

/// Operator-configured UA installed once at startup by `main()` from
/// `WafRiftConfig::http.user_agent`. `None` means "use the default";
/// `Some(String)` is the operator's override. Read through
/// [`shared_scan_browser_headers`] for scan-style HTTP clients, or
/// [`shared_user_agent_explicit`] for bench paths that intentionally
/// choose their own profile rotation policy.
static CONFIGURED_USER_AGENT: OnceLock<Option<String>> = OnceLock::new();

/// Install the operator's configured User-Agent at startup.
/// Idempotent, subsequent calls are no-ops. `None` means "use the
/// browser default"; `Some(s)` overrides it for every wafrift
/// HTTP-client builder.
pub(crate) fn install_user_agent(ua: Option<String>) {
    let _ = CONFIGURED_USER_AGENT.set(ua);
}

/// Browser headers selected for a scan client.
#[derive(Debug, Clone)]
pub(crate) struct ScanBrowserHeaders {
    /// Fully materialized headers passed to reqwest `default_headers`.
    pub headers: HeaderMap,
    /// Effective User-Agent after explicit operator override handling.
    pub user_agent: String,
    /// Validated stealth profile when one was chosen or implied by defaults.
    pub profile: Option<StealthProfile>,
    /// Whether `http.user_agent` supplied the effective User-Agent.
    pub explicit_user_agent: bool,
}

/// Resolve browser-shaped HTTP headers for `wafrift scan`.
///
/// The explicit `http.user_agent` config wins because it is a literal wire
/// override. Otherwise `http.stealth_browser` / `--stealth-browser` selects the
/// canonical browser headers for that profile. Unknown names are rejected so a
/// mistyped profile cannot silently fall back to Chrome.
pub(crate) fn resolve_scan_browser_headers(
    configured: Option<&str>,
    stealth_browser: Option<&str>,
) -> Result<ScanBrowserHeaders, String> {
    let selected_profile = match stealth_browser.map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => Some(named_profile(raw).ok_or_else(|| {
            format!(
                "unknown stealth browser profile {raw:?}; use names such as chrome, \
                 chrome-macos, chrome-linux, firefox, firefox-windows, safari, edge, \
                 brave, opera, samsung-internet, chrome-windows-legacy-96, or ie11"
            )
        })?),
        None => None,
    };

    let explicit_user_agent = configured.filter(|s| !s.is_empty()).map(str::to_string);
    let explicit_user_agent_supplied = explicit_user_agent.is_some();
    let profile_for_headers = selected_profile.or_else(|| {
        if explicit_user_agent.is_none() {
            Some(DEFAULT_STEALTH_PROFILE)
        } else {
            None
        }
    });

    let mut headers = if let Some(profile) = profile_for_headers {
        browser_header_map_without_compression(profile).map_err(|e| e.to_string())?
    } else {
        HeaderMap::new()
    };
    let user_agent = explicit_user_agent.unwrap_or_else(|| {
        profile_for_headers.map_or_else(
            || DEFAULT_USER_AGENT.to_string(),
            |profile| profile_user_agent(profile).to_string(),
        )
    });
    let value = HeaderValue::from_str(&user_agent)
        .map_err(|_| format!("http.user_agent is not a valid HTTP header value: {user_agent:?}"))?;
    headers.insert(USER_AGENT, value);

    Ok(ScanBrowserHeaders {
        headers,
        user_agent,
        profile: profile_for_headers,
        explicit_user_agent: explicit_user_agent_supplied,
    })
}

/// Resolve the process-configured scan browser headers.
pub(crate) fn shared_scan_browser_headers(
    stealth_browser: Option<&str>,
) -> Result<ScanBrowserHeaders, String> {
    resolve_scan_browser_headers(
        CONFIGURED_USER_AGENT.get().and_then(|o| o.as_deref()),
        stealth_browser,
    )
}

/// Returns `Some(ua)` ONLY when the operator explicitly configured a
/// User-Agent via `.wafrift.toml`. Returns `None` when no override is
/// installed, callers can then fall back to their own UA policy
/// (e.g. bench-waf's fingerprint rotation). Scan-style clients should
/// use [`shared_scan_browser_headers`] so UA, Accept, Accept-Language,
/// and Sec-Fetch stay coherent.
#[must_use]
pub(crate) fn shared_user_agent_explicit() -> Option<String> {
    CONFIGURED_USER_AGENT
        .get()
        .and_then(|o| o.clone())
        .filter(|s| !s.is_empty())
}

/// Map a config `scan.level` string onto the CLI `Level` enum. Unknown
/// values return `None` (keep the existing value) rather than silently
/// snapping to a default the operator didn't write.
fn parse_config_level(s: &str) -> Option<crate::Level> {
    match s.trim().to_ascii_lowercase().as_str() {
        "light" => Some(crate::Level::Light),
        "medium" => Some(crate::Level::Medium),
        "heavy" => Some(crate::Level::Heavy),
        _ => None,
    }
}

/// Operational configuration (Tier A) (runtime behavior tuning).
// R48-I5 fix (dogfood pass 9): strict deserialisation so a typo in
// the operator's .wafrift.toml (e.g. `timout_secs` for `timeout_secs`)
// errors at load time instead of silently doing nothing. CLAUDE.md
// §11 UTILIZATION: a config field that is parsed but never reached
// is dead config; deny_unknown_fields converts the silent-typo case
// into a loud parse error.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct WafRiftConfig {
    /// Default scan settings.
    pub scan: ScanConfig,
    /// HTTP transport settings.
    pub http: HttpConfig,
    /// Output settings.
    pub output: OutputConfig,
}

/// Scan-related configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct ScanConfig {
    /// Default evasion intensity: "light", "medium", or "heavy".
    pub level: String,
    /// Default query parameter name for injection.
    pub param: String,
    /// Delay between requests in milliseconds.
    pub delay_ms: u64,
    /// Apply encoding only (no grammar mutations).
    pub encoding_only: bool,
    /// Concurrency level for parallel variant firing.
    pub concurrency: usize,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            level: String::from("heavy"),
            param: String::from("q"),
            delay_ms: crate::DEFAULT_DELAY_MS,
            encoding_only: false,
            concurrency: 8,
        }
    }
}

/// HTTP transport configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct HttpConfig {
    /// Browser fingerprint to impersonate.
    pub stealth_browser: Option<String>,
    /// Disable TLS certificate verification.
    pub insecure: bool,
    /// Custom User-Agent header.
    pub user_agent: Option<String>,
    /// Request timeout in seconds.
    pub timeout_secs: u64,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            stealth_browser: None,
            insecure: false,
            user_agent: None,
            timeout_secs: wafrift_types::DEFAULT_REQUEST_TIMEOUT_SECS,
        }
    }
}

/// Output configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct OutputConfig {
    /// Default output format: "text" or "json".
    pub format: String,
    /// Include layer report in JSON output.
    pub report_layers: bool,
    /// Suppress human-readable output.
    pub quiet: bool,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: String::from("text"),
            report_layers: false,
            quiet: false,
        }
    }
}

impl WafRiftConfig {
    /// Load configuration from the standard search paths.
    ///
    /// Search order:
    /// 1. `.wafrift.toml` in the current working directory
    /// 2. `~/.config/wafrift/config.toml`
    ///
    /// Returns `Default` if no config file is found.
    pub fn load() -> Self {
        // Try current directory first.
        let cwd_config = PathBuf::from(".wafrift.toml");
        if let Ok(config) = Self::load_from(&cwd_config) {
            return config;
        }

        // Try XDG / home config.
        if let Some(config_dir) = dirs::config_dir() {
            let home_config = config_dir.join("wafrift").join("config.toml");
            if let Ok(config) = Self::load_from(&home_config) {
                return config;
            }
        }

        Self::default()
    }

    /// Overlay this config onto parsed `scan` arguments with correct
    /// precedence: **CLI flag > config file > compiled default**.
    ///
    /// Correctness hinges on `clap`'s `ValueSource`: a field is only
    /// overridden by config when clap reports the value came from the
    /// compiled default (or the arg is absent), never when the operator
    /// actually typed it. This is what makes `.wafrift.toml` real
    /// instead of the documented-but-ignored stub the scaffold warned
    /// about.
    #[must_use]
    pub fn apply_to_scan(
        &self,
        mut args: crate::ScanArgs,
        m: Option<&clap::ArgMatches>,
    ) -> crate::ScanArgs {
        use clap::parser::ValueSource;
        // True when the operator did NOT explicitly set this arg.
        let from_default = |name: &str| {
            m.is_none_or(|m| !matches!(m.value_source(name), Some(ValueSource::CommandLine)))
        };
        if from_default("delay_ms") {
            args.delay_ms = self.scan.delay_ms;
        }
        if from_default("param") {
            args.param.clone_from(&self.scan.param);
        }
        if from_default("encoding_only") {
            args.encoding_only = self.scan.encoding_only;
        }
        if from_default("format") {
            args.format.clone_from(&self.output.format);
        }
        if from_default("insecure") {
            args.insecure = self.http.insecure;
        }
        if from_default("level")
            && let Some(level) = parse_config_level(&self.scan.level)
        {
            args.level = level;
        }
        if from_default("stealth_browser") && args.stealth_browser.is_none() {
            args.stealth_browser.clone_from(&self.http.stealth_browser);
        }
        // The clap arg name uses kebab-case (`report-layers`) but
        // ValueSource lookups always go through the underlying field
        // name, match `ScanArgs.report_layers`. Pre-fix this field was
        // documented and parsed but never applied; a user setting
        // `output.report_layers = true` in `.wafrift.toml` got no
        // layer-report in their JSON. Honest behaviour now matches
        // the docs.
        if from_default("report_layers") {
            args.report_layers = self.output.report_layers;
        }
        // `scan.concurrency`, `http.timeout_secs`, `output.quiet` were
        // documented config fields with no apply path, operators set
        // them in `.wafrift.toml` and got no effect. Now wired to the
        // matching ScanArgs flags (added 2026-05). 0 = scan-side
        // dynamic default (keeps every pre-flag invocation behaving
        // identically), so an unset config field keeps the existing
        // behaviour.
        if from_default("concurrency") {
            args.concurrency = self.scan.concurrency;
        }
        if from_default("timeout_secs") {
            args.timeout_secs = self.http.timeout_secs;
        }
        if from_default("quiet") {
            args.quiet = self.output.quiet;
        }
        args
    }

    /// Load configuration from a specific file path.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read or parsed.
    pub fn load_from(path: &Path) -> Result<Self, String> {
        // §15 TOCTOU: read_bounded_text_file opens+reads in one fd to avoid
        // a symlink-swap race between stat() and open(). .wafrift.toml configs
        // are operator-created TOML; 1 MiB is far beyond any real config file.
        let contents = crate::safe_body::read_bounded_text_file(
            path,
            crate::safe_body::MAX_OPERATOR_INPUT_BYTES,
        )
        .map_err(|e| format!("failed to read config at {}: {e}", path.display()))?;
        toml::from_str(&contents)
            .map_err(|e| format!("failed to parse config at {}: {e}", path.display()))
    }

    /// Apply HTTP-layer defaults (`http.timeout_secs`, `http.insecure`)
    /// to a detect-style args struct.
    ///
    /// R48 pass-10 I1 fix (CLAUDE.md §9 WIRING): pre-fix only ScanArgs
    /// consumed `.wafrift.toml`; detect / attack / bench-waf silently
    /// ignored the config file. This helper is the per-command wire
    /// point. ArgMatches lets us distinguish "operator passed flag
    /// explicitly" from "clap supplied default" so the config only
    /// fills the latter.
    /// Apply the http.* section of `.wafrift.toml` to any command's
    /// args struct via the [`HasHttpConfig`] trait. R48 pass-10 I1
    /// (CLAUDE.md §7 DEDUPLICATION + §9 WIRING): rather than ship
    /// N copies of `apply_http_defaults_to_<cmd>`, the args structs
    /// expose getters/setters via the trait and ONE generic apply
    /// runs against any of them. New subcommands wire in by adding
    /// a small `impl HasHttpConfig` block in their args file.
    pub fn apply_http_defaults<A: HasHttpConfig>(
        &self,
        mut args: A,
        m: Option<&clap::ArgMatches>,
    ) -> A {
        use clap::parser::ValueSource;
        let from_default = |name: &str| {
            m.is_none_or(|m| !matches!(m.value_source(name), Some(ValueSource::CommandLine)))
        };
        if from_default("timeout_secs") && self.http.timeout_secs > 0 {
            args.set_timeout_secs(self.http.timeout_secs);
        }
        if from_default("insecure") {
            args.set_insecure(self.http.insecure);
        }
        args
    }
}

/// Args structs that carry HTTP-layer settings (timeout, insecure)
/// implement this trait so [`WafRiftConfig::apply_http_defaults`]
/// can fill them from `.wafrift.toml` without per-command code.
pub(crate) trait HasHttpConfig {
    fn set_timeout_secs(&mut self, secs: u64);
    fn set_insecure(&mut self, insecure: bool);
}

impl HasHttpConfig for crate::detect_cmd::DetectArgs {
    fn set_timeout_secs(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }
    fn set_insecure(&mut self, insecure: bool) {
        self.insecure = insecure;
    }
}

impl HasHttpConfig for crate::attack_cmd::AttackArgs {
    fn set_timeout_secs(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }
    fn set_insecure(&mut self, insecure: bool) {
        self.insecure = insecure;
    }
}

impl HasHttpConfig for crate::bench_waf::BenchWafArgs {
    fn set_timeout_secs(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }
    fn set_insecure(&mut self, insecure: bool) {
        self.insecure = insecure;
    }
}

impl HasHttpConfig for crate::diff::body_diff_cmd::BodyDiffArgs {
    fn set_timeout_secs(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }
    fn set_insecure(&mut self, insecure: bool) {
        self.insecure = insecure;
    }
}

impl HasHttpConfig for crate::diff::cache_diff_cmd::CacheDiffArgs {
    fn set_timeout_secs(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }
    fn set_insecure(&mut self, insecure: bool) {
        self.insecure = insecure;
    }
}

impl HasHttpConfig for crate::diff::cors_diff_cmd::CorsDiffArgs {
    fn set_timeout_secs(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }
    fn set_insecure(&mut self, insecure: bool) {
        self.insecure = insecure;
    }
}

impl HasHttpConfig for crate::diff::header_diff_cmd::HeaderDiffArgs {
    fn set_timeout_secs(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }
    fn set_insecure(&mut self, insecure: bool) {
        self.insecure = insecure;
    }
}

// R55 pass-17 I1 (CLAUDE.md §9 WIRING): the six diff subcommands
// below all carry their own `--timeout-secs` / `--insecure` flags but
// were not wired through the trait, so a setting in `.wafrift.toml`
// silently applied to detect/attack/bench/header-diff/body-diff/cache-
// diff/cors-diff and silently DID NOT apply to these six. Trait impls
// + dispatch wiring in main.rs closes the gap.
impl HasHttpConfig for crate::diff::query_diff_cmd::QueryDiffArgs {
    fn set_timeout_secs(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }
    fn set_insecure(&mut self, insecure: bool) {
        self.insecure = insecure;
    }
}

impl HasHttpConfig for crate::diff::h2_diff_cmd::H2DiffArgs {
    fn set_timeout_secs(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }
    fn set_insecure(&mut self, insecure: bool) {
        self.insecure = insecure;
    }
}

impl HasHttpConfig for crate::diff::method_diff_cmd::MethodDiffArgs {
    fn set_timeout_secs(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }
    fn set_insecure(&mut self, insecure: bool) {
        self.insecure = insecure;
    }
}

impl HasHttpConfig for crate::diff::gql_diff_cmd::GqlDiffArgs {
    fn set_timeout_secs(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }
    fn set_insecure(&mut self, insecure: bool) {
        self.insecure = insecure;
    }
}

impl HasHttpConfig for crate::diff::jwt_diff_cmd::JwtDiffArgs {
    fn set_timeout_secs(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }
    fn set_insecure(&mut self, insecure: bool) {
        self.insecure = insecure;
    }
}

impl HasHttpConfig for crate::diff::trailer_diff_cmd::TrailerDiffArgs {
    fn set_timeout_secs(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }
    fn set_insecure(&mut self, insecure: bool) {
        self.insecure = insecure;
    }
}

// R55 pass-18 I1 (CLAUDE.md §9 WIRING): distill and tmin (which
// delegates to distill) both hit the network but were dispatched
// without `apply_http_defaults`, so `.wafrift.toml`'s http.* keys
// silently dropped on the floor, operators with a lab on a
// self-signed cert had no way to make distill work short of passing
// --insecure on every invocation.
impl HasHttpConfig for crate::hunt::distill_cmd::DistillArgs {
    fn set_timeout_secs(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }
    fn set_insecure(&mut self, insecure: bool) {
        self.insecure = insecure;
    }
}

impl HasHttpConfig for crate::tmin_cmd::TminArgs {
    fn set_timeout_secs(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }
    fn set_insecure(&mut self, insecure: bool) {
        self.insecure = insecure;
    }
}

// R55 pass-19 I1 (CLAUDE.md §9 WIRING): bypass-probe ignored
// `.wafrift.toml`'s http.* keys silently, every other reachable
// subcommand consumes them.
impl HasHttpConfig for crate::replay::ReplayArgs {
    // R68 pass-21: pre-fix `wafrift replay` was the only network
    // subcommand without a HasHttpConfig impl; its dispatch in main.rs
    // never called apply_http_defaults so `.wafrift.toml` http.timeout
    // and http.insecure were silently ignored on every replay
    // invocation. Surface from Coherence R2 audit.
    fn set_timeout_secs(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }
    fn set_insecure(&mut self, insecure: bool) {
        self.insecure = insecure;
    }
}

impl HasHttpConfig for crate::bypass_probe::BypassProbeArgs {
    fn set_timeout_secs(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }
    fn set_insecure(&mut self, insecure: bool) {
        self.insecure = insecure;
    }
}

// R56 pass-20 I1 (CLAUDE.md §9 WIRING): discover was the last
// network-capable subcommand that ignored `.wafrift.toml` http.*
// keys. Added --timeout-secs / --insecure flags to DiscoverArgs
// and wire them through apply_http_defaults here.
impl HasHttpConfig for crate::discover_cmd::DiscoverArgs {
    fn set_timeout_secs(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }
    fn set_insecure(&mut self, insecure: bool) {
        self.insecure = insecure;
    }
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
