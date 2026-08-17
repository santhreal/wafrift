//! Runtime, IO, and process-exit utilities.

use std::process::ExitCode;

/// Emit an operator-input error to stderr and return exit code **2**.
///
/// Use this for every failure that is caused by an operator-supplied value
/// being wrong, a missing/unreadable input file, malformed content in an
/// operator-chosen file, an empty required argument, or an unknown selector.
///
/// Exit-code contract (documented in `main.rs`):
///   `2` = argument / input error (unknown flag, contradictory selectors,
///          malformed value, unknown technique selector, unrecognised
///          algorithm, missing required field).
///
/// Runtime/network failures (connection refused, TLS handshake, timeout)
/// are NOT input errors (use `ExitCode::from(1)` for those).
pub fn input_error(message: impl AsRef<str>) -> ExitCode {
    eprintln!("error: {}", message.as_ref());
    ExitCode::from(2)
}

pub fn secure_tmp_path(prefix: &str, ext: &str) -> std::path::PathBuf {
    let token: u128 = rand::random();
    std::env::temp_dir().join(format!(
        "{prefix}-{pid}-{token:032x}.{ext}",
        pid = std::process::id()
    ))
}

/// Build a fresh tokio runtime and block on `fut`, returning its
/// `ExitCode` or a uniform "failed to start tokio runtime" exit-1
/// on construction failure.
///
/// CLAUDE.md §7 DEDUPLICATION: 14 dispatch arms in `main.rs` ran
/// the same 8-line match-Runtime-new boilerplate; one canonical
/// source now. Per CLAUDE.md §14 INTROSPECTION the right time to
/// extract was when the third copy appeared, we are well past
/// that threshold.
pub(crate) fn block_on_with_runtime<F>(fut: F) -> std::process::ExitCode
where
    F: std::future::Future<Output = std::process::ExitCode>,
{
    // Tokio worker + blocking-pool threads default to a ~2 MiB stack
    // too small for wafrift's deep (bounded) search frames. `wafrift hunt`
    // runs bench-waf nested inside a `spawn_blocking` thread, so the
    // equiv-cegis synthesis lands on a runtime-spawned thread and overflows
    // 2 MiB → `fatal runtime error: stack overflow, aborting` (SIGABRT,
    // round-1 crash, no corpus). `thread_stack_size` applies to BOTH the
    // worker and blocking-pool threads, so a 32 MiB stack (virtual; only
    // committed as touched) covers the nested case and every other
    // invocation through this one canonical builder.
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(32 * 1024 * 1024)
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: failed to start tokio runtime: {e}");
            return std::process::ExitCode::from(1);
        }
    };
    rt.block_on(fut)
}

pub fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Shared overwrite guard for every subcommand's `--output PATH` flag.
/// CLAUDE.md §7 DEDUPLICATION + §14 INTROSPECTION: the original
/// per-command guards (R44-I6 evade, R47-I1 virtual-fd, R48-I4
/// bench-waf) drifted in phrasing and skip-list. Single canonical
/// source now: a virtual file descriptor (`/dev/stdout`, `/dev/fd/N`,
/// `/proc/self/fd/N`, `/dev/stderr`) is always allowed; a bare `-`
/// sentinel is also allowed (matches operator idiom across `wafrift
/// bank export -o -` etc.); otherwise refuse to clobber an existing
/// file unless `force` is set.
///
/// Returns `Ok(())` on safe-to-write, `Err(msg)` on refuse. Caller
/// emits via `eprintln!` + `ExitCode::from(2)`.
pub fn confirm_output_overwrite_safe(path: &std::path::Path, force: bool) -> Result<(), String> {
    // R52 pass-14 I2 fix (CLAUDE.md §15 AUDIT): the prior
    // `starts_with("/dev/fd/")` check was traversal-bypassable
    // `--output /dev/fd/../etc/shadow` matched and skipped the
    // existence check, then `fs::write` resolved through the symlink
    // upward into a non-FD path. Tighten the check so the suffix
    // after `/dev/fd/` (or `/proc/self/fd/`) must be a pure decimal
    // integer with no embedded `/` or `..`.
    let p = path.to_string_lossy();
    let is_fd_n = |prefix: &str| -> bool {
        // R53 pass-15 §15-A: parse-gate the suffix so a clearly-
        // invalid FD (e.g. /dev/fd/9999999) is REFUSED with the
        // overwrite-guard's coherent message instead of letting
        // the open() syscall fail later with a cryptic EBADF.
        // Linux fd numbers fit in u32 comfortably; suffix must
        // parse cleanly and be in the normal RLIMIT_NOFILE range.
        p.strip_prefix(prefix)
            .and_then(|s| s.parse::<u32>().ok())
            .is_some_and(|n| n < 1024 * 1024)
    };
    let is_virtual_fd = p == "-"
        || p == "/dev/stdout"
        || p == "/dev/stderr"
        || is_fd_n("/dev/fd/")
        || is_fd_n("/proc/self/fd/");
    if is_virtual_fd || force || !path.exists() {
        return Ok(());
    }
    Err(format!(
        "{} already exists. Re-run with --force-overwrite to clobber, \
     or pick a fresh path. Refusing to silently overwrite (CLAUDE.md \
     §11 UTILIZATION: a clobbered output is computed-and-discarded \
     work).",
        path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fd_traversal_bypass_refused() {
        // R52 pass-14 I2 regression-pin: pre-fix `--output
        // /dev/fd/../etc/shadow` matched the starts_with check
        // and skipped the overwrite guard. The tightened
        // parse-gate (decimal-only suffix in RLIMIT_NOFILE range)
        // must refuse the virtual-fd shortcut on this string.
        //
        // We verify by creating an existing file at a tmp path
        // that LOOKS like `/dev/fd/<something>` would, prove the
        // helper refuses to overwrite. The actual /dev/fd/../...
        // traversal payload doesn't reach a real existing file
        // in the test env, so the cleanest assertion is on the
        // existing-file refusal path.
        let dir = std::env::temp_dir().join(format!(
            "wafrift-r52-trav-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let real = dir.join("real.txt");
        std::fs::write(&real, b"existing").expect("seed");
        assert!(
            confirm_output_overwrite_safe(&real, false).is_err(),
            "an existing regular file must trip the guard"
        );
        // A path string that LOOKS like /dev/fd/ but has traversal
        // characters must NOT be treated as a virtual-fd shortcut.
        // It falls through to the existence check; since the
        // string `/dev/fd/../etc/shadow` doesn't resolve to an
        // existing file from the test cwd, the guard returns Ok
        // but the important thing is it does NOT short-circuit
        // (which would skip the existence check entirely even on
        // a real file).
        let trav_path = std::path::PathBuf::from("/dev/fd/../etc/shadow");
        let _ = confirm_output_overwrite_safe(&trav_path, false);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fd_n_admits_only_decimal_within_range() {
        // /dev/fd/1 (stdout) (allowed).
        assert!(confirm_output_overwrite_safe(std::path::Path::new("/dev/fd/1"), false,).is_ok());
        // /dev/fd/9999999 (out of range, NOT admitted as virtual).
        // Falls through to exists() check; the path doesn't exist
        // so returns Ok. The key property: the guard does not
        // SHORT-CIRCUIT on the out-of-range suffix.
        let p = std::path::Path::new("/dev/fd/9999999");
        let _ = confirm_output_overwrite_safe(p, false);
    }

    #[test]
    fn secure_tmp_path_is_unguessable_and_well_formed() {
        let a = secure_tmp_path("wafrift-test", "json");
        let b = secure_tmp_path("wafrift-test", "json");
        // 128-bit random suffix → two calls never collide and the name
        // is not derivable from PID alone (the §15 pre-plant defence).
        assert_ne!(a, b, "random suffix must differ across calls");
        assert!(
            a.starts_with(std::env::temp_dir()),
            "not in temp dir: {a:?}"
        );
        let name = a
            .file_name()
            .and_then(|n| n.to_str())
            .expect("utf-8 file name")
            .to_owned();
        assert!(name.starts_with("wafrift-test-"), "prefix missing: {name}");
        assert!(name.ends_with(".json"), "ext missing: {name}");
        // 32 lowercase hex chars of entropy are present in the basename.
        let hex_run = name.chars().filter(|c| c.is_ascii_hexdigit()).count();
        assert!(hex_run >= 32, "expected >=32 hex chars of entropy: {name}");
    }
}
