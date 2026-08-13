#!/usr/bin/env bash
# Publish the workspace version to crates.io in dependency order.
#
# The order is derived from `cargo metadata` at run time, so adding a crate or
# changing an intra-workspace dependency cannot leave a stale hand-written list
# behind. Already-visible versions are skipped, which makes a rerun of a
# partially failed release resume at the first missing package.

set -euo pipefail

if [[ -z "${CARGO_REGISTRY_TOKEN:-}" ]]; then
    echo "error: CARGO_REGISTRY_TOKEN is required" >&2
    exit 2
fi

ROOT="$(cd -P -- "$(dirname -- "$0")/.." && pwd -P)"
cd "$ROOT"

if ! VERSION="$(python3 -B - <<'PY'
import pathlib
import tomllib

document = tomllib.loads(pathlib.Path("Cargo.toml").read_text(encoding="utf-8"))
print(document["workspace"]["package"]["version"])
PY
)"; then
    echo "error: missing workspace.package.version in Cargo.toml" >&2
    exit 2
fi

if ! mapfile -t CRATES < <(python3 -B scripts/publish_order.py --root "$ROOT"); then
    echo "error: cannot derive the workspace publish order" >&2
    exit 2
fi

if (( ${#CRATES[@]} == 0 )); then
    echo "error: no publishable workspace crates found" >&2
    exit 2
fi

crate_visible() {
    python3 -B - "$1" "$VERSION" <<'PY'
import sys
import urllib.error
import urllib.parse
import urllib.request

crate, version = sys.argv[1:]
url = "https://crates.io/api/v1/crates/{}/{}".format(
    urllib.parse.quote(crate, safe=""), urllib.parse.quote(version, safe="")
)
request = urllib.request.Request(url, headers={"User-Agent": "wafrift-release"})
try:
    with urllib.request.urlopen(request, timeout=30) as response:
        raise SystemExit(0 if response.status == 200 else 1)
except urllib.error.HTTPError as error:
    raise SystemExit(1 if error.code == 404 else 2)
PY
}

wait_until_visible() {
    local crate="$1"
    local delay=1
    local elapsed=0
    while ! crate_visible "$crate"; do
        if (( elapsed >= 300 )); then
            echo "error: timed out waiting for $crate $VERSION on crates.io" >&2
            return 1
        fi
        sleep "$delay"
        elapsed=$((elapsed + delay))
        if (( delay < 15 )); then
            delay=$((delay * 2))
            if (( delay > 15 )); then delay=15; fi
        fi
    done
}

publish_crate() {
    local crate="$1"
    local attempt
    local delay=2

    if crate_visible "$crate"; then
        echo "==> $crate $VERSION already published"
        return 0
    fi

    for attempt in 1 2 3; do
        echo "==> publishing $crate $VERSION (attempt $attempt/3)"
        if cargo publish --locked --no-verify --registry crates-io -p "$crate"; then
            wait_until_visible "$crate"
            return
        fi

        # The upload can succeed even when the client loses the response.
        # Visibility makes a rerun idempotent without parsing Cargo's prose.
        if crate_visible "$crate"; then
            echo "==> $crate $VERSION became visible after the failed upload response"
            return 0
        fi
        if (( attempt < 3 )); then
            echo "warning: $crate $VERSION upload failed; retrying in ${delay}s" >&2
            sleep "$delay"
            delay=$((delay * 2))
        fi
    done

    echo "error: failed to publish $crate $VERSION after 3 attempts" >&2
    echo "error: rerun this release workflow; already-visible crates will be skipped" >&2
    return 1
}

for crate in "${CRATES[@]}"; do
    publish_crate "$crate"
done

echo "Published wafrift $VERSION to crates.io (${#CRATES[@]} crates)."
