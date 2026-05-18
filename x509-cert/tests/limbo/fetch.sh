#!/bin/bash
# Fetch the C2SP/x509-limbo `limbo.json` fixture into this directory.
#
# Usage: ./fetch.sh
#
# The fixture is large and is gitignored. The harness in
# `x509-cert/tests/limbo.rs` skips cleanly when it's absent, so running
# `cargo test` without first calling this script is safe — it just won't
# exercise the limbo corpus.
#
# We pin to a specific upstream commit so test results are reproducible
# across machines and time. Bump `LIMBO_SHA` when you want to rebase
# against a newer x509-limbo release.

set -euo pipefail

REPO="C2SP/x509-limbo"
LIMBO_SHA="086b0da8b83d78ed0f491d6df6672b2673406500"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
fixture_path="${script_dir}/limbo.json"

if ! command -v gh >/dev/null 2>&1; then
    echo "error: gh CLI is required" >&2
    exit 1
fi
if ! command -v git >/dev/null 2>&1; then
    echo "error: git is required" >&2
    exit 1
fi

# Verify the pinned SHA still exists upstream before we clone.
if ! gh api "repos/${REPO}/commits/${LIMBO_SHA}" --jq '.sha' >/dev/null 2>&1; then
    echo "error: pinned SHA ${LIMBO_SHA} not found in ${REPO}" >&2
    exit 1
fi

# When run inside a Claude Code session a hook redirects clone targets
# to a session-scoped directory; honor that so we don't conflict with
# other concurrent agents.
if [[ -n "${CLAUDE_SESSION_ID:-}" ]]; then
    tmp_root="${TMPDIR:-/tmp}/gh-clones-${CLAUDE_SESSION_ID}"
    mkdir -p "${tmp_root}"
    clone_dir="${tmp_root}/x509-limbo"
    rm -rf "${clone_dir}"
    trap 'rm -rf "${clone_dir}"' EXIT
else
    clone_dir="$(mktemp -d "${TMPDIR:-/tmp}/x509-limbo.XXXXXX")"
    trap 'rm -rf "${clone_dir}"' EXIT
fi

# Shallow-clone default branch first, then fetch + check out the pinned
# SHA. `--depth 1` alone cannot fetch arbitrary SHAs, so we widen with
# a follow-up `git fetch`.
gh repo clone "${REPO}" "${clone_dir}" -- --depth 1
git -C "${clone_dir}" fetch --depth 1 origin "${LIMBO_SHA}"
git -C "${clone_dir}" checkout --detach "${LIMBO_SHA}"

if [[ ! -f "${clone_dir}/limbo.json" ]]; then
    echo "error: limbo.json missing at pinned SHA — upstream layout change?" >&2
    exit 1
fi

cp "${clone_dir}/limbo.json" "${fixture_path}"
echo "copied ${REPO}@${LIMBO_SHA} limbo/limbo.json to ${fixture_path}"
echo "fixture size: $(wc -c <"${fixture_path}") bytes"
