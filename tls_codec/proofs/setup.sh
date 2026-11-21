#!/bin/sh
# Builds the aeneas binary that the hax proof scenarios of tls_codec use:
# `[tools] aeneas = { path = ".hax-tools/aeneas/bin/aeneas" }` in
# `tls_codec/hax.toml` (also used by `tls_codec/std-derive-test/hax.toml`).
#
# The aeneas binary and the aeneas Lean library must come from the same
# revision. The Lean projects require the library from git at AENEAS_REV
# (`lakefile.toml` / `lake-manifest.json`), so this script builds the binary
# from that revision. charon is not built here: hax downloads the version
# pinned in hax.toml.
#
# Usage:   sh tls_codec/proofs/setup.sh
# Result:  tls_codec/.hax-tools/aeneas/bin/aeneas (git-ignored), next to a checkout of
#          cryspen/aeneas at AENEAS_REV.
# Build:   with nix if available (flake output `aeneas`), otherwise with the
#          aeneas Makefile (`make setup-charon build-dev`, needs OCaml / opam
#          and the dependencies listed in the aeneas README).
#          AENEAS_BIN=/path/to/aeneas skips the build and links that binary
#          instead (it must be built from AENEAS_REV).
set -eu

AENEAS_URL=${AENEAS_URL:-https://github.com/cryspen/aeneas}
AENEAS_REV=4aefccc867beefe0e90b2e16279134bf8592e2ff

root=$(cd "$(dirname "$0")/.." && pwd)
dest="$root/.hax-tools/aeneas"

echo "aeneas $AENEAS_REV -> $dest"
if [ ! -d "$dest/.git" ]; then
  mkdir -p "$dest"
  git -C "$dest" init -q
  git -C "$dest" remote add origin "$AENEAS_URL"
fi
if [ "$(git -C "$dest" rev-parse -q --verify HEAD || true)" != "$AENEAS_REV" ]; then
  git -C "$dest" fetch -q --depth 1 origin "$AENEAS_REV"
  git -C "$dest" checkout -q --detach "$AENEAS_REV"
fi

mkdir -p "$dest/bin"
if [ -n "${AENEAS_BIN:-}" ]; then
  echo "using the prebuilt binary $AENEAS_BIN"
  ln -sf "$AENEAS_BIN" "$dest/bin/aeneas"
elif command -v nix >/dev/null 2>&1; then
  nix --extra-experimental-features 'nix-command flakes' \
    build "git+file://$dest?shallow=1#aeneas" --out-link "$dest/result"
  ln -sf ../result/bin/aeneas "$dest/bin/aeneas"
else
  (cd "$dest" && make setup-charon && make build-dev)
fi

"$dest/bin/aeneas" -help >/dev/null 2>&1 || {
  echo "error: $dest/bin/aeneas does not run" >&2
  exit 1
}
echo "ok: $dest/bin/aeneas"
