#!/bin/bash
# Constant-time regression check (research preview).
#
# Builds the `ct-disasm` wrapper crate at release optimization, dumps the
# emitted assembly via `rustc --emit=asm`, and reports per-wrapper
# conditional-branch counts. The wrapper crate places `#[inline(never)]`
# `extern "C"` shims around the public `base16ct` / `base32ct` / `base64ct`
# encode/decode entry points so that the `#[inline(always)]` CT-critical
# helpers (`decode_nibble`, `decode_5bits`, `decode_6bits`, `is_pad_ct`)
# get inlined into our wrapper, where the asm scanner can see them.
#
# IMPORTANT — current limitation:
# The reported branch count includes BOTH genuine data-dependent branches
# AND panic-trampoline branches that LLVM emits for things like bounds
# checks and integer overflow checks on cold paths. Filtering the latter
# out automatically requires walking the asm CFG to identify which targets
# are panic blocks. This prototype does NOT do that. Use the script as:
#
#   1. Baseline: run it once on a known-good revision, snapshot the per-
#      wrapper counts (`./check.sh --baseline > baseline.txt`).
#   2. Regression gate: rerun and diff against the baseline. Any *increase*
#      in count, or change in branch-target structure, warrants manual
#      asm review.
#
# Usage:
#   ./check.sh                           # report counts
#   ./check.sh --baseline                # machine-readable counts
#   ./check.sh --baseline > b.txt
#   diff b.txt baseline.txt              # regression gate

set -euo pipefail
cd "$(dirname "$0")"

MODE="report"
TARGET=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --baseline) MODE="baseline"; shift ;;
        --target)   TARGET="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

if [[ -z "$TARGET" ]]; then
    HOST_OS=$(uname -s)
    HOST_ARCH=$(uname -m)
    case "${HOST_OS}-${HOST_ARCH}" in
        Darwin-arm64)   TARGET="aarch64-apple-darwin" ;;
        Darwin-x86_64)  TARGET="x86_64-apple-darwin" ;;
        Linux-aarch64)  TARGET="aarch64-unknown-linux-gnu" ;;
        Linux-x86_64)   TARGET="x86_64-unknown-linux-gnu" ;;
        *) echo "unknown host: ${HOST_OS}-${HOST_ARCH}; pass --target" >&2; exit 2 ;;
    esac
fi

case "$TARGET" in
    aarch64-*|arm64-*) ISA="arm64" ;;
    x86_64-*)          ISA="x86" ;;
    *) echo "unsupported target $TARGET" >&2; exit 2 ;;
esac

# Conditional branches only (no unconditional jumps, no conditional moves).
case "$ISA" in
    arm64)
        BRANCH_REGEX='b\.(eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)|cbz|cbnz|tbz|tbnz'
        ;;
    x86)
        BRANCH_REGEX='j(e|ne|z|nz|l|le|g|ge|a|ae|b|be|c|nc|o|no|p|np|s|ns|cxz|ecxz|rcxz)'
        ;;
esac

DEPS_DIR="../../target/$TARGET/release/deps"
rm -f "$DEPS_DIR"/ct_disasm-*.s 2>/dev/null || true
touch src/lib.rs
cargo rustc --release --target "$TARGET" --quiet -- --emit=asm

ASM_FILE=$(find "$DEPS_DIR" -maxdepth 1 -name 'ct_disasm-*.s' | head -n1)
if [[ -z "$ASM_FILE" || ! -f "$ASM_FILE" ]]; then
    echo "FAIL: could not locate emitted asm under $DEPS_DIR" >&2
    exit 1
fi

# Wrapper symbol names — keep in sync with src/lib.rs.
WRAPPERS=(
    ct_disasm_base16_lower_decode
    ct_disasm_base16_lower_encode
    ct_disasm_base16_upper_decode
    ct_disasm_base16_upper_encode
    ct_disasm_base16_mixed_decode
    ct_disasm_base32_lower_decode
    ct_disasm_base32_lower_encode
    ct_disasm_base32_upper_decode
    ct_disasm_base64_padded_decode
    ct_disasm_base64_padded_encode
    ct_disasm_base64_unpadded_decode
)

if [[ "$MODE" == "report" ]]; then
    echo "=== ct-disasm: target=$TARGET isa=$ISA ==="
    echo "asm: $ASM_FILE ($(wc -l <"$ASM_FILE") lines)"
fi

for W in "${WRAPPERS[@]}"; do
    # Mach-O prefixes symbols with `_`. Try both.
    BODY=$(awk -v sym="$W" '
        BEGIN { in_body = 0 }
        # Match either `<sym>:` or `_<sym>:` at the start of a line.
        $0 ~ ("^_?" sym ":$") { in_body = 1; next }
        # Stop on .cfi_endproc — emitted by both Mach-O and ELF assemblers
        # at the end of every function. This is more reliable than scanning
        # for the next label, since the asm contains many local debug
        # labels (Lfunc_begin0, Ltmp1, etc.) inside a function body.
        in_body && /\.cfi_endproc/ { in_body = 0 }
        in_body { print }
    ' "$ASM_FILE")

    if [[ -z "$BODY" ]]; then
        echo "WARN: $W not found in asm" >&2
        continue
    fi

    COUNT=$(printf '%s\n' "$BODY" | grep -cE "(^|[[:space:]])($BRANCH_REGEX)([[:space:]]|$)" || true)
    LINES=$(printf '%s\n' "$BODY" | wc -l | tr -d ' ')

    if [[ "$MODE" == "baseline" ]]; then
        printf '%s\t%s\t%s\n' "$W" "$COUNT" "$LINES"
    else
        printf '  %-40s  branches=%-3s  lines=%s\n' "$W" "$COUNT" "$LINES"
    fi
done
