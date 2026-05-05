# ct-disasm — constant-time disassembly check (research preview)

A regression-detection tool for the constant-time hot paths in `base16ct`,
`base32ct`, and `base64ct`. Compiles a small wrapper crate that drives each
crate's public encode/decode API on a fixed-length buffer, dumps the
emitted assembly via `rustc --emit=asm`, and reports per-wrapper
conditional-branch counts. Designed to be diffed against a snapshotted
baseline as a CI gate.

## Why this exists

The CT-critical inner functions (`decode_nibble`, `decode_5bits`,
`decode_6bits`, `is_pad_ct`) are `#[inline(always)]` and not exported.
Checking them in isolation isn't useful — what matters is what they look
like *after* LLVM has inlined them into the public API path that real
callers use. This crate places `#[inline(never)]` `extern "C"` shims around
those public APIs, with input/output buffers sized as compile-time
constants, so length-dependent branches in the public API collapse and
the asm scanner sees the actual inlined CT machinery.

A constant-time-analysis audit of these crates (Trail of Bits) confirmed
the source-level CT idioms are correct. This tool exists to catch
**compiler regressions** — a future LLVM that decides to lower one of the
arithmetic-mask idioms back into a branch.

## Usage

```sh
# Native target (auto-detects):
./check.sh

# Explicit target (requires `rustup target add <triple>`):
./check.sh --target x86_64-unknown-linux-gnu

# Machine-readable output for use as a baseline / regression diff:
./check.sh --baseline > baseline.txt
git diff baseline.txt   # any change → manual review
```

No external tools beyond a Rust toolchain plus standard `awk` / `grep` /
`find` / `sed`.

## Current baseline (aarch64-apple-darwin, rustc 1.85)

```text
ct_disasm_base16_lower_decode             branches=0    lines=164
ct_disasm_base16_lower_encode             branches=0    lines=43
ct_disasm_base16_upper_decode             branches=0    lines=164
ct_disasm_base16_upper_encode             branches=0    lines=43
ct_disasm_base16_mixed_decode             branches=0    lines=225
ct_disasm_base32_lower_decode             branches=20   lines=426
ct_disasm_base32_lower_encode             branches=0    lines=252
ct_disasm_base32_upper_decode             branches=20   lines=426
ct_disasm_base64_padded_decode            branches=14   lines=369
ct_disasm_base64_padded_encode            branches=0    lines=30
ct_disasm_base64_unpadded_decode          branches=3    lines=516
```

Reading this:

* **`branches=0` is the strongest signal.** Five of `base16ct`'s wrappers
  and two of `base64ct`/`base32ct`'s are fully branch-free at the chosen
  fixed size. Any future regression that flips one of these to nonzero
  is a CT-violation candidate that needs immediate review.
* **`branches > 0` does NOT mean a CT bug exists today.** The remaining
  branches are length-dependent (chunk-loop iteration boundaries,
  `if src_rem.len() >= N` tail handling) or panic-trampoline branches
  (bounds checks LLVM didn't fold). The crate documentation explicitly
  states timing depends on message *length*, not content. The number is
  a fingerprint of how LLVM chose to lower the code.
* **The metric is whether the count, and the structure of branch targets,
  changes between revisions.** A toolchain bump that drops 20 branches
  to 18 is fine. A source change that turns 0 into 1 demands review. A
  source change that turns 14 into 14 with different target labels also
  demands review (LLVM may have rewritten the same control flow into
  different but equivalent shape — or it may have introduced a new
  data-dependent branch).

## Layout

* `src/lib.rs` — `#[no_mangle] extern "C"` shims around the public APIs.
  Buffer sizes are fixed at compile time and inputs/outputs are routed
  through `core::hint::black_box` to anchor the optimizer.
* `check.sh` — bash script: builds, locates the emitted `.s`, scans each
  wrapper body delimited by `.cfi_endproc`, counts conditional branches.
* `Cargo.toml` — workspace member; depends on the three CT crates as
  in-tree path deps.

## Known limitations

1. **Length-dependent and panic-trampoline branches are counted.** These
   are not CT bugs. To filter them out automatically the script would
   need to walk the asm CFG and identify branch targets that are panic
   blocks (`bl ___rust_alloc_error_handler`, `udf`, `brk`, etc.) or
   non-cold loop-iteration blocks. Out of scope for this preview.
2. **Conditional moves (`cmov` / `csel`) are not flagged.** They're
   branch-free at the pipeline level. If a hyper-strict posture is
   wanted, extend `BRANCH_REGEX` in `check.sh`.
3. **Memory-access-pattern leaks aren't caught.** A function that
   indexed a table by a secret byte would still register as
   `branches=0` here. The audited crates avoid such patterns by
   construction; this tool doesn't reverify that.
4. **Some `base64ct` variants aren't wrapped** (`Base64Url`,
   `Base64Bcrypt`, `Base64Crypt`, `Base64ShaCrypt`, `Base64Pbkdf2`).
   They share the `Alphabet::decode_6bits` / `encode_6bits` machinery
   with `Base64`, so the existing wrappers transitively exercise the
   same code. If a variant ever diverges, add a wrapper.
5. **Not yet wired into CI.** To promote, add a step that runs
   `./dev-tools/ct-disasm/check.sh --baseline | diff - baseline.txt`
   and fails on any non-empty diff.

## Suggested next steps

* Snapshot a `baseline.{aarch64,x86_64}.txt` on a known-good revision and
  commit it. Add a CI step that diffs the two.
* Add panic-target filtering to `check.sh` so it can become a true
  pass/fail gate rather than a baseline-diff gate.
* Extend the wrapper list to `serdect` once that crate's public API is
  also fixed-length-callable.
