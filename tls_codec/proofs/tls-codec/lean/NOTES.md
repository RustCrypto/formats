# tls-codec: notes

Lean project (package `TlsCodec`, scenario `tls-codec` of `../../../hax.toml`) extracted with
aeneas' trait-level specs from the crate. Targets in `PROOF_TARGETS.md`.

## Build

    lake build        # from this directory

Default target `TlsCodec` (`TlsCodec.lean`) = `Extraction` + `Verification/ProofObligations` (and so
PF / FC / Helpers). `Extraction/ProofObligations.lean` (the lean-comparator "challenge") is not
imported; check it separately. One `declaration uses sorry` warning is expected: the OPEN
`Error.Insts.CoreConvertFromError.from_spec.panic_freedom` (`PanicFreedom.lean`):
false in Rust for an `io::Error::Custom` whose payload's `Debug` fails; proved for the errors
lawful readers produce (`Helpers/ErrorFrom.lean`).

Audit status (`scripts/Audit.lean`): all 281 function specs proved (PF / FC / PO 281 / 281);
per-impl `Lawful`: LPF 580 / 581, LFC 382 / 382, LAW 655 / 656. The one open obligation is that
`from_spec.panic_freedom`, so 2 theorems are not clean: it and `Error.Insts.CoreConvertFromError.Lawful`.

## Layout

| File | Content | Who edits |
|---|---|---|
| `Extraction/*.lean` | aeneas output (`Types`, `Funs`, `Specs`, `ProofObligations`, `*External`, templates) | generated; only `scripts/post_extract.sh` patches it (module wrappers, one aeneas bug) |
| `Assumptions/MissingCoreModels.lean` | CoreModels gaps (defs where the Rust semantics is certain: `String`, `Vec::extend`, `FromUtf8Error`, ...; signature-only axioms otherwise), the 22 core `Lawful` stubs. Crate-independent, `-extra-includes` | hand |
| `Assumptions/MissingCoreModelsSpecs.lean` | Specs of core functions: proved specs (`@[spec]`), core `Lawful` lemmas (`PartialEq`, `AsRef`), `slice::Iter::any`. No axiom (its header lists every `Assumptions/` axiom). Crate-independent; imported by `Verification/Helpers/Base.lean` only | hand |
| `Assumptions/FmtAssumptions.lean` | the one ASSUMED `fmt` spec (`FromUtf8Error`'s `Display`) | hand |
| `Assumptions/MissingThirdPartyModels.lean` | `zeroize::Zeroize`, its `Vec` impl, its `Lawful` stub; `DefaultIsZeroes` (+ `u8`), the blanket `Zeroize`, `ZeroizeOnDrop` (+ `Lawful`). `-extra-includes` | hand |
| `Assumptions/CrateAssumptions.lean` | ASSUMED crate facts: `size_of_U24`; the opaque `append_bytes` with its ASSUMED spec | hand |
| `Assumptions/FunsExternal.lean`, `TypesExternal.lean` | crate `fmt` axioms, `write_hex`; hand-translated bodies of `get_content_lengths` x4, `<&[T]>::tls_serialize_bytes`, `<Box<T>>::tls_deserialize_bytes`, with verbatim copies `tls_codec.Copied.*` of the crate functions they call | hand |
| `Verification/Helpers.lean` + `Verification/Helpers/*.lean` | bytes-path helpers, one module per topic in dependency order (`Base` → `BigEndian` → … → `RoundTripBase`; `Helpers.lean` imports the last): `len_add` / `checked_len_add` triples, `Copied.*_eq`, intermediate specs, the generic `TlsVecGen` / `TlsByteVecGen` families, content lemmas; plus `RoundTrip`, `DeserializeSuffix`, `ErrorFrom` | hand |
| `Verification/Std/*.lean` | `std`-path helpers: `Io` (reader / writer laws) → `Bridge` (contracts ↔ behaviour) → per-codec files (`VarInt`, `VarIntDe`, `VLBytes`, `Containers`, `VecSer`, `VecRoundTrip`, `TlsVec`, ...); `SecretFrom` (for OpenMLS), `Agree` (`DecodersAgree` / `RoundTripMixed`: the decoders of `u8`..`u64`, `[u8; N]`, `VLBytes`, `SecretVLBytes`, `Vec<T>` agree) | hand |
| `Verification/Derive/*.lean` | tactics for downstream crates: `Bytes` (derived bytes impls, `RoundTrip`, `PartialEq`), `Std` (derived `std` impls), `HandWritten` (hand-written codecs), `HandWrittenReader` (hand-written bytes decoders returning the reader slice), `RoundTripStd` (`std` round trip of composed codecs, `derive_rt_std`), `DecodersAgree` (agreement of the `std` and byte-slice decoders of composed codecs: `seqStd` / `seqB` chains, `enum_agree_vcs` / `enum_bindep`, `AgreeF.via`), `SimpAttr` | hand |
| `Verification/PanicFreedom.lean` | PF theorems | generated once, proofs by hand |
| `Verification/FunctionalCorrectness.lean` | FC theorems | generated once, proofs by hand |
| `Verification/ProofObligations.lean` | every obligation, rebuilt from PF + FC | generated, never edited |
| `Tools/AxiomGate.lean` | `#axiom_gate` (run by `scripts/AxiomGate.lean`) | hand |

Every assumed item lives in `Assumptions/`, never in `Verification/`. The `Assumptions/` modules
`MissingCoreModels` and `MissingThirdPartyModels` are imported into every generated file through aeneas'
`-extra-includes` (`aeneas-args` in `hax.toml`); they are compiled before `Extraction/Funs.lean`, so crate
functions are not visible there (hence the `Copied` copies). `MissingCoreModelsSpecs` is only for proofs:
`Verification/Helpers/Base.lean` imports it, so the generated files (and the comparator challenge
`Extraction/ProofObligations.lean`) do not see its ASSUMED axioms or `@[spec]` lemmas.

Two kinds of obligations (`Extraction/ProofObligations.lean`):
- 281 function specs `X.spec.proof`: halves `X.spec.panic_freedom` (`⇓ _ => True`) and
  `X.spec.functional_correctness` (`⇓?`, generated post). Generic ones carry `…InstLawful`
  hypotheses (the trait contracts of their instance arguments): use `TInstLawful.m_spec` as an
  `mvcgen` spec (e.g. `mvcgen [f, DeserializeBytesInstLawful.tls_deserialize_bytes_spec]`, or
  `have hs := fun x => Inst.m_spec x (pre_holds_of_ok_true rfl)` then `mvcgen [f, hs]`).
- 656 per-impl `I.Lawful : Trait.Lawful T I`. For every method field `m_spec`, the halves
  `I.m_spec.panic_freedom` / `I.m_spec.functional_correctness`, stated with the impl's method
  (`I.m`, or the projection `(I …).m` for a trait default) and without the `ok true` `pre`.
  `Size.tls_serialized_len_spec` (post `true`) and `Clone.clone_spec` have PF only. Parent
  fields (`SizeInstLawful`) come from the parent impl's `Lawful`; field-less stubs are `⟨⟩`.

Proofs go in the PF and FC halves; `X.spec.proof` / `I.Lawful` then hold with no further
work. Glue in `Verification/ProofObligations.lean`: `triple_of_panic_freedom_of_functional_correctness`,
`triple_of_panic_freedom_of_post_holds` and the macros `pf_fc_combine`, `pf_only_combine`,
`lawful_parent`, `lawful_hyp`.

Notation (Lean core `Std.Do`): `⇓ r => Q` is `PostCond.noThrow` (terminates with `ok`, and `Q`);
`⇓? r => Q` is `PostCond.mayThrow` (if it returns `ok r`, then `Q`). For `RustM`, "throw" covers
both `fail` and `div`.

## Scripts (`scripts/`)

| Script | Use |
|---|---|
| `classify_targets.py` | recomputes the obligation lists of `PROOF_TARGETS.md` (between its `BEGIN/END TARGETS` markers; known-false notes copied after `--`) |
| `gen_verification.py` | generates `Verification/`; reads `Extraction/{Specs,ProofObligations,Funs}.lean`, the `Assumptions/Missing*Models.lean` `Lawful` structures and `PROOF_TARGETS.md` (keep its row format) |
| `Audit.lean` | axiom audit (below); writes `audit_*_clean.txt` |
| `audit_compare.py BASELINE_DIR` | lost / gained / axiom-set-changed theorems against saved `audit_*_clean.txt`; exit 1 on regression |
| `decl_tool.py show\|rm FILE NAME…` | print / delete top-level declarations (with doc comment and attribute) by name |

## Regenerating after re-extraction

`cargo hax extract` (scenario `tls-codec`, run from the crate directory `tls_codec/`) overwrites
`TlsCodec/Extraction/`; proofs written there are lost, so keep them under `Verification/`. Then:

    sh scripts/post_extract.sh                   # module-wrapper and aeneas-bug patches
    python3 scripts/classify_targets.py          # PROOF_TARGETS.md lists
    python3 scripts/gen_verification.py --merge   # keeps proofs, by theorem name

`--merge` regenerates every statement and keeps each existing proof body by theorem name, plus extra
`import` lines; it lists theorems whose statement changed (flagging proved ones: re-check with
`lean_build`). It refuses (writes nothing) if a proved theorem would disappear or if PF / FC contain
non-generated top-level lines (keep lemmas in `Helpers.lean`); an `attribute [local …] … in` line
directly above a theorem is kept with it. Without a flag the script refuses to overwrite files that
contain proofs; `--force` drops all proofs. `ProofObligations.lean` is always regenerated.

## Checking

- Audit: open `scripts/Audit.lean` with `lean_diagnostic_messages` after `lean_build`; it prints the
  counts per group (`PF`, `FC`, `PO` function specs; `LPF`, `LFC` Lawful fields; `LAW` per-impl
  `Lawful`, per trait) and writes `scripts/audit_*_clean.txt` (clean theorems with their non-standard
  axioms). Expected non-standard axioms: the `Assumptions/` ones (fmt ASSUMED no-fail, `size_of*`,
  `numBits_eq_64`, `append_bytes(_spec)`, fmt / hash / zeroize signatures reached by statements)
  and the extraction's own `…tls_deserialize_bytes_loop.body._native.decide.ax_*`.
- Regression gate: save `scripts/audit_*_clean.txt` before a refactor, then
  `python3 scripts/audit_compare.py <saved dir>` after the audit.
- `lean_verify` needs the `tls_codec.` prefix on names.

## Proving

- Work on the PF / FC theorems; do not edit `Verification/ProofObligations.lean`.
- PF is a `noThrow` triple: every reachable call must succeed, including calls to signature-only axioms
  on error paths, which is impossible for them. FC (`⇓?`) says nothing about failing calls, but a
  signature-only axiom returning `ok` still has no spec.
- Core specs rule (`Assumptions/MissingCoreModelsSpecs.lean`): **proved => `@[spec]`, sorried => no
  attribute**. When you prove one, tag it after `lean_verify` shows no `sorryAx`. A sorried one is used
  only by opt-in (`mvcgen [f, CoreModels.core.option.Option.is_some_spec]`, or
  `attribute [local spec] … in`), so `sorryAx` appears in `#print axioms` exactly for proofs relying on an
  unproved spec. Do not unfold CoreModels defs in proofs: prove the core spec once and `mvcgen [f]`.
- `mvcgen` picks the generic `@[spec]` over a specialised one unless the latter is `@[spec high]`;
  nothing warns. A `match` in a spec post elaborates to its own anonymous matcher and no `simp` lemma can
  target it: state results with a named def (the `tryCF` pattern). Characterisation lemmas stay untagged
  (tagging one changes the VCs of the proof of the function it describes); consumers pass them explicitly.
- `pre.holds` hypotheses: `hax_mvcgen [f, <crate defs called by the pre>]` (instead of
  `intro; mvcgen [f]`); a callee without `@[spec]` fails fast naming it. Then `scalar_tac`.
- `?` on `Result`: `mvcgen [f]` leaves one `Break` VC per `?`; `try_vcs [crate From impl defs]` closes them
  (Helpers). `Vec` / slice indexing has direct specs (`index_usize_spec`, `@[spec high]`). FC arithmetic:
  `fc_arith`. `scalar_tac` does not see through `decide (a = b) = true`: `simp only [decide_eq_true_eq]` first.
- `mvcgen` rejects applied terms in its list. It always applies the built-in `Aeneas.Std.loop_spec` to an
  inline `loop` (local hypotheses and `attribute [-spec]` do not stop it, and a restated lambda never matches
  the def's: each `match` has its own matcher constant). Working patterns: a loop lemma generic in the body
  plus `triple_bind_of_total`, `mvcgen [-Aeneas.Std.loop_spec, h]`, or `attribute [local spec high] lemma in`.
- Per-width families (`TlsVecU*`, `SecretTlsVecU*`, `TlsSliceU*`, `TlsByteVecU*`): generic lemmas
  `TlsVecGen` / `TlsByteVecGen` in Helpers, linked to each width by `rfl`; a new width is an `rfl` link plus
  corollaries. `rfl` links fail on matchers applied to a variable (different `match_n` constants): `cases` on
  the scrutinee first. Never write a `toStr` literal in Helpers (default `decide +native` proof = new axiom):
  quantify it existentially and let `rfl` unify it.
- `Vec` / `Slice` / `Iter` are distinct defs at instance transparency: `rw` / `simp` with `deref` / `iter`
  equations fails unless the RHS re-packs (`⟨v.val, v.property⟩`), then `erw [bind_tc_ok]`.
- 64-bit `usize`: the PF of the 6 U24 / U32 `TlsByteVecU*` serializer / `byte_vec_*_encode_decode`
  targets (U24: `usize::from(U24)`; U32: `written + len`) and the U24 conversions are proved under the
  ASSUMED `numBits_eq_64`. (The `get_content_lengths` `debug_assert!` is gated by `#[cfg(not(hax))]`.)
  `len_add` / `checked_len_add` are extracted; their specs are theorems.

## Tooling gotchas

- `lean_build` is needed after every Helpers change before PF / FC see it, and shows only the first error
  per declaration; use `lean_diagnostic_messages` (retry with `timeout_s` after an edit if it answers "Lean
  did not finish").
- `lean_multi_attempt` mis-parses multi-line snippets; `lean_goal` / `lean_multi_attempt` output is huge
  after `mvcgen`, so targeted `lean_diagnostic_messages` is cheaper.
- `rename_i` lists are fragile (inaccessible hypotheses, order shifts after `simp … at *` / `subst_vars`);
  prefer a Helpers lemma stating the whole behaviour and a short consumer.
- `simp_all` can hit max recursion on goals with two `↑x = ↑y` hypotheses.

## `std` feature

The scenario extracts `features = ["mls", "std"]` (what OpenMLS builds). `std::io` models are
in `Assumptions/MissingCoreModels.lean` ("`std::io`" section: `ErrorKind`, `io::Error` (kind only),
`Write` / `Read` structures, `Write for Vec<u8>`, `Read for &[u8]`, `&mut R`, `Take`,
`take` / `read_to_end` / `default_read_exact`, `new_debug`; all `def`s except the `Debug` `fmt` of
`io::Error`), with field-less `Write.Lawful` / `Read.Lawful` (contracts: `spec.rs`, module `io`).
`Assumptions/FunsExternal.lean` "`std` feature" section: the hand-translated `try_fold` sums
(`checked_len_fold`, `get_content_lengths_std`, 16 per-impl one-liners,
`quic_vec.rw.checked_content_length`) and the `SecretVLBytes` / `SecretVLByteVec` accessors
(an aeneas bug, see `hax.toml`). After every extraction run `scripts/post_extract.sh` (it refuses if
the number of patched sites changes). cargo-hax 721d1a27 needs `hax-lib` 0.4.2 in `Cargo.lock`.
