/- Crate-specific assumptions (ASSUMED axioms about this crate's types, and the opaque
append helper with its ASSUMED bound). Crate-side:
they mention crate types, so they cannot be in the `-extra-includes` modules (those are
imported by `Types.lean`). Imported by `FunsExternal.lean`, hence visible from `Funs.lean`
on. Every proof using one shows it in `#print axioms`. -/
import TlsCodec.Extraction.Types
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM

namespace CoreModels

/-- ASSUMED: `U24` is `struct U24([u8; 3])` without `#[repr]`, so Rust does not
    guarantee its size; rustc lays it out in 3 bytes. -/
axiom core.mem.size_of_U24 : core.mem.size_of tls_codec.U24 = ok 3#usize

end CoreModels

/-! ## Length-sum helpers (`lib.rs`)

`tls_codec::len_add` (`a.saturating_add(b)`) and `tls_codec::checked_len_add`
(`a.checked_add(b).ok_or(InvalidVectorLength)`) are extracted (one definition on every
target); their specs `len_add_spec` / `len_add_spec_sat` /
`checked_len_add_spec` are theorems in `Verification/Helpers.lean`. No assumption here. -/

/-! ## Append helper of the derived serializers (`lib.rs`)

`tls_codec::append_bytes` is opaque (`hax.toml`): `tls_codec_derive`'s serializers append each
field's bytes through it. Rust: `fn append_bytes(out: &mut Vec<u8>, mut bytes: Vec<u8>) ->
Result<(), Error> { out.append(&mut bytes); Ok(()) }` (always `Ok`; an `append` past the
allocation limit would panic instead). Signature exactly as in
`Extraction/FunsExternal_Template.lean` (the second component is `out` after the call). -/

/-- [tls_codec::append_bytes] (opaque, `hax.toml`). -/
axiom append_bytes
  : alloc.vec.Vec Std.U8 → alloc.vec.Vec Std.U8 →
    RustM ((core.result.Result Unit tls_codec.Error) × (alloc.vec.Vec Std.U8))

/-- ASSUMED: `append_bytes out b` is the checked concatenation: `Ok ()` with `out ++ b` when the
    result fits in a `Vec` (`Usize.max` elements), `Err InvalidVectorLength` with `out` unchanged
    otherwise. For the Rust (always `Ok`) it agrees whenever the concatenation fits, i.e. it
    assumes an `append` of in-memory vectors never exceeds `usize` (allocations are bounded by
    `isize::MAX`: both operands are owned, unaliased buffers). The model
    allows vectors of length `Usize.max`, so an unconditional `Ok` would be inconsistent;
    `Err` takes the place of Rust's capacity-overflow panic. Consistent: `append_bytes` is an
    opaque constant, and the function defined by these two cases satisfies the axiom. -/
axiom append_bytes_spec (out b : alloc.vec.Vec Std.U8) :
  ((out : Slice Std.U8).val.length + (b : Slice Std.U8).val.length ≤ Usize.max →
     ∃ v : alloc.vec.Vec Std.U8, append_bytes out b = ok (.Ok (), v) ∧
       (v : Slice Std.U8).val = (out : Slice Std.U8).val ++ (b : Slice Std.U8).val) ∧
  (Usize.max < (out : Slice Std.U8).val.length + (b : Slice Std.U8).val.length →
     append_bytes out b = ok (.Err tls_codec.Error.InvalidVectorLength, out))

/-! ## Platform width -/

/-- ASSUMED: `usize` is 64 bits (needed by the `U24` / `U32`
    cases). The crate is used on 64-bit targets; CoreModels'
    `usize` `from_be_bytes` / `to_be_bytes` work on 8 bytes while the ASSUMED
    `size_of_Usize` follows `numBits`, so the `U24` conversions need this.
    Consistent: `System.Platform.numBits` is defined from an `opaque` (`getNumBits`). -/
axiom numBits_eq_64 : System.Platform.numBits = 64
