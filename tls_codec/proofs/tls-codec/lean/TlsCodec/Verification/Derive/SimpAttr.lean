/- Simp sets of `Derive/Bytes.lean` (an attribute must be registered in an earlier module).

Obligations: none.
Axioms reached: none. -/
import Lean

/-- `szv` of the constant-size field types (`szv_U64 : szv U64… x = 8#usize`, …). -/
register_simp_attr szv_simps
