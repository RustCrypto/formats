/- Missing third-party models: items of third-party crates the extraction references
(not part of CoreModels). Crate-independent, imported into every generated file by
`-extra-includes`. -/
import Aeneas
import CoreModels
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.unusedVariables false

/-! Hand-written model (not generated): the third-party trait `zeroize::Zeroize`
    (zeroize 1.9, `pub trait Zeroize { fn zeroize(&mut self); }`).
    Encoded the way aeneas encodes traits: a structure with one field per
    method; the `&mut self` method returning `()` becomes `Self → RustM Self`
    (same shape as aeneas' `core.ops.drop.Drop`). -/
structure zeroize.Zeroize (Self : Type) where
  zeroize : Self → RustM Self

/-- Hand-written (not in the generated template): model of the third-party impl
    [zeroize::{impl zeroize::Zeroize for alloc::vec::Vec<Z>}::zeroize]
    (zeroize 1.9, src/lib.rs 520:0-538:1), referenced by the `Zeroize` impls of
    `tls_vec.SecretTlsVecU*` in Extraction/Funs.lean. Left opaque: the real
    function zeroizes the elements and leaves the vector empty. -/
axiom zeroize.alloc.vec.Vec.Insts.ZeroizeZeroize.zeroize
  {Z : Type} (zeroizeZeroizeInst : zeroize.Zeroize Z) :
  alloc.vec.Vec Z → RustM (alloc.vec.Vec Z)

/-- `Lawful` structure of the third-party trait `zeroize::Zeroize` (no field; see
    the core stubs in `MissingCoreModels.lean`). -/
structure zeroize.Zeroize.Lawful (Self : Type) (ZeroizeInst : zeroize.Zeroize Self) : Prop where

/-! ### `zeroize` items reached by the `std` extraction -/

/-- [zeroize::DefaultIsZeroes] (`pub trait DefaultIsZeroes: Copy + Default + Sized {}`):
    a marker; only the `Default` parent is used (by the blanket `Zeroize`). -/
structure zeroize.DefaultIsZeroes (Self : Type) where
  DefaultInst : core.default.Default Self

/-- [zeroize::{impl zeroize::DefaultIsZeroes for u8}] -/
@[reducible]
def zeroize.U8.Insts.ZeroizeDefaultIsZeroes : zeroize.DefaultIsZeroes Std.U8 := {
  DefaultInst := core.U8.Insts.CoreDefaultDefault
}

/-- [zeroize::{impl<Z: DefaultIsZeroes> zeroize::Zeroize for Z}]: `zeroize` volatile-writes
    `Z::default()` over `self` (zeroize 1.9, src/lib.rs), so the new value is the default. -/
@[reducible]
def zeroize.Zeroize.Blanket {Z : Type} (DefaultIsZeroesInst : zeroize.DefaultIsZeroes Z) :
  zeroize.Zeroize Z := {
  zeroize := fun _ => DefaultIsZeroesInst.DefaultInst.default
}

/-- [zeroize::ZeroizeOnDrop]: a marker trait (no method). -/
structure zeroize.ZeroizeOnDrop (Self : Type) where

/-- `Lawful` structure of the marker `zeroize::ZeroizeOnDrop` (no field). -/
structure zeroize.ZeroizeOnDrop.Lawful (Self : Type)
  (ZeroizeOnDropInst : zeroize.ZeroizeOnDrop Self) : Prop where
