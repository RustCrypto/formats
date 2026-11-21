/- Missing core models: `core` / `alloc` items the extraction references that
CoreModels (hax-lean v0.3.27) does not provide. Crate-independent (imports only
Aeneas and CoreModels), so `-extra-includes` can import it into every generated file.
Specs for these and for existing CoreModels functions: `MissingCoreModelsSpecs.lean`. -/
import Aeneas
import CoreModels
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option linter.unusedVariables false
set_option linter.style.whitespace false
set_option linter.style.setOption false
set_option linter.style.longLine false

/-- Hand-written stopgap (not generated): `alloc::string::FromUtf8Error` is
    referenced by Extraction/Funs.lean but not provided by CoreModels
    (hax-lean v0.3.27).

    Rust: `struct FromUtf8Error { bytes: Vec<u8>, error: Utf8Error }`, private
    fields, built only by `String::from_utf8` from the rejected input. `error`
    (`valid_up_to`, `error_len`) is computed from `bytes` by std's validator, so
    it carries no further information and is left out: `bytes` determines the
    Rust value. -/
structure CoreModels.alloc.string.FromUtf8Error : Type where
  /-- The rejected input (`FromUtf8Error::into_bytes`). -/
  bytes : alloc.vec.Vec Std.U8

/-! ## Hand-written stopgaps for CoreModels gaps (not generated)

Rust `core`/`alloc` items that Extraction/Funs.lean references but that
CoreModels (hax-lean v0.3.27) does not provide. Candidates for upstreaming into
hax's core models. Where the Rust semantics is trivial and certain, the item is
a `def` that follows the Rust implementation; otherwise it is an opaque `axiom`
that only fixes the type. -/

/-- [alloc::string::{impl core::cmp::PartialEq<String> for String}::eq] -/
def alloc.string.String.Insts.CoreCmpPartialEqString.eq
  (self other : alloc.string.String) : RustM Bool :=
  ok (@decide (self = other) (instDecidableEqString self other))

/-- [alloc::string::{impl core::cmp::PartialEq<String> for String}] -/
def alloc.string.String.Insts.CoreCmpPartialEqString :
    core.cmp.PartialEq alloc.string.String alloc.string.String where
  eq := alloc.string.String.Insts.CoreCmpPartialEqString.eq
  ne := fun self other => do
    let b ← alloc.string.String.Insts.CoreCmpPartialEqString.eq self other
    ok (not b)

/-- [alloc::string::{impl core::clone::Clone for String}::clone] -/
def alloc.string.String.Insts.CoreCloneClone.clone
  (self : alloc.string.String) : RustM alloc.string.String :=
  ok self

/-- [alloc::string::{impl core::convert::From<&str> for String}::from]: the
    string whose UTF-8 encoding is the bytes of `s` (aeneas' `Str` is
    `Slice U8`). Rust's `&str` is always valid UTF-8 (building one that is not
    is undefined behaviour), so the `undef` branch has no Rust counterpart;
    `toStr "…"` literals always take the first branch. -/
def alloc.string.String.Insts.CoreConvertFromShared0Str.from
  (s : Str) : RustM alloc.string.String :=
  match String.fromUTF8? ⟨(s.val.map fun b : Std.U8 => UInt8.ofBitVec b.bv).toArray⟩ with
  | some t => ok t
  | none => fail .undef

/-- [alloc::string::{impl core::convert::From<&str> for String}] -/
@[reducible]
def alloc.string.String.Insts.CoreConvertFromShared0Str :
  core.convert.From alloc.string.String Str := {
  «from» := alloc.string.String.Insts.CoreConvertFromShared0Str.from
}

/-- [alloc::string::{String}::from_utf8]: `Ok` with the string whose UTF-8
    encoding is `vec` iff `vec` is well-formed UTF-8, else `Err` carrying `vec`.
    `ByteArray.IsValidUTF8 b` is `∃ cs : List Char, b = cs.utf8Encode` (Lean
    `Char`s are Unicode scalar values, the encoding is the shortest form), which
    is Unicode's well-formed UTF-8 and so Rust's check (no overlong forms, no
    surrogates, nothing above U+10FFFF, no truncated sequence). -/
def alloc.string.String.from_utf8 (vec : alloc.vec.Vec Std.U8) :
  RustM (core.result.Result alloc.string.String alloc.string.FromUtf8Error) :=
  match String.fromUTF8? ⟨(vec.val.map fun b : Std.U8 => UInt8.ofBitVec b.bv).toArray⟩ with
  | some s => ok (core.result.Result.Ok s)
  | none => ok (core.result.Result.Err { bytes := vec })

/-- [alloc::string::{String}::as_bytes]: the UTF-8 encoding of `self`.
    A Rust `String` has at most `isize::MAX` bytes, so the bytes always fit a
    slice. CoreModels' `alloc.string.String` is Lean's unbounded `String`: a model
    string longer than `usize::MAX` bytes has no Rust counterpart, and gets its
    longest prefix that fits (keeping `as_bytes` total, as in Rust). -/
def alloc.string.String.as_bytes (self : alloc.string.String) : RustM (Slice Std.U8) :=
  let l := self.toByteArray.data.toList.map fun b : UInt8 => (⟨b.toBitVec⟩ : Std.U8)
  ok ⟨l.take Usize.max, by simp⟩

namespace CoreModels

/-- [alloc::string::{impl core::fmt::Display for FromUtf8Error}::fmt] -/
axiom alloc.string.FromUtf8Error.Insts.CoreFmtDisplay.fmt :
  alloc.string.FromUtf8Error → core.fmt.Formatter →
  RustM ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter)

/-- [alloc::string::{impl core::fmt::Display for FromUtf8Error}] -/
@[reducible]
noncomputable def alloc.string.FromUtf8Error.Insts.CoreFmtDisplay :
  core.fmt.Display alloc.string.FromUtf8Error := {
  fmt := alloc.string.FromUtf8Error.Insts.CoreFmtDisplay.fmt
}

/-- [core::num::error::{impl core::fmt::Debug for TryFromIntError}::fmt] -/
axiom core.num.error.TryFromIntError.Insts.CoreFmtDebug.fmt :
  core.num.error.TryFromIntError → core.fmt.Formatter →
  RustM ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter)

/-- [core::num::error::{impl core::fmt::Debug for TryFromIntError}] -/
@[reducible]
noncomputable def core.num.error.TryFromIntError.Insts.CoreFmtDebug :
  core.fmt.Debug core.num.error.TryFromIntError := {
  fmt := core.num.error.TryFromIntError.Insts.CoreFmtDebug.fmt
}

/-- [core::convert::{impl core::fmt::Debug for Infallible}::fmt] -/
axiom core.convert.Infallible.Insts.CoreFmtDebug.fmt :
  core.convert.Infallible → core.fmt.Formatter →
  RustM ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter)

/-- [core::convert::{impl core::fmt::Debug for Infallible}] -/
@[reducible]
noncomputable def core.convert.Infallible.Insts.CoreFmtDebug :
  core.fmt.Debug core.convert.Infallible := {
  fmt := core.convert.Infallible.Insts.CoreFmtDebug.fmt
}

/-- [core::convert::{impl core::convert::TryFrom<U> for T}::try_from]
    (`where U: Into<T>`, `type Error = Infallible`): `Ok(U::into(value))`, as in
    Rust's `core`. CoreModels has this blanket impl as
    `convert.TryFromUTInfallible.Blanket` with a `From` bound instead. -/
def core.convert.TryFromTUInfallible.Blanket.try_from
  {T U : Type} (IntoInst : core.convert.Into U T) (value : U) :
  RustM (core.result.Result T core.convert.Infallible) := do
  let t ← IntoInst.into value
  ok (core.result.Result.Ok t)

/-- [core::mem::take]: `replace(dest, T::default())`, returning
    `(old value, new *dest)` as aeneas encodes `&mut` arguments. -/
def core.mem.take
  {T : Type} (DefaultInst : core.default.Default T) (dest : T) :
  RustM (T × T) := do
  let d ← DefaultInst.default
  ok (dest, d)

/-- [core::mem::size_of]. A type-directed constant, so it cannot be defined over
    an arbitrary `Type`: opaque, with its value fixed below for the types this
    crate queries (`primitives.rs:162`, `lib.rs:412`, `lib.rs:429`). -/
axiom core.mem.size_of (T : Type) : RustM Std.Usize

axiom core.mem.size_of_U8 : core.mem.size_of Std.U8 = ok 1#usize
axiom core.mem.size_of_U16 : core.mem.size_of Std.U16 = ok 2#usize
axiom core.mem.size_of_U32 : core.mem.size_of Std.U32 = ok 4#usize
axiom core.mem.size_of_U64 : core.mem.size_of Std.U64 = ok 8#usize

/-- `usize` is as wide as a pointer, which aeneas models by
    `System.Platform.numBits`. -/
axiom core.mem.size_of_Usize :
  ∃ n : Std.Usize, core.mem.size_of Std.Usize = ok n ∧ n.val * 8 = System.Platform.numBits

/-- [alloc::boxed::{impl core::convert::AsRef<T> for Box<T>}::as_ref]
    (`Box` is erased by aeneas, so this is the identity). -/
def alloc.Box.Insts.CoreConvertAsRef.as_ref {T : Type} (self : T) : RustM T :=
  ok self

/-- [core::fmt::{Arguments}::from_str]. `core.fmt.Arguments` is `Unit` in
    CoreModels. -/
def core.fmt.Arguments.from_str (_s : Str) : RustM core.fmt.Arguments :=
  ok ()

/-- [core::fmt::rt::{Argument}::new_display].

    DEVIATION(std): in Rust, `new_display` only stores `&x`; `alloc::fmt::format` later calls
    `Display::fmt` and panics if it returns `Err` ("a formatting trait implementation returned
    an error when the underlying stream did not"). `core.fmt.Arguments` is `Unit` in CoreModels,
    so no argument reaches `format`: the model calls `fmt` here instead, eagerly, and panics on
    `Err`. The failure is the same; only its point moves, across pure steps (`Arguments::new`).
    The text written is discarded (the `Formatter` is `Unit`). -/
def core.fmt.rt.Argument.new_display
    {T : Type} (DisplayInst : core.fmt.Display T) (x : T) :
    RustM core.fmt.rt.Argument := do
  let (r, _) ← DisplayInst.fmt x ()
  match r with
  | .Ok () => ok ⟨.Placeholder ()⟩
  | .Err _ => fail .panic

/-- [alloc::fmt::format].

    DEVIATION(std): returns the empty string (the text is not modelled; `core.fmt.Arguments` is
    `Unit`), as hax's own core-models do. It cannot fail here: `format`'s only panic, a failing
    `Display::fmt`, is modelled in `core.fmt.rt.Argument.new_display` (out-of-memory aborts are
    outside the model). -/
def alloc.fmt.format (_args : core.fmt.Arguments) : RustM alloc.string.String :=
  ok ""

/-- [alloc::vec::{impl core::iter::traits::collect::Extend<&'a T> for Vec<T>}::extend]:
    `self.spec_extend(iter.into_iter())`, i.e. push a copy of each item, in
    iteration order, until `next` returns `None`. aeneas erases the `&T` (items
    are `T`), and a `Copy` copy is bitwise (no `Clone::clone` call), so `CopyInst`
    is unused. Running out of length bound fails as `Vec::push` does (std panics
    with "capacity overflow"). A non-terminating iterator makes `loop` diverge. -/
def alloc.vec.Vec.Insts.CoreIterTraitsCollectExtendSharedAT.extend
  {T I IntoIter : Type} (CopyInst : core.marker.Copy T)
  (IntoIteratorInst : core.iter.traits.collect.IntoIterator I T IntoIter)
  (self : alloc.vec.Vec T) (iter : I) : RustM (alloc.vec.Vec T) := do
  let it ← IntoIteratorInst.into_iter iter
  loop (fun (p : IntoIter × alloc.vec.Vec T) => do
      let (o, it1) ← IntoIteratorInst.iteratorIteratorInst.next p.1
      match o with
      | core.option.Option.Some x =>
        let v ← alloc.vec.Vec.push p.2 x
        ok (cont (it1, v))
      | core.option.Option.None => ok (done p.2))
    (it, self)

/-- [alloc::vec::{impl core::hash::Hash for Vec<T>}::hash] -/
axiom alloc.vec.Vec.Insts.CoreHashHash.hash
  {T H : Type} (HashInst : core.hash.Hash T) (HasherInst : core.hash.Hasher H) :
  alloc.vec.Vec T → H → RustM H

/-- [alloc::vec::{impl core::cmp::Ord for Vec<T>}::cmp] -/
axiom alloc.vec.Vec.Insts.CoreCmpOrd.cmp
  {T : Type} (OrdInst : core.cmp.Ord T) :
  alloc.vec.Vec T → alloc.vec.Vec T → RustM core.cmp.Ordering

/-- [alloc::vec::{Vec<T>}::retain] -/
axiom alloc.vec.Vec.retain
  {T F : Type} (FnMutInst : core.ops.function.FnMut F T Bool) :
  alloc.vec.Vec T → F → RustM (alloc.vec.Vec T)

/-- [core::slice::iter::{impl Iterator for Iter<'a, T>}::any]: the trait's provided
    method (`Iterator::any`), at `slice::Iter` (as CoreModels does for `count` /
    `fold`). Needed by OpenMLS (`Extensions::try_from`). -/
abbrev core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.any
    {T F : Type} (FnInst : core.ops.function.FnMut F T Bool) :=
  iter.traits.iterator.Iterator.any.default
    (slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT T) FnInst

end CoreModels

/-! ## `std::io` (tls_codec's `std` feature)

Hand-written models of the `std::io` items the `std` extraction references (CoreModels has
none). Names are charon's: the traits and types moved to `core::io` / `alloc::io` in the
toolchain charon uses (nightly-2026.09.02). Semantics follow that std
(`library/{core,alloc}/src/io/`, read in rustup's nightly-2026-09-17 source). Everything is a
`def` except the `Debug` formatting of `io::Error` (opaque, like every other `fmt` here).

Encoding (aeneas'): a `&mut self` method returns the new `self` next to its result; a
`&mut [u8]` buffer argument is returned updated. aeneas represents `&mut R` as `R`, so the
`impl Read for &mut R` instance is the identity on dictionaries.

DEVIATIONS(std), all documented at the item:
- `io::Error` keeps only its `ErrorKind` (the payload — OS code, message, custom error — is
  only observable through `Debug`, which is opaque);
- a buffer returned by an arbitrary model reader may have another length than the one passed
  (impossible in Rust); the default methods re-cut it to the caller's length;
- `read_to_end` reads through `read` in chunks of 32 bytes (std: `read_buf` into the vector's
  spare capacity, adaptive sizes). For a reader whose `read` returns `min(n, available)`
  bytes (`&[u8]`, `Take` over it) the result is the same. -/

namespace CoreModels

/-- [core::io::error::ErrorKind], the variants in declaration order (as the `match` in
    `From<io::Error> for tls_codec::Error` lists them). -/
inductive core.io.error.ErrorKind where
  | NotFound | PermissionDenied | ConnectionRefused | ConnectionReset | HostUnreachable
  | NetworkUnreachable | ConnectionAborted | NotConnected | AddrInUse | AddrNotAvailable
  | NetworkDown | BrokenPipe | AlreadyExists | WouldBlock | NotADirectory | IsADirectory
  | DirectoryNotEmpty | ReadOnlyFilesystem | FilesystemLoop | StaleNetworkFileHandle
  | InvalidInput | InvalidData | TimedOut | WriteZero | StorageFull | NotSeekable
  | QuotaExceeded | FileTooLarge | ResourceBusy | ExecutableFileBusy | Deadlock
  | CrossesDevices | TooManyLinks | InvalidFilename | ArgumentListTooLong | Interrupted
  | Unsupported | UnexpectedEof | OutOfMemory | InProgress | TooManyOpenFiles
  | InputOutputError | Other | Uncategorized
  deriving DecidableEq, Inhabited

/-- [core::io::error::Error]. DEVIATION(std): only the kind is kept (see the section note). -/
structure core.io.error.Error where
  repr_kind : core.io.error.ErrorKind
  deriving DecidableEq, Inhabited

/-- [core::io::error::{Error}::kind] -/
def core.io.error.Error.kind (self : core.io.error.Error) : RustM core.io.error.ErrorKind :=
  ok self.repr_kind

/-- [core::io::error::{Error}::READ_EXACT_EOF] (a `SimpleMessage` of kind `UnexpectedEof`). -/
def core.io.error.Error.READ_EXACT_EOF : core.io.error.Error := ⟨.UnexpectedEof⟩

/-- [core::io::error::{impl core::fmt::Debug for Error}::fmt] -/
axiom core.io.error.Error.Insts.CoreFmtDebug.fmt :
  core.io.error.Error → core.fmt.Formatter →
  RustM ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter)

/-- [core::io::error::{impl core::fmt::Debug for Error}] -/
@[reducible]
noncomputable def core.io.error.Error.Insts.CoreFmtDebug : core.fmt.Debug core.io.error.Error := {
  fmt := core.io.error.Error.Insts.CoreFmtDebug.fmt
}

/-- [core::io::write::Write] (the methods the extraction and OpenMLS use). -/
structure core.io.write.Write (Self : Type) where
  write : Self → Slice Std.U8 →
    RustM ((core.result.Result Std.Usize core.io.error.Error) × Self)
  write_all : Self → Slice Std.U8 →
    RustM ((core.result.Result Unit core.io.error.Error) × Self)
  flush : Self → RustM ((core.result.Result Unit core.io.error.Error) × Self)

/-- [alloc::io::impls::{impl Write for Vec<u8, A>}::write_all]: `extend_from_slice`, `Ok`.
    (Running out of length bound fails as CoreModels' `extend_from_slice` does; std aborts.) -/
def alloc.vec.VecU8.Insts.CoreIoWriteWrite.write_all
  (self : alloc.vec.Vec Std.U8) (buf : Slice Std.U8) :
  RustM ((core.result.Result Unit core.io.error.Error) × alloc.vec.Vec Std.U8) := do
  let v ← alloc.vec.Vec.extend_from_slice core.U8.Insts.CoreCloneClone self buf
  ok (core.result.Result.Ok (), v)

/-- [alloc::io::impls::{impl Write for Vec<u8, A>}] (`write` = `write_all`, then
    `Ok(buf.len())`; `flush` = `Ok(())`). -/
@[reducible]
def alloc.vec.VecU8.Insts.CoreIoWriteWrite : core.io.write.Write (alloc.vec.Vec Std.U8) := {
  write := fun self buf => do
    let (r, v) ← alloc.vec.VecU8.Insts.CoreIoWriteWrite.write_all self buf
    match r with
    | .Ok () => ok (core.result.Result.Ok (Slice.len buf), v)
    | .Err e => ok (core.result.Result.Err e, v)
  write_all := alloc.vec.VecU8.Insts.CoreIoWriteWrite.write_all
  flush := fun self => ok (core.result.Result.Ok (), self)
}

/-- [alloc::io::read::Read] (the methods the extraction and OpenMLS use; the provided
    methods `take` / `read_to_end` are the `.default` functions below). -/
structure alloc.io.read.Read (Self : Type) where
  read : Self → Slice Std.U8 →
    RustM ((core.result.Result Std.Usize core.io.error.Error) × Self × Slice Std.U8)
  read_exact : Self → Slice Std.U8 →
    RustM ((core.result.Result Unit core.io.error.Error) × Self × Slice Std.U8)

/-- `xs` cut to at most `n` elements, as a slice (`n` the length of a slice). -/
def alloc.io.read.cut (xs : List Std.U8) (buf : Slice Std.U8) : Slice Std.U8 :=
  ⟨xs.take buf.length, by have := buf.property; simp; omega⟩

/-- [alloc::io::read::default_read_exact]: `read` until `buf` is full; `Ok(0)` first is
    `READ_EXACT_EOF`, `Interrupted` is retried, any other error is returned. `buf[n..]`
    panics if `read` claims more than the buffer holds. -/
def alloc.io.read.default_read_exact {Self : Type}
  (read : Self → Slice Std.U8 →
    RustM ((core.result.Result Std.Usize core.io.error.Error) × Self × Slice Std.U8))
  (self : Self) (buf : Slice Std.U8) :
  RustM ((core.result.Result Unit core.io.error.Error) × Self × Slice Std.U8) :=
  loop (fun (p : Self × Slice Std.U8 × Nat) => do
      let (s, b, pos) := p
      if pos ≥ b.length then ok (done (core.result.Result.Ok (), s, b)) else
      let rest : Slice Std.U8 := ⟨b.val.drop pos, by have := b.property; simp; omega⟩
      let (r, s1, rest1) ← read s rest
      let b1 := alloc.io.read.cut (b.val.take pos ++ rest1.val) b
      match r with
      | .Ok n =>
        if n.val = 0 then ok (done (core.result.Result.Err core.io.error.Error.READ_EXACT_EOF, s1, b1))
        else if n.val > rest.length then fail .panic
        else ok (cont (s1, b1, pos + n.val))
      | .Err e =>
        if e.repr_kind = .Interrupted then ok (cont (s1, b1, pos))
        else ok (done (core.result.Result.Err e, s1, b1)))
    (self, buf, 0)

/-- [alloc::io::impls::{impl Read for &[u8]}::read]: copy `min(buf.len(), self.len())` bytes,
    advance `self`. -/
def alloc.Shared0SliceU8.Insts.AllocIoReadRead.read
  (self : Slice Std.U8) (buf : Slice Std.U8) :
  RustM ((core.result.Result Std.Usize core.io.error.Error) × Slice Std.U8 × Slice Std.U8) :=
  let n := min buf.length self.length
  let a : Slice Std.U8 := ⟨self.val.take n, by have := self.property; simp; omega⟩
  let rest : Slice Std.U8 := ⟨self.val.drop n, by have := self.property; simp; omega⟩
  ok (core.result.Result.Ok (Slice.len a), rest, alloc.io.read.cut (a.val ++ buf.val.drop n) buf)

/-- [alloc::io::impls::{impl Read for &[u8]}::read_exact]: if `buf` is longer than `self`,
    consume all of `self` and return `READ_EXACT_EOF` (`buf` unspecified in std, unchanged
    here); else fill `buf` with the next `buf.len()` bytes and advance. -/
def alloc.Shared0SliceU8.Insts.AllocIoReadRead.read_exact
  (self : Slice Std.U8) (buf : Slice Std.U8) :
  RustM ((core.result.Result Unit core.io.error.Error) × Slice Std.U8 × Slice Std.U8) :=
  if buf.length > self.length then
    ok (core.result.Result.Err core.io.error.Error.READ_EXACT_EOF, ⟨[], by simp⟩, buf)
  else
    ok (core.result.Result.Ok (),
        ⟨self.val.drop buf.length, by have := self.property; simp; omega⟩,
        ⟨self.val.take buf.length, by have := buf.property; simp; omega⟩)

/-- [alloc::io::impls::{impl Read for &[u8]}] -/
@[reducible]
def alloc.Shared0SliceU8.Insts.AllocIoReadRead : alloc.io.read.Read (Slice Std.U8) := {
  read := alloc.Shared0SliceU8.Insts.AllocIoReadRead.read
  read_exact := alloc.Shared0SliceU8.Insts.AllocIoReadRead.read_exact
}

/-- [alloc::io::impls::{impl Read for &mut R}]: forwards every method to `R`'s impl
    (aeneas represents `&mut R` as `R`). -/
@[reducible]
def alloc.Mut0R.Insts.AllocIoReadRead {R : Type} (ReadInst : alloc.io.read.Read R) :
  alloc.io.read.Read R := ReadInst

/-- [core::io::util::Take] -/
structure core.io.util.Take (T : Type) where
  inner : T
  len : Std.U64
  limit : Std.U64

/-- [core::io::util::{Take<T>}::limit] -/
def core.io.util.Take.impl.limit {T : Type} (self : core.io.util.Take T) : RustM Std.U64 :=
  ok self.limit

/-- [alloc::io::read::Read::take] (provided method): `Take { inner: self, limit, len: limit }`;
    the backward function gives back the inner reader. -/
def alloc.io.read.Read.take.default {Self : Type} (ReadInst : alloc.io.read.Read Self)
  (self : Self) (limit : Std.U64) :
  RustM (core.io.util.Take Self × (core.io.util.Take Self → Self)) :=
  ok ({ inner := self, len := limit, limit := limit }, fun t => t.inner)

/-- [alloc::io::util::{impl Read for Take<T>}::read]: `Ok(0)` at limit 0 (the inner reader is
    not called); else read into `buf[..min(buf.len(), limit)]`, assert `n <= limit`, and
    decrease `limit` by `n`. An inner error is returned as is (`?`), `limit` unchanged. -/
def alloc.core.io.util.Take.Insts.AllocIoReadRead.read {T : Type}
  (ReadInst : alloc.io.read.Read T) (self : core.io.util.Take T) (buf : Slice Std.U8) :
  RustM ((core.result.Result Std.Usize core.io.error.Error) × core.io.util.Take T ×
    Slice Std.U8) := do
  if self.limit = 0#u64 then ok (core.result.Result.Ok 0#usize, self, buf) else
  let max := min buf.length self.limit.val
  let (r, inner1, sub1) ←
    ReadInst.read self.inner ⟨buf.val.take max, by have := buf.property; simp; omega⟩
  let buf1 := alloc.io.read.cut (sub1.val ++ buf.val.drop max) buf
  match r with
  | .Ok n =>
    let n64 ← lift (UScalar.cast .U64 n)
    if n64 > self.limit then fail .panic else
    let l ← self.limit - n64
    ok (core.result.Result.Ok n, { self with inner := inner1, limit := l }, buf1)
  | .Err e => ok (core.result.Result.Err e, { self with inner := inner1 }, buf1)

/-- [alloc::io::util::{impl Read for Take<T>}] (`read_exact`: the provided method). -/
@[reducible]
def alloc.core.io.util.Take.Insts.AllocIoReadRead {T : Type}
  (ReadInst : alloc.io.read.Read T) : alloc.io.read.Read (core.io.util.Take T) := {
  read := alloc.core.io.util.Take.Insts.AllocIoReadRead.read ReadInst
  read_exact := alloc.io.read.default_read_exact
    (alloc.core.io.util.Take.Insts.AllocIoReadRead.read ReadInst)
}

/-- [alloc::io::read::Read::read_to_end] (provided method, `default_read_to_end`): read until
    `Ok(0)`, appending to `buf`; `Interrupted` is retried; another error is returned with the
    bytes read so far left in `buf`; `Ok(bytes appended)`. DEVIATION(std): reads through
    `read` in 32-byte chunks (see the section note). The backward function is the identity
    (the reader is returned updated). -/
def alloc.io.read.Read.read_to_end.default {Self : Type} (ReadInst : alloc.io.read.Read Self)
  (self : Self) (buf : alloc.vec.Vec Std.U8) :
  RustM ((core.result.Result Std.Usize core.io.error.Error) × Self × alloc.vec.Vec Std.U8 ×
    (Self → Self)) := do
  let (r, s, v) ← loop (fun (p : Self × alloc.vec.Vec Std.U8) => do
      let (s, v) := p
      let chunk : Slice Std.U8 := ⟨List.replicate 32 0#u8, by simp [Usize.max]; scalar_tac⟩
      let (r, s1, chunk1) ← ReadInst.read s chunk
      match r with
      | .Ok n =>
        if n.val = 0 then ok (done (core.result.Result.Ok (), s1, v))
        else if n.val > 32 then fail .panic
        else
          let v1 ← alloc.vec.Vec.extend_from_slice core.U8.Insts.CoreCloneClone v
            ⟨chunk1.val.take n.val, by have := chunk1.property; simp; omega⟩
          ok (cont (s1, v1))
      | .Err e =>
        if e.repr_kind = .Interrupted then ok (cont (s1, v))
        else ok (done (core.result.Result.Err e, s1, v)))
    (self, buf)
  match r with
  | .Ok () =>
    let n ← Slice.len ⟨v.val, v.property⟩ - Slice.len ⟨buf.val, buf.property⟩
    ok (core.result.Result.Ok n, s, v, fun x => x)
  | .Err e => ok (core.result.Result.Err e, s, v, fun x => x)

/-- [core::fmt::rt::{Argument}::new_debug]: as `new_display` (same DEVIATION: `Debug::fmt` is
    called here, eagerly, and an `Err` panics as `format` would). -/
def core.fmt.rt.Argument.new_debug
    {T : Type} (DebugInst : core.fmt.Debug T) (x : T) :
    RustM core.fmt.rt.Argument := do
  let (r, _) ← DebugInst.fmt x ()
  match r with
  | .Ok () => ok ⟨.Placeholder ()⟩
  | .Err _ => fail .panic

end CoreModels


/-! ## `Lawful` structures of core traits (trait-level specs, aeneas `818b3fa6`)

The generated specs and per-impl obligations refer to `Trait.Lawful` for every
trait an impl or a bound mentions, including core traits, which CoreModels does
not provide yet. A field is a proof obligation of each impl's `Lawful` theorem,
never an axiom, so these structures assume nothing about arbitrary impls; a
generic spec gets them as `…InstLawful` hypotheses.

Fields, each the contract
Rust documents for the trait, except where noted:
- no failure (panic or divergence): `Clone.clone`, `PartialEq.ne`,
  `From.from` ("must not fail"), `TryFrom.try_from` (failure is an `Err`),
  `Default.default`, `Borrow.borrow`, `AsRef.as_ref`;
- `PartialEq.eq`: no failure, and `eq` decides `HEq` (`=` when `Rhs = Self`).
  Stronger than Rust's contract (which allows non-reflexive `eq`, e.g. `f64`): a
  modelling choice, so that a generic `T: PartialEq` bound gives real equality
  (needed by the round-trip posts `out == *self`). An impl whose `eq` is not
  structural equality, or one with `Rhs ≠ Self`, cannot prove its `Lawful`;
- `Eq`: the parent `eq` decides `=` (the model's equality is structural; now
  implied by the `PartialEq` field).
No field, on purpose:
- `Index` / `IndexMut`: the bound (`i < len`) depends on `Idx` and the impl, so it
  stays an impl-level (standalone) spec;
- `PartialOrd` / `Ord` (CoreModels' `Vec` `cmp` is an axiom), `Hash` (stub
  `Hasher`), `Debug` / `Display` (the `fmt` exclusion is open), `Drop` (stub
  `zeroize`), `FnOnce` / `FnMut` (closures may fail), `FromIterator`, and the
  markers `Copy`, `StructuralPartialEq`, `Error`. -/

namespace CoreModels

/-- `clone_spec`: `clone` does not fail (no panic, no divergence); the result is
    unconstrained. Needed by generic callers of `clone` that must prove a `⇓`
    (total-correctness) post, e.g. `from_slice` (`Slice::to_vec`). -/
structure core.clone.Clone.Lawful (Self : Type) (CloneInst : core.clone.Clone Self) : Prop where
  clone_spec (x : Self) : ⦃ ⌜ True ⌝ ⦄ CloneInst.clone x ⦃ ⇓ _ => ⌜ True ⌝ ⦄

structure core.borrow.Borrow.Lawful (Self : Type) (Borrowed : Type)
  (BorrowInst : core.borrow.Borrow Self Borrowed) : Prop where
  borrow_spec (x : Self) : ⦃ ⌜ True ⌝ ⦄ BorrowInst.borrow x ⦃ ⇓ _ => ⌜ True ⌝ ⦄

/-- `eq_spec`: the parent `PartialEq::eq` decides `=`. -/
structure core.cmp.Eq.Lawful (Self : Type)
  (EqInst : core.cmp.Eq Self) : Prop where
  eq_spec (x y : Self) :
    ⦃ ⌜ True ⌝ ⦄ EqInst.PartialEqInst.eq x y ⦃ ⇓ r => ⌜ r = true ↔ x = y ⌝ ⦄

structure core.cmp.Ord.Lawful (Self : Type)
  (OrdInst : core.cmp.Ord Self) : Prop where

structure core.cmp.PartialEq.Lawful (Self : Type) (Rhs : Type)
  (PartialEqInst : core.cmp.PartialEq Self Rhs) : Prop where
  eq_spec (x : Self) (y : Rhs) :
    ⦃ ⌜ True ⌝ ⦄ PartialEqInst.eq x y ⦃ ⇓ r => ⌜ r = true ↔ HEq x y ⌝ ⦄
  ne_spec (x : Self) (y : Rhs) : ⦃ ⌜ True ⌝ ⦄ PartialEqInst.ne x y ⦃ ⇓ _ => ⌜ True ⌝ ⦄

structure core.cmp.PartialOrd.Lawful (Self : Type) (Rhs : Type)
  (PartialOrdInst : core.cmp.PartialOrd Self Rhs) : Prop where

structure core.convert.AsRef.Lawful (Self : Type) (T : Type)
  (AsRefInst : core.convert.AsRef Self T) : Prop where
  as_ref_spec (x : Self) : ⦃ ⌜ True ⌝ ⦄ AsRefInst.as_ref x ⦃ ⇓ _ => ⌜ True ⌝ ⦄

structure core.convert.From.Lawful (Self : Type) (T : Type)
  (FromInst : core.convert.From Self T) : Prop where
  from_spec (x : T) : ⦃ ⌜ True ⌝ ⦄ FromInst.«from» x ⦃ ⇓ _ => ⌜ True ⌝ ⦄

structure core.convert.TryFrom.Lawful (Self : Type) (T : Type) (Self_Error : Type)
  (TryFromInst : core.convert.TryFrom Self T Self_Error) : Prop where
  try_from_spec (x : T) : ⦃ ⌜ True ⌝ ⦄ TryFromInst.try_from x ⦃ ⇓ _ => ⌜ True ⌝ ⦄

structure core.default.Default.Lawful (Self : Type)
  (DefaultInst : core.default.Default Self) : Prop where
  default_spec : ⦃ ⌜ True ⌝ ⦄ DefaultInst.default ⦃ ⇓ _ => ⌜ True ⌝ ⦄

structure core.error.Error.Lawful (Self : Type)
  (ErrorInst : core.error.Error Self) : Prop where

structure core.fmt.Debug.Lawful (Self : Type)
  (DebugInst : core.fmt.Debug Self) : Prop where

structure core.fmt.Display.Lawful (Self : Type)
  (DisplayInst : core.fmt.Display Self) : Prop where

structure core.hash.Hash.Lawful (Self : Type)
  (HashInst : core.hash.Hash Self) : Prop where

structure core.iter.traits.collect.FromIterator.Lawful (Self : Type) (A : Type)
  (FromIteratorInst : core.iter.traits.collect.FromIterator Self A) : Prop where

structure core.marker.Copy.Lawful (Self : Type)
  (CopyInst : core.marker.Copy Self) : Prop where

structure core.marker.StructuralPartialEq.Lawful (Self : Type)
  (StructuralPartialEqInst : core.marker.StructuralPartialEq Self) : Prop where

structure core.ops.drop.Drop.Lawful (Self : Type)
  (DropInst : core.ops.drop.Drop Self) : Prop where

structure core.ops.function.FnMut.Lawful (Self : Type) (Args : Type) (Self_Output : Type)
  (FnMutInst : core.ops.function.FnMut Self Args Self_Output) : Prop where

structure core.ops.function.FnOnce.Lawful (Self : Type) (Args : Type) (Self_Output : Type)
  (FnOnceInst : core.ops.function.FnOnce Self Args Self_Output) : Prop where

structure core.ops.index.Index.Lawful (Self : Type) (Idx : Type) (Self_Output : Type)
  (IndexInst : core.ops.index.Index Self Idx Self_Output) : Prop where

structure core.ops.index.IndexMut.Lawful (Self : Type) (Idx : Type) (Self_Output : Type)
  (IndexMutInst : core.ops.index.IndexMut Self Idx Self_Output) : Prop where

/-! ### `std::io` traits

A modelling choice (std documents no such contract): the `std` path is verified for in-memory
writers and readers only. A lawful writer is an append-only byte sink: a `view` of its state (the
bytes written so far) such that `write_all` appends and succeeds exactly when the result fits in
`usize`. A lawful reader is a deterministic byte stream: a `view` (the bytes still to come) and an
`adv` (the state after reading `n` of them) such that `read` copies `min(buf.len(), view.len())`
bytes and `read_exact` fills the buffer or fails with `UnexpectedEof` (state unspecified then).
Excluded: short reads, `Interrupted`, other I/O errors (files, sockets). `Vec<u8>` (writer),
`&[u8]`, `&mut R` and `Take<R>` (readers) are lawful (proved in `Verification/Std/Io.lean`). The
ghost observers `spec::io::{sink, stream, advanced}` read the views
(`Assumptions/FunsExternal.lean`); for a lawful instance the views are unique
(`Verification/Std/Io.lean`), so the choice below is no assumption. -/

structure core.io.write.Write.Law {Self : Type} (WriteInst : core.io.write.Write Self)
    (view : Self → List Std.U8) : Prop where
  view_le (w : Self) : (view w).length ≤ Usize.max
  write_all_ok (w : Self) (s : Slice Std.U8) : (view w).length + s.val.length ≤ Usize.max →
    ∃ w', WriteInst.write_all w s = ok (.Ok (), w') ∧ view w' = view w ++ s.val
  write_all_bound (w w' : Self) (s : Slice Std.U8) :
    WriteInst.write_all w s = ok (.Ok (), w') → (view w).length + s.val.length ≤ Usize.max

structure core.io.write.Write.Lawful (Self : Type)
  (WriteInst : core.io.write.Write Self) : Prop where
  law : ∃ view, core.io.write.Write.Law WriteInst view

structure alloc.io.read.Read.Law {Self : Type} (ReadInst : alloc.io.read.Read Self)
    (view : Self → List Std.U8) (adv : Self → Nat → Self) : Prop where
  view_le (r : Self) : (view r).length ≤ Usize.max
  adv_zero (r : Self) : adv r 0 = r
  adv_view (r : Self) (n : Nat) : n ≤ (view r).length → view (adv r n) = (view r).drop n
  adv_adv (r : Self) (a b : Nat) : a + b ≤ (view r).length → adv (adv r a) b = adv r (a + b)
  read (r : Self) (buf : Slice Std.U8) : ∃ k : Std.Usize,
    k.val = min buf.val.length (view r).length ∧
    ReadInst.read r buf = ok (.Ok k, adv r k.val,
      alloc.io.read.cut ((view r).take k.val ++ buf.val.drop k.val) buf)
  read_exact_ok (r : Self) (buf : Slice Std.U8) : buf.val.length ≤ (view r).length →
    ReadInst.read_exact r buf = ok (.Ok (), adv r buf.val.length, alloc.io.read.cut (view r) buf)
  read_exact_eof (r : Self) (buf : Slice Std.U8) : (view r).length < buf.val.length →
    ∃ r' b', ReadInst.read_exact r buf = ok (.Err core.io.error.Error.READ_EXACT_EOF, r', b')

structure alloc.io.read.Read.Lawful (Self : Type)
  (ReadInst : alloc.io.read.Read Self) : Prop where
  law : ∃ view adv, alloc.io.read.Read.Law ReadInst view adv

open Classical in
/-- The view of a lawful writer (a chosen one; unique, see the section note). -/
noncomputable def core.io.write.Write.view {Self : Type} (WriteInst : core.io.write.Write Self) :
    Self → List Std.U8 :=
  if h : ∃ view, core.io.write.Write.Law WriteInst view then Classical.choose h else fun _ => []

open Classical in
/-- The view of a lawful reader (a chosen one). -/
noncomputable def alloc.io.read.Read.view {Self : Type} (ReadInst : alloc.io.read.Read Self) :
    Self → List Std.U8 :=
  if h : ∃ view adv, alloc.io.read.Read.Law ReadInst view adv then Classical.choose h
  else fun _ => []

open Classical in
/-- The advance function of a lawful reader (chosen with `Read.view`). -/
noncomputable def alloc.io.read.Read.adv {Self : Type} (ReadInst : alloc.io.read.Read Self) :
    Self → Nat → Self :=
  if h : ∃ view adv, alloc.io.read.Read.Law ReadInst view adv then
    Classical.choose (Classical.choose_spec h)
  else fun r _ => r

theorem core.io.write.Write.Lawful.law' {Self : Type} {WriteInst : core.io.write.Write Self}
    (h : core.io.write.Write.Lawful Self WriteInst) :
    core.io.write.Write.Law WriteInst (core.io.write.Write.view WriteInst) := by
  unfold core.io.write.Write.view
  rw [dif_pos h.law]
  exact Classical.choose_spec h.law

theorem alloc.io.read.Read.Lawful.law' {Self : Type} {ReadInst : alloc.io.read.Read Self}
    (h : alloc.io.read.Read.Lawful Self ReadInst) :
    alloc.io.read.Read.Law ReadInst (alloc.io.read.Read.view ReadInst)
      (alloc.io.read.Read.adv ReadInst) := by
  unfold alloc.io.read.Read.view alloc.io.read.Read.adv
  rw [dif_pos h.law, dif_pos h.law]
  exact Classical.choose_spec (Classical.choose_spec h.law)

theorem core.io.write.Write.view_le {Self : Type} (WriteInst : core.io.write.Write Self) (w : Self) :
    (core.io.write.Write.view WriteInst w).length ≤ Usize.max := by
  unfold core.io.write.Write.view
  split
  · rename_i h; exact (Classical.choose_spec h).view_le w
  · simp

theorem alloc.io.read.Read.view_le {Self : Type} (ReadInst : alloc.io.read.Read Self) (r : Self) :
    (alloc.io.read.Read.view ReadInst r).length ≤ Usize.max := by
  unfold alloc.io.read.Read.view
  split
  · rename_i h; exact (Classical.choose_spec (Classical.choose_spec h)).view_le r
  · simp

/-- [core::convert::{impl AsRef<U> for &T}] (`T: AsRef<U>`): aeneas represents `&T` as `T`. -/
@[reducible]
def core.Shared0T.Insts.CoreConvertAsRef {T U : Type} (AsRefInst : core.convert.AsRef T U) :
  core.convert.AsRef T U := AsRefInst

end CoreModels
