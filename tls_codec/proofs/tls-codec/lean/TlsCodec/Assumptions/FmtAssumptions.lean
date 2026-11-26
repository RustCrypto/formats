/- ASSUMED specs of signature-only `fmt` axioms (`MissingCoreModels.lean`). Imported by
`MissingCoreModelsSpecs.lean` (hence by the proofs only, not by the generated files). Every
proof using one shows it in `#print axioms`.

Review: an ASSUMED "`fmt` returns `Ok`" is only honest for
an impl whose output is fixed std code writing to the formatter, since a `fmt::Error` can then
come only from the sink, and the only formatter in the model is `format!`'s (sink: a `String`,
which never fails; the `Formatter` is `Unit`, so the axiom cannot name it).
- kept: `FromUtf8Error`'s `Display` (std's `Utf8Error` message, no user payload);
- removed: `io::Error`'s `Debug`: `io::Error::Custom` delegates to the payload's
  (user) `Debug`, which may fail, and the kind-only model cannot tell a custom error apart.
  `From<io::Error> for Error` therefore has no general panic-freedom proof (it formats with
  `format!`, which panics on a failing `Debug`); `Verification/Helpers/ErrorFrom.lean` proves it for
  the errors the lawful readers produce (`UnexpectedEof`, no formatting). -/
import Aeneas
import Hax
import TlsCodec.Assumptions.MissingCoreModels
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM
open Std.Do

namespace CoreModels

/-- ASSUMED. `FromUtf8Error`'s `Display::fmt` returns `Ok`. std writes
    `invalid utf-8 sequence of {n} bytes from index {i}` (or `incomplete utf-8 byte sequence
    from index {i}`) with `write!`, which fails only if the formatter's sink does. The only
    formatter in the model is `format!`'s, whose sink is a `String` and never fails (the
    `Formatter` is `Unit`, so the axiom cannot name that sink). -/
@[spec]
axiom alloc.string.FromUtf8Error.Insts.CoreFmtDisplay.fmt.ok_spec
    (e : alloc.string.FromUtf8Error) (f : core.fmt.Formatter) :
    ⦃ ⌜ True ⌝ ⦄ alloc.string.FromUtf8Error.Insts.CoreFmtDisplay.fmt e f
    ⦃ ⇓ p => ⌜ p.1 = .Ok () ⌝ ⦄

end CoreModels
