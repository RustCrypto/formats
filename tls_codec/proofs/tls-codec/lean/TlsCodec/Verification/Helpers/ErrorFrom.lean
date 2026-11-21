/- Panic freedom of `Error::from(io::Error)` on the errors lawful readers produce.

`Error.Insts.CoreConvertFromError.from` matches on the 40 `io::ErrorKind`s; every arm but
`UnexpectedEof` formats the error (`format!("io error: {e:?}")`), which panics if the error's
`Debug` fails, as it can for `io::Error::Custom` (user payload). So the general obligation
`Error.Insts.CoreConvertFromError.from_spec.panic_freedom` is not provable without an unsound
assumption and is left OPEN. Lawful readers (`Assumptions/MissingCoreModels.lean`) only return
`READ_EXACT_EOF` (kind `UnexpectedEof`), whose arm does not format: proved here.

Obligations: none directly (`Error.from_panic_freedom_of_eof` is what the `std` proofs use).
Axioms reached (`scripts/axiom_whitelist.txt`): nothing ASSUMED; 1 signature-only stub
(`core.io.error.Error.Insts.CoreFmtDebug.fmt`). -/
import Aeneas
import CoreModels
import Hax
import TlsCodec.Extraction
import TlsCodec.Verification.Helpers
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option mvcgen.warning false
set_option linter.unusedVariables false

namespace tls_codec

/-- `Error::from` returns on an `io::Error` of kind `UnexpectedEof` (the only error lawful
    readers produce; that arm does not format). -/
theorem Error.from_panic_freedom_of_eof (x : core.io.error.Error)
    (h : x.repr_kind = .UnexpectedEof) :
    ⦃ ⌜ True ⌝ ⦄ Error.Insts.CoreConvertFromError.from x ⦃ ⇓ _ => ⌜ True ⌝ ⦄ := by
  unfold Error.Insts.CoreConvertFromError.from core.io.error.Error.kind
  simp only [Aeneas.Std.bind_tc_ok, h]
  mvcgen

/-- `Error::from(READ_EXACT_EOF)` returns. -/
theorem Error.from_read_exact_eof_panic_freedom :
    ⦃ ⌜ True ⌝ ⦄ Error.Insts.CoreConvertFromError.from core.io.error.Error.READ_EXACT_EOF
    ⦃ ⇓ _ => ⌜ True ⌝ ⦄ :=
  Error.from_panic_freedom_of_eof _ rfl

end tls_codec
