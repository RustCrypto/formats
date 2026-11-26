/- Bytes-path helpers (`SerializeBytes` / `DeserializeBytes`), shared by `PanicFreedom.lean` and
`FunctionalCorrectness.lean`: one module per topic under `Helpers/`, in dependency order (each
imports the previous one). Nothing assumed here: the imported `Assumptions/` items are listed in
`Assumptions/MissingCoreModelsSpecs.lean`'s header. -/
import TlsCodec.Verification.Helpers.RoundTripBase
