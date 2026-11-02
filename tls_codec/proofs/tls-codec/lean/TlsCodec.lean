/- TlsCodec: the proofs of the `tls_codec` crate (scenario `tls-codec`), and the generic lemmas and
tactics its downstream crates (OpenMLS) reuse. Reading order:

1. `Extraction/` (generated, never edited): `Specs.lean` (the contracts), `ProofObligations.lean`
   (the obligations; the lean-comparator "challenge").
2. `Assumptions/`: everything assumed (models, ASSUMED specs, signature-only stubs); the axiom
   inventory is `scripts/axiom_whitelist.txt`, checked by `scripts/AxiomGate.lean`.
3. `Verification/ProofObligations.lean` (generated): every obligation, from its halves in
   `Verification/PanicFreedom.lean` and `Verification/FunctionalCorrectness.lean`.
4. Their helpers: `Verification/Helpers/` (bytes path: `SerializeBytes` / `DeserializeBytes`) and
   `Verification/Std/` (`std` path: `Serialize` / `Deserialize` on lawful readers / writers).
5. For downstream crates: `Verification/Derive/` (tactics for the derived impls, `Bytes` and `Std`;
   `HandWritten` for hand-written codecs, `HandWrittenReader` for hand-written bytes decoders that
   return the reader slice, `RoundTripStd` for the `std` round trip of composed codecs,
   `DecodersAgree` for the agreement of their two decoders and the mixed round trip) and
   `Verification/Std/SecretFrom.lean`.
6. `Tools/AxiomGate.lean`: the `#axiom_gate` command.

Each file starts with what it proves, which obligations use it and which axioms it reaches. Layout
and scripts: `NOTES.md`. -/
import TlsCodec.Extraction
import TlsCodec.Verification.ProofObligations
import TlsCodec.Verification.Derive.Std
import TlsCodec.Verification.Derive.HandWritten
import TlsCodec.Verification.Derive.HandWrittenReader
import TlsCodec.Verification.Derive.RoundTripStd
import TlsCodec.Verification.Derive.DecodersAgree
import TlsCodec.Verification.Std.SecretFrom
import TlsCodec.Tools.AxiomGate
