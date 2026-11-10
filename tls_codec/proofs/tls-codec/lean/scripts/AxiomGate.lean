import TlsCodec
import TlsCodec.Tools.AxiomGate

/-! Axiom whitelist gate: open with `lean_diagnostic_messages`; an error
means a theorem of `TlsCodec.Verification` uses an axiom not listed in
`scripts/axiom_whitelist.txt`. The server caches the result: after editing the whitelist, run
`lean_build` (restarts the server) before re-opening. -/

#axiom_gate "TlsCodec.Verification" "scripts/axiom_whitelist.txt"
