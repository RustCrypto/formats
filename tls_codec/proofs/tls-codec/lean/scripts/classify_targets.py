#!/usr/bin/env python3
"""Regenerate the obligation lists of PROOF_TARGETS.md (between the markers
`<!-- BEGIN TARGETS -->` and `<!-- END TARGETS -->`; the text around them is kept).

    python3 scripts/classify_targets.py

Classes (read by gen_verification.py):
  1a  function specs `X.spec.proof` without trait-instance arguments
  1b  function specs with trait-instance arguments (and their `…InstLawful` hypotheses)
  2a  per-impl `Lawful` of `SerializeBytes` / `DeserializeBytes` (method fields)
  2b  per-impl `Lawful` of `Size` (`tls_serialized_len_spec`, post `true`: PF only)
  2c  per-impl `Lawful` of `Serialize` / `Deserialize` (parent field only)
  2d  per-impl `Lawful` of core / third-party traits (stubs of `Assumptions/`)
Groups (`####`) by source area. Known-false notes (`KNOWN`) are copied, after `--`, as a
comment line above the theorems in Verification/.
"""
import re, os, collections

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
PO = os.path.join(ROOT, "TlsCodec", "Extraction", "ProofObligations.lean")
TGT = os.path.join(ROOT, "PROOF_TARGETS.md")

# Known-false notes, `KNOWN[name] = note`. Empty: every target is proved.
KNOWN = {}


def theme(n):
    n = re.sub(r"\.(spec\.proof|Lawful)$", "", n)
    if n.startswith("spec."):
        return "Round-trip lemmas (`spec.rs`)"
    m = re.match(r"(?:tls_vec\.|Shared0)(Secret)?Tls(Byte)?(Vec|Slice)U(8|16|24|32)", n)
    if m:
        return f"`tls_vec`: {m.group(1) or ''}Tls{m.group(2) or ''}{m.group(3)}U*"
    if n.startswith("tls_vec."):
        return "`tls_vec`"
    if n.startswith("quic_vec.") or re.match(r"(Shared0)?(VL|Str|alloc\.(vec|string)|Vec|Slice)", n):
        return "`quic_vec` (VLBytes, ContentLength, Vec/Slice/Str/String)"
    if n.startswith("varint.") or "TlsVarInt" in n:
        return "`varint`"
    if re.match(r"(Shared0)?U(8|16|24|32|64)\.Insts\.Tls_codec", n):
        return "Integer primitives (primitives.rs)"
    if n.startswith(("U24.", "Usize.Insts.CoreConvertFromU24")):
        return "`U24` (lib.rs)"
    if n.startswith("ArrayU8"):
        return "Arrays (arrays.rs)"
    if re.match(r"(Pair|TupleTUV|Tuple|core\.option|Shared0Option|core\.marker|Box)\.", n):
        return "Option / tuples / PhantomData / Box (primitives.rs)"
    if n.startswith(("Error.", "__")):
        return "`Error`, trait-contract closures (lib.rs)"
    if "." not in n:
        return "Length arithmetic (lib.rs)"
    return "Other"


def conclusion(rest):
    depth = 0
    for i, ch in enumerate(rest):
        if ch in "({[":
            depth += 1
        elif ch in ")}]":
            depth -= 1
        elif ch == ":" and depth == 0:
            return rest[i + 1:].strip()
    raise ValueError(rest)


src = open(PO).read()
rows = collections.OrderedDict((c, collections.OrderedDict()) for c in ("1a", "1b", "2a", "2b", "2c", "2d"))
for m in re.finditer(r"^theorem\s+(\S+)(.*?):=\s*by\s*sorry", src, re.S | re.M):
    n, rest = m.group(1), m.group(2)
    if n.endswith(".spec.proof"):
        generic = re.search(r"Inst\s*:", rest) is not None
        c, g = ("1b" if generic else "1a"), theme(n)
    else:
        t = conclusion(rest).split()[0].lstrip("(")
        if t in ("SerializeBytes.Lawful", "DeserializeBytes.Lawful"):
            c, g = "2a", theme(n)
        elif t == "Size.Lawful":
            c, g = "2b", theme(n)
        elif t in ("Serialize.Lawful", "Deserialize.Lawful"):
            c, g = "2c", theme(n)
        else:
            c, g = "2d", f"`{t.removesuffix('.Lawful')}`"
    rows[c].setdefault(g, []).append(n)

TITLES = {
    "1a": "## 1a. Function specs, monomorphic",
    "1b": "## 1b. Function specs, generic (with `…InstLawful` hypotheses where aeneas emits them)",
    "2a": "## 2a. Per-impl `Lawful`: `SerializeBytes` / `DeserializeBytes`",
    "2b": "## 2b. Per-impl `Lawful`: `Size` (PF only)",
    "2c": "## 2c. Per-impl `Lawful`: `Serialize` / `Deserialize` (parent field only)",
    "2d": "## 2d. Per-impl `Lawful`: core / third-party traits",
}
out = []
for c, groups in rows.items():
    tot = sum(len(v) for v in groups.values())
    out.append(f"{TITLES[c]} ({tot})\n")
    for g in sorted(groups, key=lambda g: (-len(groups[g]), g)):
        out.append(f"#### {g} ({len(groups[g])})\n")
        for n in groups[g]:
            out.append(f"- `{n}`" + (f" -- {KNOWN[n]}" if n in KNOWN else ""))
        out.append("")
body = "\n".join(out)
assert all(any(n in v for g in rows.values() for v in g.values()) for n in KNOWN), "stale KNOWN entry"

old = open(TGT).read() if os.path.exists(TGT) else "<!-- BEGIN TARGETS -->\n<!-- END TARGETS -->\n"
a, b = old.index("<!-- BEGIN TARGETS -->"), old.index("<!-- END TARGETS -->")
open(TGT, "w").write(old[:a] + "<!-- BEGIN TARGETS -->\n\n" + body + "\n" + old[b:])
for c, groups in rows.items():
    print(c, sum(len(v) for v in groups.values()))
