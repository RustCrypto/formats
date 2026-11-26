#!/usr/bin/env python3
"""Generate the Verification/ skeleton from the extracted specs and obligations.

Usage (from anywhere):

    python3 scripts/gen_verification.py [--merge [--from DIR] | --force]

Reads
  TlsCodec/Extraction/Specs.lean             `def X.spec <binders> : Prop := <body>`, the
                                                  crate `Trait.Lawful` structures, `….post` defs
  TlsCodec/Extraction/ProofObligations.lean  `theorem X.spec.proof …` and the per-impl
                                                  `theorem I.Lawful … : Trait.Lawful … I …`
  TlsCodec/Extraction/Funs.lean              the instance defs `I` (field expressions)
  TlsCodec/Assumptions/Missing*Models.lean   the core / third-party `Lawful` structures
  PROOF_TARGETS.md                                classification (see below)
  scripts/port_renames.txt                        old-name -> new-name map (only with --from)
and writes
  TlsCodec/Verification/PanicFreedom.lean          PF theorems
  TlsCodec/Verification/FunctionalCorrectness.lean FC theorems
  TlsCodec/Verification/ProofObligations.lean      every obligation, derived from the two

Two kinds of obligations:

1. `X.spec.proof` (a function spec). Every body has the shape
   `[(pre …).holds →] ⦃ ⌜ True ⌝ ⦄ f args ⦃ ⇓ res => ⌜ post ⌝ ⦄` (checked). PF
   `X.spec.panic_freedom` replaces the post by `⦃ ⇓ _ => ⌜ True ⌝ ⦄`, FC
   `X.spec.functional_correctness` turns `⇓` into `⇓?`. Generic specs keep their
   `…InstLawful` binders (hypotheses usable in both halves).

2. `I.Lawful : Trait.Lawful Self … I` (one per impl). For every method field `m_spec`
   of the structure (`(args) : pre.holds → ⦃ ⌜ True ⌝ ⦄ Inst.m args ⦃ ⇓ res => post ⦄`),
   instantiated with the impl, the script generates `I.m_spec.panic_freedom` (PF) and
   `I.m_spec.functional_correctness` (FC), under the obligation's binders followed by the
   field's. `Inst.m` is written as the instance's field expression (e.g.
   `U8.Insts.Tls_codecSerializeBytes.tls_serialize_bytes`), and a `pre` that is `ok true`
   (all crate traits) is left out, so the statements match the former impl-level specs; when that expression is a trait default
   (`Trait.m.default …`) the projection `(I …).m` is used instead. A field whose post
   is `ok true` (e.g. `Size.tls_serialized_len_spec`) or literally `⌜ True ⌝`
   (`Clone.clone_spec`) gets only a PF theorem. Parent fields (`SizeInstLawful`) are
   discharged in ProofObligations.lean from the parent impl's `Lawful` theorem (or a
   `…InstLawful` hypothesis); structures without fields by `⟨⟩`.

PROOF_TARGETS.md lists every obligation (bullet / table rows starting with a backquoted
`X.spec.proof` or `I.Lawful`) under the class headings of `CLASSES` below
(`## 1a.` …). Rows under `#### <group>` headings are grouped; a row may end with
`-- <note>`, copied as a comment line above the theorem (e.g. "FALSE as generated").
`scripts/classify_targets.py` regenerates it.

PanicFreedom.lean and FunctionalCorrectness.lean hold hand-written proofs. Without a flag
the script refuses to overwrite them if they contain anything but `sorry` proofs.

`--merge` (after a re-extraction): regenerate the statements and keep the existing proof
body of every theorem, matched by name, plus extra `import` lines. It refuses (writes
nothing) if a theorem that has a proof would disappear, or if the old file has
non-generated top-level content (move it to Helpers.lean). It prints the theorems whose
statement changed (re-check those with `lean_build`).

`--merge --from DIR` (the port): take the old proofs from `DIR/PanicFreedom.lean` and
`DIR/FunctionalCorrectness.lean` (another project's Verification/) instead of the files
being rewritten. Theorem names are mapped through `scripts/port_renames.txt` (lines
`old new`; `new` = `-` retires a theorem, with the reason after `#`). A proved old theorem
must map to a generated theorem or be retired explicitly, else the merge refuses. In the
copied proofs, the package name and the renamed theorem names are rewritten, and the
value binders renamed by the new statement (`self` -> `self_`) are renamed in the proof.
`--force` overwrites and DROPS all proofs.
"""
import re, sys, os, collections

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
PKG = "TlsCodec"
EXT = os.path.join(ROOT, PKG, "Extraction")
ASM = os.path.join(ROOT, PKG, "Assumptions")
VER = os.path.join(ROOT, PKG, "Verification")
FORCE = "--force" in sys.argv
MERGE = "--merge" in sys.argv
FROM = sys.argv[sys.argv.index("--from") + 1] if "--from" in sys.argv else None
assert not (FORCE and MERGE), "--merge and --force are exclusive"
assert FROM is None or MERGE, "--from needs --merge"

specs_src = open(os.path.join(EXT, "Specs.lean")).read()
po_src = open(os.path.join(EXT, "ProofObligations.lean")).read()
funs_src = open(os.path.join(EXT, "Funs.lean")).read()
lawful_srcs = [specs_src] + [open(os.path.join(ASM, f)).read()
                             for f in ("MissingCoreModels.lean", "MissingThirdPartyModels.lean")]
# proved `Lawful` theorems of core instances (`<instance>.Lawful`), used for parent fields
core_lawful_thms = set()
_hdir = os.path.join(VER, "Helpers")
for _f in [os.path.join(ASM, "MissingCoreModelsSpecs.lean")] + (
        [os.path.join(_hdir, f) for f in sorted(os.listdir(_hdir)) if f.endswith(".lean")]
        if os.path.isdir(_hdir) else []):
    if os.path.exists(_f):
        core_lawful_thms |= set(re.findall(r"^theorem\s+(\S+Insts\.\S+\.Lawful)\s", open(_f).read(), re.M))
targets = open(os.path.join(ROOT, "PROOF_TARGETS.md")).read()


def flat(s):
    return re.sub(r"\s+", " ", s).strip()


def split_top(s):
    """Split `s` at top-level whitespace (outside (), {}, [], ⦃⦄)."""
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch in "({[⦃":
            depth += 1
        elif ch in ")}]⦄":
            depth -= 1
        if ch.isspace() and depth == 0:
            if cur:
                out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur:
        out.append(cur)
    return out


def binder_groups(s):
    """`(a b : T) {c : U}` -> [('(', ['a','b'], 'T'), ('{', ['c'], 'U')]."""
    out = []
    for g in split_top(s):
        assert g[0] in "({[" and g[-1] in ")}]", (g, s)
        inner = g[1:-1]
        if g[0] == "[" and ":" not in inner:
            out.append((g[0], [], inner))
            continue
        names, ty = inner.split(":", 1)
        out.append((g[0], names.split(), ty.strip()))
    return out


def paren(e):
    e = e.strip()
    return e if len(split_top(e)) == 1 else f"({e})"


# ---------------------------------------------------------------- spec defs
specs = {}  # name -> (binders, body)
for m in re.finditer(r"^def\s+(\S+)\.spec\s(.*?)\n\n", specs_src, re.S | re.M):
    name, rest = m.group(1), m.group(2)
    i = rest.find(": Prop :=")
    assert i >= 0, name
    binders, body = rest[:i].rstrip(), rest[i + len(": Prop :="):].strip("\n")
    fl = flat(re.sub(r"--[^\n]*", "", body))
    shape = re.sub(r"\(([^()]|\(([^()]|\([^()]*\))*\))*\)\.holds →", "H →", fl)
    assert re.fullmatch(r"(H → )*⦃ ⌜ True ⌝ ⦄ .*? ⦃ ⇓ \S+ => ⌜ .* ⌝ ⦄", shape), (name, fl)
    assert body.count("⦃ ⇓") == 1, name
    specs[name] = (binders, body)

# trivial pres / posts: `def T.m.pre … := do\n  ok true`
trivial_post, trivial_pre = set(), set()
for m in re.finditer(r"^def\s+(\S+)\.(pre|post)\b(.*?)\n\n", specs_src, re.S | re.M):
    if flat(m.group(3)).endswith(":= do ok true"):
        (trivial_post if m.group(2) == "post" else trivial_pre).add(m.group(1))

# ---------------------------------------------------------------- Lawful structures
Field = collections.namedtuple("Field", "name binders stmt parent")
structs = {}  # Trait.Lawful (without CoreModels.) -> (param names, [Field])
for src in lawful_srcs:
    for m in re.finditer(r"^structure\s+(\S+\.Lawful)\s(.*?)\s*:\s*Prop\s+where\n((?:  [^\n]*\n|\n(?=  ))*)",
                         src, re.M | re.S):
        sname = m.group(1).removeprefix("CoreModels.")
        params = [n for _, ns, _ in binder_groups(m.group(2)) for n in ns]
        fields = []
        for fm in re.finditer(r"^  (\w+)\b(.*?)(?=^  \w|\Z)", m.group(3), re.S | re.M):
            fname, rest = fm.group(1), fm.group(2)
            # binders up to the top-level ':'
            depth, k = 0, None
            for idx, ch in enumerate(rest):
                if ch in "({[⦃":
                    depth += 1
                elif ch in ")}]⦄":
                    depth -= 1
                elif ch == ":" and depth == 0:
                    k = idx
                    break
            assert k is not None, (sname, fname)
            fb, ft = rest[:k].strip(), rest[k + 1:].strip()
            parent = re.match(r"(\S+\.Lawful)\b", ft)
            fields.append(Field(fname, fb, ft, parent.group(1).removeprefix("CoreModels.") if parent else None))
        structs[sname] = (params, fields)

# ---------------------------------------------------------------- instance defs (Funs.lean)
inst_fields = {}  # instance name -> (binder names, {field: expr})
for m in re.finditer(r"^@\[reducible\]\n(?:def|impl_def)\s+(\S+)(.*?):=\s*\{\n(.*?)^\}", funs_src, re.S | re.M):
    name, head, body = m.group(1), m.group(2), m.group(3)
    fields, cur = {}, None
    for line in body.rstrip("\n").split("\n"):
        if not line.strip():
            continue
        fm = re.match(r"^  (\S+) :=(.*)", line)
        if fm:
            cur = fm.group(1)
            fields[cur] = fm.group(2)
        else:
            fields[cur] += " " + line
    # explicit binder names of the def (before the last top-level ':')
    depth, k = 0, None
    for idx, ch in enumerate(head):
        if ch in "({[":
            depth += 1
        elif ch in ")}]":
            depth -= 1
        elif ch == ":" and depth == 0:
            k = idx
    expl = [n for b, ns, _ in binder_groups(head[:k]) if b == "(" for n in ns]
    inst_fields[name] = (expl, {f: flat(e) for f, e in fields.items()})

# ---------------------------------------------------------------- obligations
Obl = collections.namedtuple("Obl", "name kind header lead binders typ")
obls = []
for m in re.finditer(r"((?:^--[^\n]*\n)*)^(theorem\s+(\S+)(.*?))\s*:=\s*by\s*sorry", po_src, re.S | re.M):
    name, rest = m.group(3), m.group(4)
    kind = "spec" if name.endswith(".spec.proof") else "lawful"
    assert kind == "spec" or name.endswith(".Lawful"), name
    depth, k = 0, None
    for idx, ch in enumerate(rest):
        if ch in "({[⦃":
            depth += 1
        elif ch in ")}]⦄":
            depth -= 1
        elif ch == ":" and depth == 0:
            k = idx
            break
    obls.append(Obl(name, kind, m.group(2), m.group(1), rest[:k].strip(), rest[k + 1:].strip()))

spec_obls = [o for o in obls if o.kind == "spec"]
assert {o.name[:-len(".spec.proof")] for o in spec_obls} == set(specs), "specs vs obligations"


class Lawful:
    """A per-impl Lawful obligation with its instantiated fields."""

    def __init__(self, o):
        self.o = o
        self.impl = o.name[:-len(".Lawful")]
        toks = split_top(flat(o.typ))
        self.trait = toks[0]
        assert self.trait in structs, (o.name, self.trait)
        params, fields = structs[self.trait]
        args = toks[1:]
        assert len(args) == len(params), (o.name, toks, params)
        self.sub = dict(zip(params, args))
        self.inst = args[-1]
        self.binder_names = [n for _, ns, _ in binder_groups(o.binders) for n in ns]
        # the instance def, to write `Inst.m` as the field expression
        itoks = split_top(self.inst.strip("()") if self.inst.startswith("(") else self.inst)
        self.inst_head, self.inst_args = itoks[0], itoks[1:]
        self.fields = fields

    def subst(self, s):
        for p, a in self.sub.items():
            s = re.sub(r"(?<![\w.'])" + re.escape(p) + r"(?![\w'])", lambda _: paren(a), s)
        return s

    def method_expr(self, method):
        expl, fields = inst_fields.get(self.inst_head, (None, {}))
        e = fields.get(method)
        if e is None or expl != self.inst_args or re.match(r"\S+\.default\b", e):
            return f"{paren(self.inst)}.{method}"
        return paren(e)

    def methods(self):
        """[(field, PF statement, FC statement or None)] for the method fields."""
        out = []
        inst_param = list(self.sub)[-1]
        for f in self.fields:
            if f.parent:
                continue
            fb = binder_groups(f.binders) if f.binders else []
            clash = {n for _, ns, _ in fb for n in ns} & set(self.binder_names)
            assert not clash, (self.o.name, clash)
            pre_, call = f.stmt.split("⦃ ⌜ True ⌝ ⦄", 1)
            call, post_ = call.split("⦃ ⇓", 1)
            mm = re.search(r"(?<![\w.'])" + re.escape(inst_param) + r"\.(«\w+»|\w+)", call)
            method = mm.group(1)
            call = self.subst(call)
            proj = f"{paren(self.inst)}.{method}"
            assert call.count(proj) == 1, (self.o.name, call, proj)
            call = call.replace(proj, self.method_expr(method))
            pm_ = re.fullmatch(r"\s*\((\S+)\.pre\b.*\)\.holds →\s*", pre_, re.S)
            if pm_ and pm_.group(1) in trivial_pre:
                pre_ = ""  # `pre` is `ok true`: the hypothesis is dropped (re-added by the glue)
            stmt = self.subst(pre_) + "⦃ ⌜ True ⌝ ⦄" + call + "⦃ ⇓" + self.subst(post_)
            name = f"{self.impl}.{f.name}"
            binders = (self.o.binders + " " + self.subst(f.binders)).strip()
            i = stmt.index("⦃ ⇓")
            post_true = flat(stmt[i:]).startswith("⦃ ⇓ _ => ⌜ True ⌝ ⦄")
            pm = re.search(r"⌜ \((\S+)\.post\b", stmt[i:])
            trivial = post_true or (pm is not None and pm.group(1) in trivial_post)
            stmt = stmt.lstrip()
            i = stmt.index("⦃ ⇓")
            pf = f"theorem {name}.panic_freedom {binders} :\n  {stmt[:i]}⦃ ⇓ _ => ⌜ True ⌝ ⦄"
            fc = None if trivial else f"theorem {name}.functional_correctness {binders} :\n  {stmt.replace('⦃ ⇓ ', '⦃ ⇓? ', 1)}"
            out.append((f, name, pf, fc, None if post_true or pm is None else pm.group(1) + ".post"))
        return out

    def parents(self):
        return [f for f in self.fields if f.parent]


lawfuls = {o.name: Lawful(o) for o in obls if o.kind == "lawful"}

# ---------------------------------------------------------------- classes
CLASSES = [  # (tag, heading prefix in PROOF_TARGETS.md, section title in the .lean files, doc)
    ("ready", "## 1a.", "1a. Function specs: monomorphic",
     "Function specs without trait-instance arguments. Grouped as in PROOF_TARGETS.md."),
    ("generic", "## 1b.", "1b. Function specs: generic",
     "Function specs over trait instances. Since the trait-level specs, the instance "
     "arguments come with `…InstLawful` hypotheses (the trait contracts), usable through "
     "`TInstLawful.m_spec` (e.g. as an `mvcgen` spec)."),
    ("codec", "## 2a.", "2a. Per-impl `Lawful`: `SerializeBytes` / `DeserializeBytes`",
     "Method fields of the crate's codec traits, one PF and one FC theorem per field."),
    ("size", "## 2b.", "2b. Per-impl `Lawful`: `Size`",
     "`Size.tls_serialized_len_spec` (post `true`): panic freedom only."),
    ("parent", "## 2c.", "2c. Per-impl `Lawful`: parent fields only (`Serialize` / `Deserialize`)",
     "No method field: built from the `Size` impl's `Lawful` theorem."),
    ("core", "## 2d.", "2d. Per-impl `Lawful`: core / third-party traits",
     "Structures of `Assumptions/MissingCoreModels.lean`: no-failure fields (`Clone`, `PartialEq`, `From`, `TryFrom`, `Default`, `Borrow`, `AsRef`) and `Eq.eq_spec` (`eq` decides `=`); the other core traits have no field."),
]
TAGS = [c[0] for c in CLASSES]

cls, group, note = {}, {}, {}
heads = [(c[0], c[1]) for c in CLASSES]
for n_, (tag, a) in enumerate(heads):
    b = heads[n_ + 1][1] if n_ + 1 < len(heads) else None
    s = targets[targets.index(a): targets.index(b) if b else None]
    g = None
    for line in s.split("\n"):
        gm = re.match(r"^#### (.*)", line)
        if gm:
            g = re.sub(r"\s*\(\d+\)$", "", gm.group(1)).replace("`", "")
            continue
        m = re.match(r"^[-|] `([^`]+)`(.*)", line)
        if not m:
            continue
        n = m.group(1)
        assert n not in cls, n
        cls[n], group[n] = tag, g
        nm = re.search(r"-- (.*)$", m.group(2))
        if nm:
            note[n] = nm.group(1).strip().rstrip("|").strip()
assert set(cls) == {o.name for o in obls}, sorted(set(cls) ^ {o.name for o in obls})[:20]
assert all(cls[o.name] in ("ready", "generic") for o in spec_obls)

HEADER = """import Aeneas
import CoreModels
import Hax
import {pkg}.Extraction
{imports}
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
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false
set_option maxHeartbeats 1000000
set_option maxRecDepth 2048

noncomputable section

namespace tls_codec
"""

GEN_NOTE = ("-- GENERATED by scripts/gen_verification.py from Extraction/{Specs,ProofObligations,Funs}.lean "
            "and PROOF_TARGETS.md.")


def ordered(size_first=False):
    """(tag, title, doc, [obligation]) in class order (in the PO file the `Size` impls come
    before the other per-impl obligations, which use them); within a class, by group, then
    in generated order."""
    classes = CLASSES
    if size_first:
        classes = [c for c in CLASSES if c[0] != "size"]
        classes.insert(TAGS.index("codec"), next(c for c in CLASSES if c[0] == "size"))
    for tag, _, title, doc in classes:
        items = [o for o in obls if cls[o.name] == tag]
        gorder = []
        for o in items:
            if group[o.name] not in gorder:
                gorder.append(group[o.name])
        items.sort(key=lambda o: gorder.index(group[o.name]))
        yield tag, title, doc, items


def entries(render, size_first=False):
    out, counts = [], collections.Counter()
    for tag, title, doc, items in ordered(size_first):
        chunks, last = [], object()
        for o in items:
            text = render(o)
            if text is None:
                continue
            if group[o.name] != last:
                if group[o.name]:
                    chunks.append(f"/-! ### {group[o.name]} -/\n")
                last = group[o.name]
            if o.name in note:
                chunks.append(f"-- {note[o.name]}")
            chunks.append(text)
            counts[tag] += len(re.findall(r"^theorem\b", text, re.M))
        if chunks:
            out.append(f"\n/-! ## {title}\n\n{doc} -/\n")
            out += chunks
    return "\n".join(out), counts


def pf_stmt(name):
    binders, body = specs[name]
    i = body.index("⦃ ⇓")
    return f"theorem {name}.spec.panic_freedom {binders} :\n{body[:i]}⦃ ⇓ _ => ⌜ True ⌝ ⦄"


def fc_stmt(name):
    binders, body = specs[name]
    return f"theorem {name}.spec.functional_correctness {binders} :\n{body.replace('⦃ ⇓ ', '⦃ ⇓? ', 1)}"


def render_pf(o):
    if o.kind == "spec":
        return f"{pf_stmt(o.name[:-len('.spec.proof')])} := by\n  sorry\n"
    ms = lawfuls[o.name].methods()
    return "\n".join(f"{pf} := by\n  sorry\n" for _, _, pf, _, _ in ms) or None


def render_fc(o):
    if o.kind == "spec":
        return f"{fc_stmt(o.name[:-len('.spec.proof')])} := by\n  sorry\n"
    ms = [fc for _, _, _, fc, _ in lawfuls[o.name].methods() if fc]
    return "\n".join(f"{fc} := by\n  sorry\n" for fc in ms) or None


def render_po(o):
    lead = "".join(f"{l}\n" for l in o.lead.strip("\n").split("\n") if l)
    if o.kind == "spec":
        n = o.name[:-len(".spec.proof")]
        return (f"{lead}{o.header}\n  := by\n  unfold {n}.spec\n"
                f"  pf_fc_combine {n}.spec.panic_freedom {n}.spec.functional_correctness\n")
    L = lawfuls[o.name]
    if not L.fields:
        return f"{lead}{o.header}\n  := ⟨⟩\n"
    lines = []
    for f in L.parents():
        sub_inst = f"{paren(L.inst)}.{f.stmt.split()[-1].split('.')[-1]}"
        head = None
        expl, ifields = inst_fields.get(L.inst_head, (None, {}))
        pe = ifields.get(f.stmt.split()[-1].split(".")[-1])
        if pe:
            h = split_top(pe)[0]
            if f"{h}.Lawful" in lawfuls or f"{h}.Lawful" in core_lawful_thms:
                head = f"{h}.Lawful"
        tac = f"lawful_parent {head}" if head else "lawful_hyp"
        lines.append(f"  {f.name} := by {tac}")
    for f, name, pf, fc, post in L.methods():
        if fc:
            lines.append(f"  {f.name} := by pf_fc_combine {name}.panic_freedom {name}.functional_correctness")
        elif post:
            lines.append(f"  {f.name} := by pf_post_true_combine {name}.panic_freedom {post}")
        else:
            lines.append(f"  {f.name} := by pf_only_combine {name}.panic_freedom")
    return f"{lead}{o.header}\n  := {{\n" + "\n".join(lines) + "\n}\n"


def write(path, text):
    if os.path.exists(path) and not FORCE and not MERGE and path.endswith(("PanicFreedom.lean", "FunctionalCorrectness.lean")):
        old = open(path).read()
        stripped = re.sub(r":= by\s*sorry", "", old)
        if ":= by" in stripped or "by\n" in stripped:
            sys.exit(f"{path} contains proofs; rerun with --merge (keeps them) or --force (drops them)")
    open(path, "w").write(text)


# ---------------------------------------------------------------- merge (--merge)
THM = re.compile(r"^theorem\s+(\S+)")


def attr_prefix(lines, i):
    """The `attribute [local …] … in` lines right above line `i` (kept with the theorem)."""
    a = i
    while a > 0 and lines[a - 1].startswith("attribute [local ") and lines[a - 1].rstrip().endswith(" in"):
        a -= 1
    return lines[a:i]


def theorems(lines):
    """name -> (first line, last statement line, end of proof) for `theorem … := by` + indented body."""
    out, i = {}, 0
    while i < len(lines):
        m = THM.match(lines[i])
        if not m:
            i += 1
            continue
        j = i
        while not re.search(r":=\s*by\s*$", lines[j]):
            j += 1
        k = j + 1
        while k < len(lines) and (lines[k] == "" or lines[k][0].isspace()):
            k += 1
        while k > j + 1 and lines[k - 1] == "":
            k -= 1
        out[m.group(1)] = (i, j, k)
        i = k
    return out


def is_sorry(body):
    return [l.strip() for l in body if l.strip()] == ["sorry"]


def load_renames():
    ren, retired = {}, {}
    p = os.path.join(ROOT, "scripts", "port_renames.txt")
    for line in open(p):
        line = line.split("#", 1)
        reason = line[1].strip() if len(line) > 1 else ""
        toks = line[0].split()
        if not toks:
            continue
        old, new = toks
        if new == "-":
            retired[old] = reason
        else:
            ren[old] = new
    return ren, retired


def value_binders(stmt_lines):
    """Explicit binder names of a theorem statement, in order."""
    s = flat("\n".join(stmt_lines))
    s = s.split(None, 2)[2]  # drop `theorem name`
    depth, k = 0, len(s)
    for idx, ch in enumerate(s):
        if ch in "({[⦃":
            depth += 1
        elif ch in ")}]⦄":
            depth -= 1
        elif ch == ":" and depth == 0:
            k = idx
            break
    return [n for b, ns, _ in binder_groups(s[:k]) if b == "(" for n in ns]


def merge(path, text, old_path):
    """Put the proofs of `old_path` into the freshly generated `text`."""
    if not os.path.exists(old_path):
        return text
    old = open(old_path).read().split("\n")
    new = text.split("\n")
    to, tn = theorems(old), theorems(new)
    proof = {n: old[j + 1:k] for n, (i, j, k) in to.items()}
    ren, retired = load_renames() if FROM else ({}, {})
    target = {n: ren.get(n, n) for n in to}
    lost = sorted(n for n in to if target[n] not in tn and n not in retired and not is_sorry(proof[n]))
    if lost:
        sys.exit(f"{path}: proved theorems no longer generated, add them to "
                 f"scripts/port_renames.txt or merge by hand: {lost}")
    src_of = {}
    for n in to:
        t = target[n]
        if t in tn and n not in retired:
            # prefer a proved source if two old names map to the same new one
            if t not in src_of or (is_sorry(proof[src_of[t]]) and not is_sorry(proof[n])):
                src_of[t] = n
    changed = sorted(t for t, n in src_of.items()
                     if flat("\n".join(old[to[n][0]:to[n][1] + 1])).replace(n, t, 1)
                     != flat("\n".join(new[tn[t][0]:tn[t][1] + 1])))
    # rewrite references to renamed theorems inside proofs (longest names first)
    ren_items = sorted(ren.items(), key=lambda kv: -len(kv[0]))
    dp = os.path.join(ROOT, "scripts", "port_def_renames.txt")
    if FROM and os.path.exists(dp):
        ren_items += sorted((tuple(l.split()) for l in open(dp) if l.strip() and not l.startswith("#")),
                            key=lambda kv: -len(kv[0]))

    def port_body(n, t, body):
        b = "\n".join(body)
        if FROM:
            b = re.sub(r"\bTlsCodec\b(?!Setup)", PKG, b)
            for o_, n_ in ren_items:
                b = re.sub(r"(?<![\w.'])" + re.escape(o_) + r"(?![\w'])", n_, b)
            ob, nb = value_binders(old[to[n][0]:to[n][1] + 1]), value_binders(new[tn[t][0]:tn[t][1] + 1])
            if len(ob) == len(nb):
                for x, y in zip(ob, nb):
                    if x != y:
                        b = re.sub(r"(?<![\w.'])" + re.escape(x) + r"(?![\w'])", y, b)
        return b.split("\n")

    out, pos, kept = [], 0, 0
    for t, (i, j, k) in sorted(tn.items(), key=lambda e: e[1][0]):
        out += new[pos:i]
        n = src_of.get(t)
        if n is not None and not is_sorry(proof[n]):
            out += port_body(n, t, attr_prefix(old, to[n][0])) if attr_prefix(old, to[n][0]) else []
        out += new[i:j + 1]
        if n is not None and not is_sorry(proof[n]):
            out += port_body(n, t, proof[n])
            kept += 1
        else:
            out += new[j + 1:k]
        pos = k
    out += new[pos:]
    missing = [re.sub(r"\bTlsCodec\b(?!Setup)", PKG, l) for l in old if l.startswith("import ")]
    missing = [l for l in missing if l not in out and not (FROM and "MissingSpecs" in l)]
    if missing:
        last = max(n for n, l in enumerate(out) if l.startswith("import "))
        out[last + 1:last + 1] = missing
    if not FROM:
        extra = sorted(set(l for l in old if l and not l[0].isspace()) - set(out))
        extra = [l for l in extra if not l.startswith(("/-! ## ", "-- "))]
        extra = [l for l in extra if not (l.startswith("theorem ") and l.split()[1] in tn)]
        if extra:
            sys.exit(f"{path}: non-generated top-level lines, move them (e.g. to Helpers.lean) "
                     f"or merge by hand: {extra}")
    print(f"{os.path.basename(path)}: kept {kept} proofs; {len(changed)} statements changed")
    for t in changed:
        n = src_of[t]
        print(f"  changed: {t}" + (f" (from {n})" if n != t else "")
              + ("  [HAS PROOF: re-check]" if not is_sorry(proof[n]) else ""))
    return "\n".join(out)


IMPORTS = f"import {PKG}.Verification.Helpers"

# ---------------------------------------------------------------- PanicFreedom
pf_body, pf_counts = entries(render_pf)
pf = f"""{GEN_NOTE}
/- Panic freedom: for every function spec `X.spec.proof` a total-correctness triple
`X.spec.panic_freedom`, and for every method field `m_spec` of a per-impl `I.Lawful`
obligation a triple `I.m_spec.panic_freedom`, with post `True`, under the same `pre`
hypotheses.

`⦃ ⌜ True ⌝ ⦄ f args ⦃ ⇓ _ => ⌜ True ⌝ ⦄` is `PostCond.noThrow`: `f args` returns `ok`.
For `RustM` this excludes both `fail` (panic, overflow) and `div`.
Functional correctness is in `FunctionalCorrectness.lean`; both are combined in
`ProofObligations.lean`. Proofs go here, replacing the `sorry`s.
-/
""" + HEADER.format(pkg=PKG, imports=IMPORTS) + pf_body + "\nend tls_codec\n\nend\n"

# ---------------------------------------------------------------- FunctionalCorrectness
fc_body, fc_counts = entries(render_fc)
fc = f"""{GEN_NOTE}
/- Functional correctness: for every function spec `X.spec.proof` and every method field
`m_spec` of a per-impl `I.Lawful` obligation (except those whose post is `true`), a
partial-correctness triple with the generated post, under the same `pre` hypotheses.

`⦃ ⌜ True ⌝ ⦄ f args ⦃ ⇓? res => ⌜ post ⌝ ⦄` is `PostCond.mayThrow`: *if* `f args`
returns `ok res`, then `post` holds. For `RustM` nothing is claimed on `fail` or `div`.
Note that `(X.post … res).holds` is itself a total triple: `post` must not panic.
Panic freedom is in `PanicFreedom.lean`; both are combined in `ProofObligations.lean`.
Proofs go here, replacing the `sorry`s.
-/
""" + HEADER.format(pkg=PKG, imports=IMPORTS) + fc_body + "\nend tls_codec\n\nend\n"

# ---------------------------------------------------------------- ProofObligations
# Size impls first: the parent fields of the other impls use their `Lawful` theorems.
po_body, po_counts = entries(render_po, size_first=True)
# `lawful_hyp`: a `…Lawful` hypothesis, or any parent projection of one (generated from the
# parsed structures' parent fields, to any depth), or a proved `Lawful` theorem of a core
# instance (`Assumptions/MissingCoreModelsSpecs.lean`, `Verification/Helpers.lean`).
crate_structs = {m.group(1) for m in re.finditer(r"^structure\s+(\S+\.Lawful)\s", specs_src, re.M)}
LAWFUL_HYP_LINES = ['/-- A `…Lawful` hypothesis, a parent projection of one (any depth), or the `Lawful`',
                    'theorem of a core instance. -/',
                    'syntax "lawful_hyp_aux" : tactic',
                    'macro "lawful_hyp" : tactic => `(tactic| first | assumption | lawful_hyp_aux)', '']
def _qual(sname):
    return f"tls_codec.{sname}" if sname in crate_structs else sname


def _paths(sname, depth=0):
    """Projection chains from a hypothesis of structure `sname` to its ancestors:
    yields (term wrapper builder) as a list of (struct, field) steps."""
    for f in structs[sname][1]:
        if f.parent and f.parent in structs:
            yield [(sname, f.name)]
            if depth < 3:
                for rest in _paths(f.parent, depth + 1):
                    yield [(sname, f.name)] + rest


for sname in structs:
    for steps in _paths(sname):
        term = "‹_›"
        for st, fn in steps:
            term = f"{_qual(st)}.{fn} ({term})" if term != "‹_›" else f"{_qual(st)}.{fn} {term}"
        LAWFUL_HYP_LINES.append(
            f"macro_rules | `(tactic| lawful_hyp_aux) => `(tactic| exact {term})")
for t in sorted(core_lawful_thms):
    LAWFUL_HYP_LINES.append(
        f"macro_rules | `(tactic| lawful_hyp_aux) => `(tactic| (apply {t} <;> lawful_hyp))")
LAWFUL_HYP = "\n".join(LAWFUL_HYP_LINES)

po = f"""{GEN_NOTE}
/- The generated proof obligations, discharged from their panic-freedom and
functional-correctness halves.

Layout as in hax's `examples/barrett` (lean comparator ready): this file restates every
theorem of `Extraction/ProofObligations.lean` under the same name, with the header
copied verbatim, so it is the "solution" for that "challenge" file. It must therefore
not import `Extraction/ProofObligations.lean` (the names would clash).

Nothing to prove here: each `X.spec.proof` follows from `X.spec.panic_freedom` and
`X.spec.functional_correctness`; each per-impl `I.Lawful` is a structure instance whose
method fields follow from `I.m_spec.panic_freedom` / `.functional_correctness`, and whose
parent fields (`SizeInstLawful`) come from the parent impl's `Lawful` theorem (or from a
`…InstLawful` hypothesis).
-/
import Aeneas
import CoreModels
import Hax
import {PKG}.Extraction
import {PKG}.Verification.PanicFreedom
import {PKG}.Verification.FunctionalCorrectness
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
set_option maxHeartbeats 1000000
set_option maxRecDepth 2048
set_option mvcgen.warning false

/-- Total correctness = termination without exception (`⇓ _ => True`) plus partial
correctness (`⇓?`). Holds in any `WPMonad`, by conjunctivity of `wp`. -/
theorem triple_of_panic_freedom_of_functional_correctness
    {{m : Type → Type}} {{ps : PostShape}} [Monad m] [WPMonad m ps] {{α : Type}}
    {{x : m α}} {{P : Assertion ps}} {{Q : α → Assertion ps}}
    (hpf : ⦃ P ⦄ x ⦃ ⇓ _ => ⌜ True ⌝ ⦄) (hfc : ⦃ P ⦄ x ⦃ ⇓? r => Q r ⦄) :
    ⦃ P ⦄ x ⦃ ⇓ r => Q r ⦄ :=
  Triple.of_entails_right _
    (Triple.of_entails_left _ (Triple.and x hpf hfc) (SPred.and_intro .rfl .rfl))
    (PostCond.entails.mk (fun _ => SPred.and_elim_r) (ExceptConds.and_elim_left _ _))

/-- A post that always holds: panic freedom alone gives the total triple. -/
theorem triple_of_panic_freedom_of_post_holds
    {{α : Type}} {{x : RustM α}} {{Q : α → Prop}}
    (hpf : ⦃ ⌜ True ⌝ ⦄ x ⦃ ⇓ _ => ⌜ True ⌝ ⦄) (hQ : ∀ r, Q r) :
    ⦃ ⌜ True ⌝ ⦄ x ⦃ ⇓ r => ⌜ Q r ⌝ ⦄ :=
  Triple.of_entails_right _ hpf
    (PostCond.entails.mk (fun r => SPred.pure_mono (fun _ => hQ r)) (ExceptConds.entails.refl _))

/-- Close `pre₁ → … → ⦃ P ⦄ f args ⦃ ⇓ r => Q r ⦄` (an unfolded `X.spec`, or a `Lawful`
method field) from the panic-freedom and functional-correctness lemmas of the same shape. -/
macro "pf_fc_combine " pf:ident fc:ident : tactic =>
  `(tactic| (intros
             exact triple_of_panic_freedom_of_functional_correctness
               (by apply $pf <;> assumption) (by apply $fc <;> assumption)))

/-- Close a `Lawful` method field whose post is `⌜ True ⌝` from its panic-freedom lemma. -/
macro "pf_only_combine " pf:ident : tactic =>
  `(tactic| (intros; apply $pf <;> assumption))

/-- Close a `Lawful` method field whose post `post` is `ok true` from its panic-freedom
lemma. -/
macro "pf_post_true_combine " pf:ident post:ident : tactic =>
  `(tactic| (intros
             exact triple_of_panic_freedom_of_post_holds (by apply $pf <;> assumption)
               (fun _ => by unfold $post; mvcgen)))

{LAWFUL_HYP}

/-- A parent field: the parent impl's `Lawful` theorem, its `…Lawful` arguments from the
hypotheses. -/
macro "lawful_parent " t:ident : tactic =>
  `(tactic| first | (apply $t <;> lawful_hyp) | lawful_hyp)

noncomputable section

namespace tls_codec
""" + po_body + "\nend tls_codec\n\nend\n"

if MERGE:  # merge both before writing anything, so a refusal leaves the files untouched
    src_dir = FROM or VER
    pf = merge(os.path.join(VER, "PanicFreedom.lean"), pf, os.path.join(src_dir, "PanicFreedom.lean"))
    fc = merge(os.path.join(VER, "FunctionalCorrectness.lean"), fc,
               os.path.join(src_dir, "FunctionalCorrectness.lean"))
write(os.path.join(VER, "PanicFreedom.lean"), pf)
write(os.path.join(VER, "FunctionalCorrectness.lean"), fc)
write(os.path.join(VER, "ProofObligations.lean"), po)
for label, c in (("PanicFreedom", pf_counts), ("FunctionalCorrectness", fc_counts),
                 ("ProofObligations", po_counts)):
    print(f"{label}: {sum(c.values())} theorems; " + ", ".join(f"{t}={c[t]}" for t in TAGS))
