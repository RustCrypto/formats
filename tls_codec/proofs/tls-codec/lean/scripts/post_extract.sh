#!/bin/sh
# WORKAROUND (tooling skew):
# the installed cargo-hax (hax main 721d1a27) writes Lean-module wrappers
# (`module` / `public import`), but the pinned aeneas library and TlsCodec are on
# Lean v4.31 with non-module files, and a `module` cannot import a non-module.
# Strip the module syntax from the three hax-written wrappers.
# Run after every `cargo hax extract tls-codec`. Undo: delete this script once
# the whole stack (TlsCodec, aeneas, Lean) moves to the module system.
cd "$(dirname "$0")/.." || exit 1
for f in TlsCodec/Extraction.lean TlsCodec/Extraction/FunsExternal.lean TlsCodec/Extraction/TypesExternal.lean; do
  # `module` and the blank line hax puts after it, then `public import`
  sed -i -e '/^module$/{N;d;}' -e 's/^public import /import /' "$f"
done

# WORKAROUND (aeneas bug):
# a generic trait method called at a type that contains a mutable borrow,
# `T::tls_deserialize::<Take<&mut R>>(&mut sub)` (the `Vec<T>`, `TlsVecU*` and
# `SecretTlsVecU*` `std` deserializers), is destructured as if it returned a
# backward function `Take R → Take R`, but the trait field (generic in `R`) returns
# only `(result, reader)`: "expected a product type, got core.io.util.Take R".
# Rust's parametricity makes that backward function the identity (the method
# cannot replace the `&mut R` inside the `Take`), so bind it as such.
# Undo: delete this block once aeneas types the call by the trait field.
f=TlsCodec/Extraction/Funs.lean
n=$(grep -c '^    let (r, sub, tls_deserialize_back) ←$' "$f")
done_n=$(grep -c '^    let tls_deserialize_back := fun (x : core.io.util.Take R) => x$' "$f")
if [ "$n" = 0 ] && [ "$done_n" = 9 ]; then
  exit 0  # already patched
fi
if [ "$n" != 9 ]; then
  echo "post_extract.sh: expected 9 'tls_deserialize_back' sites in $f, found $n" >&2
  exit 1
fi
sed -i 's/^    let (r, sub, tls_deserialize_back) ←$/    let tls_deserialize_back := fun (x : core.io.util.Take R) => x\n    let (r, sub) ←/' "$f"
