#!/usr/bin/env python3
"""Remove or extract top-level declarations of a Lean file by name (PE1 refactor helper).

    python3 scripts/decl_tool.py rm   FILE NAME...   # delete the declarations (with doc comment / attributes)
    python3 scripts/decl_tool.py show FILE NAME...   # print them

A declaration starts at its `theorem|lemma|def|abbrev ... NAME` line, extended upward over the
attribute line and the `/-- … -/` doc comment directly above it, and ends before the next
top-level item (a line starting with `theorem`, `@[`, `/--`, `/-!`, `def`, `end`, `namespace`,
`section`, `noncomputable`, `abbrev`, `lemma`, `instance`, `example`, `#`, `open`, `set_option`,
`attribute`, `macro`, `syntax`), trailing blank lines included.
"""
import re
import sys

TOP = re.compile(r'^(theorem|lemma|def|abbrev|noncomputable|instance|example|@\[|/--|/-!|end\b|namespace|section|#|open|set_option|attribute|macro|syntax|private|protected)')


def find(lines, name):
    pat = re.compile(r'^(@\[[^\]]*\]\s*)?(private |protected |noncomputable )?(theorem|lemma|def|abbrev)\s+' + re.escape(name) + r'(\s|$)')
    hits = [i for i, l in enumerate(lines) if pat.match(l)]
    if len(hits) != 1:
        sys.exit(f'{name}: {len(hits)} matches')
    i = hits[0]
    start = i
    if start > 0 and lines[start - 1].startswith('@['):
        start -= 1
    if start > 0 and lines[start - 1].rstrip().endswith('-/'):
        j = start - 1
        while not lines[j].startswith('/--'):
            j -= 1
            if j < 0 or lines[j].strip() == '':
                sys.exit(f'{name}: unterminated doc comment')
        start = j
    end = i + 1
    while end < len(lines) and not TOP.match(lines[end]):
        end += 1
    return start, end


def main():
    mode, path, names = sys.argv[1], sys.argv[2], sys.argv[3:]
    lines = open(path).read().split('\n')
    spans = sorted(find(lines, n) for n in names)
    if mode == 'show':
        for s, e in spans:
            print('\n'.join(lines[s:e]))
        return
    assert mode == 'rm'
    for s, e in reversed(spans):
        del lines[s:e]
    open(path, 'w').write('\n'.join(lines))
    print(f'removed {len(spans)} declarations, {sum(e - s for s, e in spans)} lines')


if __name__ == '__main__':
    main()
