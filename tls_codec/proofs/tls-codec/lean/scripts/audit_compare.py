#!/usr/bin/env python3
"""Compare the current `scripts/audit_*_clean.txt` with a saved baseline directory (PE1 gate).

    python3 scripts/audit_compare.py BASELINE_DIR

Per group: counts, theorems lost (regressions), theorems gained, and theorems whose
axiom set changed. Exit code 1 on any loss or any new axiom.
"""
import os
import sys

GROUPS = ['PF', 'FC', 'PO', 'LPF', 'LFC', 'LAW']


def load(path):
    d = {}
    for line in open(path):
        line = line.rstrip('\n')
        if not line:
            continue
        parts = line.split('\t')
        d[parts[0]] = set(a.strip() for a in parts[-1].strip('[]').split(',') if a.strip())
    return d


def main():
    base = sys.argv[1]
    here = os.path.join(os.path.dirname(__file__))
    bad = False
    for g in GROUPS:
        b = load(os.path.join(base, f'audit_{g}_clean.txt'))
        c = load(os.path.join(here, f'audit_{g}_clean.txt'))
        lost = sorted(set(b) - set(c))
        gained = sorted(set(c) - set(b))
        newax = sorted(n for n in set(b) & set(c) if c[n] - b[n])
        print(f'{g}: baseline {len(b)} now {len(c)} lost {len(lost)} gained {len(gained)} new-axiom {len(newax)}')
        for n in lost:
            print('  LOST', n)
        for n in gained:
            print('  GAINED', n)
        for n in newax:
            print('  NEWAX', n, sorted(c[n] - b[n]))
        bad |= bool(lost or newax)
    sys.exit(1 if bad else 0)


if __name__ == '__main__':
    main()
