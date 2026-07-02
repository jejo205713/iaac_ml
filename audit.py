#!/usr/bin/env python3
"""CTO data-quality audit for corpus_raw.jsonl. Reports (does not mutate):
- label conflicts (same command, different class) — the worst training poison
- unresolved placeholders / template junk
- empty / too-short / non-command rows
- families spanning multiple classes (split-integrity risk)
- length + synthetic/source distribution
"""
import json, os, re, collections

HERE = os.path.dirname(os.path.abspath(__file__))
IN = os.path.join(HERE, "corpus_raw.jsonl")
LABELS = {"BENIGN", "ADMIN", "RECON", "EXPLOIT", "PERSISTENCE", "EXFILTRATION"}


def norm(c):
    return re.sub(r"\s+", " ", c.strip()).lower()


def main():
    rows = [json.loads(l) for l in open(IN) if l.strip()]
    n = len(rows)
    print(f"total rows: {n}")

    # 1. label conflicts
    bycmd = collections.defaultdict(set)
    for r in rows:
        bycmd[norm(r["command"])].add(r["expected"])
    conflicts = {c: labs for c, labs in bycmd.items() if len(labs) > 1}
    print(f"\n[1] LABEL CONFLICTS (same command, >1 class): {len(conflicts)}")
    for c, labs in list(conflicts.items())[:8]:
        print(f"    {sorted(labs)}  {c[:70]}")

    # 2. placeholder / template junk
    ph = re.compile(r"<[a-z_]+>|#\{|\{\{|\bYOUR_|\bTODO\b", re.I)
    junk = [r for r in rows if ph.search(r["command"])]
    print(f"\n[2] PLACEHOLDER/TEMPLATE junk: {len(junk)}")
    for r in junk[:6]:
        print(f"    {r['expected']:12s} {r['command'][:70]}")

    # 3. empty / too short / prose-like
    short = [r for r in rows if len(r["command"].strip()) < 3]
    prose = [r for r in rows if len(r["command"].split()) > 3
             and not re.search(r"[/\-|>&$;=]", r["command"]) and r["command"][0].isupper()]
    print(f"\n[3] too-short (<3 chars): {len(short)} | prose-like (no shell metachars): {len(prose)}")
    for r in prose[:6]:
        print(f"    {r['expected']:12s} {r['command'][:70]}")

    # 4. families spanning multiple classes
    fam = collections.defaultdict(set)
    for r in rows:
        fam[r["family_id"]].add(r["expected"])
    multi = {f: labs for f, labs in fam.items() if len(labs) > 1}
    print(f"\n[4] families spanning >1 class: {len(multi)} (of {len(fam)})")
    for f, labs in list(multi.items())[:6]:
        print(f"    {f}: {sorted(labs)}")

    # 5. length + source
    lens = sorted(len(r["command"]) for r in rows)
    print(f"\n[5] cmd length: min={lens[0]} p50={lens[n//2]} p95={lens[int(n*0.95)]} max={lens[-1]}")
    syn = collections.Counter(r["is_synthetic"] for r in rows)
    print(f"    synthetic: True={syn[True]} False={syn[False]}")
    src = collections.Counter(r["source"] for r in rows)
    print("    sources:", dict(src.most_common(8)))


if __name__ == "__main__":
    main()
