#!/usr/bin/env python3
"""Merge dataset/seeds/*.jsonl -> dataset/corpus_raw.jsonl.

- validates the §15.0 record schema, drops malformed / bad-label rows
- dedups exact + near-dup (whitespace-collapsed, case-folded) per (command,label)
- ensures every row has a family_id (derives one from the command if missing)
- prints per-class and safe/unsafe counts
"""
import json, glob, os, re, sys, collections

HERE = os.path.dirname(os.path.abspath(__file__))
SEEDS = os.path.join(HERE, "seeds")
OUT = os.path.join(HERE, "corpus_raw.jsonl")
LABELS = {"BENIGN", "ADMIN", "RECON", "EXPLOIT", "PERSISTENCE", "EXFILTRATION", "UNKNOWN"}


def norm_key(cmd):
    return re.sub(r"\s+", " ", cmd.strip()).lower()


def derive_family(cmd):
    toks = re.sub(r"\s+", " ", cmd.strip()).split(" ")
    base = os.path.basename(toks[0]) if toks else "misc"
    sub = toks[1] if len(toks) > 1 and not toks[1].startswith("-") else ""
    slug = re.sub(r"[^a-z0-9]+", "-", (base + "-" + sub).lower()).strip("-")
    return slug or "misc"


# label preference on ties: SAFE first (FP-averse, product rule #1), then by severity
TIEBREAK = {"BENIGN": 0, "ADMIN": 1, "RECON": 2, "EXFILTRATION": 3, "PERSISTENCE": 4, "EXPLOIT": 5}

# optional per-class cap (v3+): keeps balance when real data floods the safe classes.
# Off by default so v1/v2 corpora reproduce exactly.
MAXPERCLASS = int(os.environ.get("MAXPERCLASS", "0"))


def family_diverse(items, cap):
    """Deterministic round-robin across family_id -> maximizes technique coverage
    (keeps both real and synthetic families) when trimming a class to `cap`."""
    buckets = collections.defaultdict(list)
    for r in sorted(items, key=lambda r: r["command"]):
        buckets[r["family_id"]].append(r)
    fams = sorted(buckets)
    out, i = [], 0
    while len(out) < cap and any(buckets[f] for f in fams):
        f = fams[i % len(fams)]
        if buckets[f]:
            out.append(buckets[f].pop(0))
        i += 1
    return out


def main():
    files = sorted(glob.glob(os.path.join(SEEDS, "*.jsonl")))
    if not files:
        print("No seed files in", SEEDS)
        sys.exit(1)
    # gather every occurrence per unique normalized command
    bycmd = collections.defaultdict(list)   # nkey -> list of raw rows
    dropped_bad = 0
    for f in files:
        for line in open(f):
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except Exception:
                dropped_bad += 1
                continue
            cmd = (r.get("command") or "").strip()[:4096]
            lab = r.get("expected")
            if lab not in LABELS or len(re.sub(r"\s", "", cmd)) < 2:  # drop empty/1-char junk
                dropped_bad += 1
                continue
            r["command"] = cmd
            bycmd[norm_key(cmd)].append(r)

    rows, conflicts_resolved = [], 0
    for nkey, occs in bycmd.items():
        labs = collections.Counter(o["expected"] for o in occs)
        if len(labs) > 1:
            conflicts_resolved += 1
        # winner: highest count, tiebreak by SAFE-first preference
        winner = min(labs.items(), key=lambda kv: (-kv[1], TIEBREAK[kv[0]]))[0]
        pick = next(o for o in occs if o["expected"] == winner)  # keep a row that had the winning label
        cmd = pick["command"]
        rows.append({
            "command": cmd,
            "expected": winner,
            "source": pick.get("source") or "unknown",
            "technique": pick.get("technique"),
            "is_synthetic": bool(pick.get("is_synthetic", False)),
            "is_obfuscated": bool(pick.get("is_obfuscated", False)),
            "family_id": (pick.get("family_id") or "").strip() or derive_family(cmd),
            "reviewed_by": pick.get("reviewed_by"),
        })
    dropped_dup = sum(len(v) for v in bycmd.values()) - len(rows)

    if MAXPERCLASS:
        byc = collections.defaultdict(list)
        for r in rows:
            byc[r["expected"]].append(r)
        capped, dropped_cap = [], 0
        for c, items in byc.items():
            if len(items) <= MAXPERCLASS:
                capped += items
            else:
                keep = family_diverse(items, MAXPERCLASS)
                capped += keep
                dropped_cap += len(items) - len(keep)
        rows = capped
        print(f"cap={MAXPERCLASS}/class dropped_over_cap={dropped_cap}")

    with open(OUT, "w") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    by_class = collections.Counter(r["expected"] for r in rows)
    fams = len({r["family_id"] for r in rows})
    print(f"files={len(files)} kept={len(rows)} dup/collapsed={dropped_dup} "
          f"bad={dropped_bad} conflicts_resolved={conflicts_resolved} families={fams}")
    for c in sorted(by_class):
        print(f"  {c:14s} {by_class[c]}")
    safe = by_class["BENIGN"] + by_class["ADMIN"]
    unsafe = sum(by_class[c] for c in ("RECON", "EXPLOIT", "PERSISTENCE", "EXFILTRATION"))
    print(f"  SAFE={safe} UNSAFE={unsafe} -> {OUT}")


if __name__ == "__main__":
    main()
