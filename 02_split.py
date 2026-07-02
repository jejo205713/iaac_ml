#!/usr/bin/env python3
"""Family-grouped, class-stratified 80/10/10 split of corpus_raw.jsonl.

Whole families stay in one split so templated near-duplicates can't leak across
train/test (ml_build.md §9). Writes splits/{train,val,test}.jsonl (full
provenance) and splits/{train,val,test}_min.jsonl in the {command,expected}
eval format. The test split stays REAL-only — augmentation is added later to
train only. Copies the test set to dataset/test_set.jsonl (the §12 deliverable).
"""
import json, os, collections, random, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
IN = os.path.join(HERE, "corpus_raw.jsonl")
OUTD = os.path.join(HERE, "splits")
SEED = 1337


def main():
    os.makedirs(OUTD, exist_ok=True)
    rows = [json.loads(l) for l in open(IN) if l.strip()]
    fam_rows = collections.defaultdict(list)
    for r in rows:
        fam_rows[r["family_id"]].append(r)
    fam_class = {fam: collections.Counter(r["expected"] for r in rs).most_common(1)[0][0]
                 for fam, rs in fam_rows.items()}
    by_class = collections.defaultdict(list)
    for fam, c in fam_class.items():
        by_class[c].append(fam)

    rng = random.Random(SEED)
    split_fams = {"train": set(), "val": set(), "test": set()}
    for c, fams in by_class.items():
        fams = sorted(fams)
        rng.shuffle(fams)
        n = len(fams)
        if n < 3:  # too few families to split -> keep in train
            split_fams["train"].update(fams)
            continue
        ntest = max(1, round(n * 0.1))
        nval = max(1, round(n * 0.1))
        split_fams["test"].update(fams[:ntest])
        split_fams["val"].update(fams[ntest:ntest + nval])
        split_fams["train"].update(fams[ntest + nval:])

    def which(fam):
        for s in ("test", "val", "train"):
            if fam in split_fams[s]:
                return s
        return "train"

    buckets = {"train": [], "val": [], "test": []}
    for r in rows:
        buckets[which(r["family_id"])].append(r)

    for s, rs in buckets.items():
        with open(os.path.join(OUTD, f"{s}.jsonl"), "w") as fh:
            for r in rs:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        with open(os.path.join(OUTD, f"{s}_min.jsonl"), "w") as fh:
            for r in rs:
                fh.write(json.dumps({"command": r["command"], "expected": r["expected"]},
                                    ensure_ascii=False) + "\n")
        cc = collections.Counter(r["expected"] for r in rs)
        print(f"{s:5s} n={len(rs):6d}  " + " ".join(f"{k}={cc[k]}" for k in sorted(cc)))

    shutil.copy(os.path.join(OUTD, "test_min.jsonl"), os.path.join(HERE, "test_set.jsonl"))
    print("wrote deliverable", os.path.join(HERE, "test_set.jsonl"))


if __name__ == "__main__":
    main()
