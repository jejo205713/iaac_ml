#!/usr/bin/env python3
"""Obfuscation-augment the TRAIN split only (never val/test).

Attack classes only; label unchanged, is_obfuscated=true, family_id preserved
(so variants never leak into val/test). Writes splits/train_aug.jsonl.
"""
import json, os, random, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib_augment import augment_variants, ATTACK_CLASSES

HERE = os.path.dirname(os.path.abspath(__file__))
IN = os.path.join(HERE, "splits", "train.jsonl")
OUT = os.path.join(HERE, "splits", "train_aug.jsonl")
MAX_VARIANTS = 3
SEED = 1337


def main():
    rng = random.Random(SEED)
    rows = [json.loads(l) for l in open(IN) if l.strip()]
    out = list(rows)
    added = 0
    for r in rows:
        if r["expected"] in ATTACK_CLASSES:
            for v in augment_variants(r["command"], rng, MAX_VARIANTS):
                nr = dict(r)
                nr["command"] = v
                nr["is_obfuscated"] = True
                nr["is_synthetic"] = True
                out.append(nr)
                added += 1
    rng.shuffle(out)
    with open(OUT, "w") as fh:
        for r in out:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"train base={len(rows)} +aug={added} total={len(out)} -> {OUT}")


if __name__ == "__main__":
    main()
