#!/usr/bin/env bash
# IAAC command-intent dataset pipeline. Run after the harvest agents have
# written seeds into dataset/seeds/*.jsonl (see ml_build.md §15).
set -euo pipefail
cd "$(dirname "$0")"

echo "== 1. merge + dedup + family_id =="
python3 01_merge_dedup.py

echo; echo "== 2. family-grouped 80/10/10 split =="
python3 02_split.py

echo; echo "== 3. obfuscation-augment train only =="
python3 03_augment_train.py

echo; echo "== 4. TF-IDF + LogReg baseline (sanity gate) =="
python3 04_train_baseline.py
