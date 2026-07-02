# IAAC command-intent dataset pipeline

Builds the labeled corpus for the `iaac-scorer` model described in
`../ml_build.md`. Command **strings only** — nothing here executes commands.

## Layout

The training data is consolidated into **one file**, `dataset.jsonl`. The raw
upstream corpora and intermediate splits were removed to keep the repo lean
(see `DATA_SOURCES.md`); `dataset.jsonl` is fully re-splittable via its `split`
field, so nothing is lost.

```
dataset.jsonl          # THE training data — 43,253 rows, single file.
                       #   each row tagged "split": train | val | test
                       #   train rows include the obfuscation-augmented attack variants
                       #   test = REAL only, never augmented (locked eval set)
train_transformer.py   # fine-tune DistilBERT from dataset.jsonl  -> model/hf/
export_onnx.py         # export the trained model to ONNX INT8
model/                 # score.py (inference), model_card.md, tokenizer, calibration.json
                       #   (trained weights are NOT committed — rebuild them, below)

# corpus-build pipeline — retained for methodology/reference. It rebuilds
# dataset.jsonl FROM the raw source corpora, which are NOT in this repo
# (re-fetch per DATA_SOURCES.md):
#   parse_realdata.py / parse_external.py / gen_*.py  -> seeds
#   01_merge_dedup -> 02_split -> 03_augment_train     -> dataset.jsonl
#   lib_augment.py   obfuscation augmenter (attack classes, train-time)
#   04_train_baseline.py   TF-IDF+LogReg sanity gate on label/split quality
#   audit.py         corpus stats / QA
```

## Record schema (each row in `dataset.jsonl`)

```json
{"command": "...", "expected": "BENIGN|ADMIN|RECON|EXPLOIT|PERSISTENCE|EXFILTRATION",
 "source": "...", "technique": "T#### or null", "is_synthetic": false,
 "is_obfuscated": false, "family_id": "tool-op-slug", "reviewed_by": null,
 "split": "train|val|test"}
```

`family_id` groups near-duplicate/templated commands so whole families stay in one
split — this prevents the train/test leakage that inflates F1 (ml_build.md §9).

## Run

Train the shipped model directly from the consolidated dataset:

```bash
pip install -r model/requirements.txt        # or your train env
python train_transformer.py                   # fine-tune DistilBERT from dataset.jsonl
python export_onnx.py                          # -> ONNX INT8 for inference (model/score.py)
```

`run_all.sh` runs the full corpus-build → baseline → train pipeline, but stages
01–03 require the raw source corpora (not in this repo — see `DATA_SOURCES.md`).
The `04_train_baseline.py` step (TF-IDF word+char → LogisticRegression) is a
**sanity gate** on label/split quality — it reports macro-F1, per-class F1,
confusion matrix, the safe/unsafe collapse (unsafe recall + FP rate), and CPU
latency — not the shipped model.

## Live telemetry (highest-value benign data)

`../backend/export_command_events.py` exports de-identified real command events
for labeling and folding into `seeds/`:

```bash
cd ../backend && PYTHONPATH=. python export_command_events.py \
  --out ../dataset/seeds/live_export.jsonl [--email <org>] [--decision ALLOW]
```
