# Model card — iaac-scorer-v1.0.0

Command-intent classifier for IAAC (see `../../ml_build.md`). Given a shell command,
outputs one of 6 intents (+UNKNOWN escape hatch), a 0–100 risk score, and a
calibrated confidence. Replaces `llama-guard3:1b` (0.81 F1 / 36% FP / 4.4 s).

**Status: v1 baseline. Passes the size + latency gates; below the accuracy gates.
Data-limited, not model-limited — safe to soak in observe-only, NOT to enforce.**

## Architecture
- Base: `distilbert-base-uncased` (66M params), linear head over pooled [CLS] → 6 classes, softmax.
- Preprocessing: WordPiece, max_seq_len 96, command truncated to 4096 chars. Command-only (no `context` fields used in v1 — degrades gracefully by design).
- Export: ONNX FP32 via torch 2.11 dynamo exporter (INT8 dynamic quant hit an onnxruntime shape-inference bug on the dynamo graph; FP32 is 268 MB < 300 MB gate so INT8 deferred).
- Inference: `score.py`, onnxruntime + numpy + tokenizers only (no torch/transformers).

## Training data
- Corpus: 11,567 rows / 3,961 families (the state at v1 train time; corpus has since grown to ~12.8k+ and is expanding — this card is for the v1 snapshot).
- Sources: 30-agent harvest (attack + sector-admin realism) + public sets (Atomic Red Team MIT, NL2Bash-adjacent, tldr/docs) + generators. ~87% synthetic / agent-authored, ~13% canonical. **0% real live telemetry** (the top v2 lever).
- Class counts (train-time corpus): ADMIN 4,899 · BENIGN 2,960 · EXPLOIT 1,304 · EXFILTRATION 1,092 · PERSISTENCE 677 · RECON 635.
- Split: family-grouped 80/10/10 (no leakage). Train 9,134 → +obfuscation-augment (attack classes only) → 17,843. Val 1,344. Test 1,089 (real, un-augmented — `../test_set.jsonl`).

## Hyperparameters
AdamW lr 3e-5, warmup 6%, weight decay 0.01, batch 16, 3 epochs (best val macro-F1 = epoch 2). Class-weighted CE with 1.3× weight on the 4 attack classes. max_seq_len 96. CPU-only train (~2.6 h, 8 cores).

## Calibration
Temperature scaling on val → **T = 1.361**. UNKNOWN emitted when calibrated confidence < 0.55. Risk score = per-class band centre × (0.6 + 0.4·confidence).

## Eval — locked test set (n=1,089)

| Metric | v1 | Gate (§11) | Pass |
|---|---|---|---|
| Macro-F1 (6-class) | **0.766** | ≥0.95 | ❌ |
| Unsafe recall | **0.856** | ≥0.97 | ❌ |
| FP rate (safe→unsafe) | **0.056** | ≤0.03 | ❌ |
| p99 latency (CPU, warm) | **38.5 ms** (mean 14) | ≤150 ms | ✅ |
| Model size | **268.6 MB** | ≤300 MB | ✅ |

Per-class F1: EXFILTRATION 0.93 · PERSISTENCE 0.87 · EXPLOIT 0.84 · ADMIN 0.80 · BENIGN 0.66 · **RECON 0.51**.

Dominant errors (confusion matrix): BENIGN↔ADMIN churn (fuzzy boundary, mostly within-safe so low product cost) and RECON↔BENIGN (the FP + macro-F1 drag). Cross-boundary attack leaks (EXPLOIT/PERSIST→ADMIN) are small but present — the reason for observe-only, not enforce.

## Known limitations / v2 plan
1. **RECON weak (0.51) & BENIGN↔ADMIN fuzzy** — cap on macro-F1.
2. **No live telemetry** — #1 fix: real BENIGN/ADMIN distribution + real grey-zone.
3. **RECON/PERSISTENCE under §6 target** — grow to ~2k (in progress).
4. **INT8** — revisit via optimum/onnxruntime static quant for smaller/faster ship.
5. Then: error-analysis + hard-negative loop; benchmark CodeBERT.

## Files
`model.onnx` (FP32) · `tokenizer/` · `score.py` · `calibration.json` · `requirements.txt` · `../test_set.jsonl`.
