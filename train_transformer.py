#!/usr/bin/env python3
"""Fine-tune DistilBERT as the IAAC command-intent classifier (ml_build.md §3, §9).

- 6-class sequence classifier over the pooled [CLS] embedding
- class-weighted CE with extra weight on the 4 attack classes (protect the
  safe<->unsafe boundary that §4 calls the costliest error)
- trains on train_aug (obfuscation-augmented), early-checkpoints best val macro-F1
- temperature-scales on val for calibrated confidence (§11)
- evaluates on the REAL locked test split and writes model/calibration.json

Env overrides: BASE_MODEL, MAXLEN, BATCH, EPOCHS, LR.
"""
import os, json, time, random, collections
import numpy as np
import torch
from torch.utils.data import Dataset, DataLoader
from transformers import (AutoTokenizer, AutoModelForSequenceClassification,
                          get_linear_schedule_with_warmup)
from sklearn.metrics import f1_score, classification_report, confusion_matrix

HERE = os.path.dirname(os.path.abspath(__file__))
DATASET = os.path.join(HERE, "dataset.jsonl")   # single consolidated file; rows tagged split=train|val|test
OUTD = os.path.join(HERE, "model")
HFD = os.path.join(OUTD, "hf")
os.makedirs(HFD, exist_ok=True)

LABELS = ["BENIGN", "ADMIN", "RECON", "EXPLOIT", "PERSISTENCE", "EXFILTRATION"]
L2I = {l: i for i, l in enumerate(LABELS)}
SAFE = {"BENIGN", "ADMIN"}
ATTACK_IDS = [L2I[l] for l in ("RECON", "EXPLOIT", "PERSISTENCE", "EXFILTRATION")]

BASE = os.environ.get("BASE_MODEL", "distilbert-base-uncased")
MAXLEN = int(os.environ.get("MAXLEN", "96"))
BATCH = int(os.environ.get("BATCH", "16"))
EPOCHS = int(os.environ.get("EPOCHS", "3"))
LR = float(os.environ.get("LR", "3e-5"))
SEED = 1337

torch.manual_seed(SEED); random.seed(SEED); np.random.seed(SEED)
torch.set_num_threads(os.cpu_count() or 4)
tok = AutoTokenizer.from_pretrained(BASE)


def load(split):
    rows = [json.loads(l) for l in open(DATASET) if l.strip()]
    rows = [r for r in rows if r.get("split") == split]
    return [r["command"] for r in rows], [L2I[r["expected"]] for r in rows]


class DS(Dataset):
    def __init__(self, X, y): self.X, self.y = X, y
    def __len__(self): return len(self.X)
    def __getitem__(self, i): return self.X[i], self.y[i]


def collate(batch):
    xs = [b[0] for b in batch]
    ys = [b[1] for b in batch]
    enc = tok(xs, truncation=True, max_length=MAXLEN, padding=True, return_tensors="pt")
    enc["labels"] = torch.tensor(ys)
    return enc


def evaluate(model, X, y):
    model.eval()
    preds, logits_all = [], []
    dl = DataLoader(DS(X, y), batch_size=64, collate_fn=collate)
    with torch.no_grad():
        for enc in dl:
            enc.pop("labels")
            out = model(**enc)
            logits_all.append(out.logits.cpu())
            preds.extend(out.logits.argmax(-1).tolist())
    return f1_score(y, preds, average="macro"), preds, torch.cat(logits_all)


def fit_temperature(logits, labels):
    T = torch.nn.Parameter(torch.ones(1))
    opt = torch.optim.LBFGS([T], lr=0.01, max_iter=100)
    nll = torch.nn.CrossEntropyLoss()
    def closure():
        opt.zero_grad()
        loss = nll(logits / T, labels)
        loss.backward()
        return loss
    opt.step(closure)
    return float(T.detach().clamp(min=0.05))


def main():
    Xtr, ytr = load("train")   # split=train == the obfuscation-augmented training rows
    Xva, yva = load("val")
    Xte, yte = load("test")
    print(f"train={len(Xtr)} val={len(Xva)} test={len(Xte)} base={BASE} maxlen={MAXLEN} "
          f"batch={BATCH} epochs={EPOCHS} threads={torch.get_num_threads()}", flush=True)

    cnt = collections.Counter(ytr)
    N, K = len(ytr), len(LABELS)
    w = torch.tensor([N / (K * cnt[i]) for i in range(K)], dtype=torch.float)
    for i in ATTACK_IDS:
        w[i] *= 1.3
    print("class weights", [round(float(x), 3) for x in w], flush=True)

    model = AutoModelForSequenceClassification.from_pretrained(BASE, num_labels=K)
    lossf = torch.nn.CrossEntropyLoss(weight=w)
    opt = torch.optim.AdamW(model.parameters(), lr=LR, weight_decay=0.01)
    dl = DataLoader(DS(Xtr, ytr), batch_size=BATCH, shuffle=True, collate_fn=collate)
    total_steps = len(dl) * EPOCHS
    sch = get_linear_schedule_with_warmup(opt, int(0.06 * total_steps), total_steps)

    best, t0 = -1.0, time.time()
    for ep in range(EPOCHS):
        model.train(); run = 0.0
        for step, enc in enumerate(dl):
            labels = enc.pop("labels")
            out = model(**enc)
            loss = lossf(out.logits, labels)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step(); sch.step(); opt.zero_grad()
            run += loss.item()
            if step % 100 == 0:
                print(f"ep{ep} step{step}/{len(dl)} loss={run/(step+1):.4f} "
                      f"elapsed={time.time()-t0:.0f}s", flush=True)
        macro, _, _ = evaluate(model, Xva, yva)
        print(f"== epoch {ep} val macro-F1={macro:.4f} (best={max(best,macro):.4f}) ==", flush=True)
        if macro > best:
            best = macro
            model.save_pretrained(HFD); tok.save_pretrained(HFD)
            print(f"  saved best -> {HFD}", flush=True)

    model = AutoModelForSequenceClassification.from_pretrained(HFD)
    _, _, val_logits = evaluate(model, Xva, yva)
    T = fit_temperature(val_logits, torch.tensor(yva))
    print(f"calibration temperature={T:.4f}", flush=True)

    macro, preds, _ = evaluate(model, Xte, yte)
    print(f"\n=== TEST (DistilBERT fine-tune) ===\nmacro-F1 (6-class) = {macro:.4f}\n", flush=True)
    print(classification_report(yte, preds, target_names=LABELS, digits=3, zero_division=0), flush=True)
    cm = confusion_matrix(yte, preds, labels=list(range(K)))
    print("confusion matrix (rows=true, cols=pred):", flush=True)
    print("        " + " ".join(f"{c[:5]:>6s}" for c in LABELS), flush=True)
    for i, c in enumerate(LABELS):
        print(f"{c[:7]:7s} " + " ".join(f"{cm[i, j]:6d}" for j in range(K)), flush=True)

    ts = ["SAFE" if LABELS[y] in SAFE else "UNSAFE" for y in yte]
    ps = ["SAFE" if LABELS[p] in SAFE else "UNSAFE" for p in preds]
    tp = sum(1 for t, p in zip(ts, ps) if t == "UNSAFE" and p == "UNSAFE")
    fn = sum(1 for t, p in zip(ts, ps) if t == "UNSAFE" and p == "SAFE")
    fp = sum(1 for t, p in zip(ts, ps) if t == "SAFE" and p == "UNSAFE")
    tn = sum(1 for t, p in zip(ts, ps) if t == "SAFE" and p == "SAFE")
    print(f"\nsafe/unsafe: unsafe_recall={tp/(tp+fn):.4f} (>=0.97)  "
          f"FP_rate={fp/(fp+tn):.4f} (<=0.03)", flush=True)

    json.dump({"labels": LABELS, "temperature": T, "maxlen": MAXLEN, "base": BASE,
               "unknown_threshold": 0.55, "model_version": "iaac-scorer-v3.0.0",
               "test_macro_f1": round(macro, 4)},
              open(os.path.join(OUTD, "calibration.json"), "w"), indent=2)
    print("wrote", os.path.join(OUTD, "calibration.json"), flush=True)
    print("DONE", flush=True)


if __name__ == "__main__":
    main()
