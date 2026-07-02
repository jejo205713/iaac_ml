#!/usr/bin/env python3
"""Baseline sanity model: TF-IDF (word + char n-gram) -> LogisticRegression.

This is the ml_build.md §9 baseline — it tells us whether the labels/split are
sane BEFORE spending GPU time on the transformer. Trains on train_aug (falls
back to train), evaluates on the REAL test split. Reports macro-F1, per-class
F1, confusion matrix, the safe/unsafe collapse (unsafe recall + FP rate), and
CPU latency.
"""
import json, os, time
from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, classification_report, confusion_matrix

HERE = os.path.dirname(os.path.abspath(__file__))
SP = os.path.join(HERE, "splits")
CLASSES = ["BENIGN", "ADMIN", "RECON", "EXPLOIT", "PERSISTENCE", "EXFILTRATION"]
SAFE = {"BENIGN", "ADMIN"}


def load(name):
    rows = [json.loads(l) for l in open(os.path.join(SP, name)) if l.strip()]
    return [r["command"] for r in rows], [r["expected"] for r in rows]


def main():
    train_file = "train_aug.jsonl" if os.path.exists(os.path.join(SP, "train_aug.jsonl")) else "train.jsonl"
    Xtr, ytr = load(train_file)
    Xte, yte = load("test.jsonl")

    word = TfidfVectorizer(analyzer="word", ngram_range=(1, 2), min_df=2,
                           sublinear_tf=True, token_pattern=r"[^\s]+")
    char = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, sublinear_tf=True)
    Xtr_f = hstack([word.fit_transform(Xtr), char.fit_transform(Xtr)]).tocsr()
    Xte_f = hstack([word.transform(Xte), char.transform(Xte)]).tocsr()

    clf = LogisticRegression(max_iter=2000, C=4.0, class_weight="balanced")
    clf.fit(Xtr_f, ytr)
    pred = clf.predict(Xte_f)

    macro = f1_score(yte, pred, average="macro", labels=CLASSES)
    print("\n=== BASELINE (TF-IDF word+char + LogReg) ===")
    print(f"train={len(ytr)} ({train_file})  test={len(yte)}")
    print(f"macro-F1 (6-class) = {macro:.4f}\n")
    print(classification_report(yte, pred, labels=CLASSES, digits=3, zero_division=0))

    cm = confusion_matrix(yte, pred, labels=CLASSES)
    print("confusion matrix (rows=true, cols=pred):")
    print("        " + " ".join(f"{c[:5]:>6s}" for c in CLASSES))
    for i, c in enumerate(CLASSES):
        print(f"{c[:7]:7s} " + " ".join(f"{cm[i, j]:6d}" for j in range(len(CLASSES))))

    ts = ["SAFE" if y in SAFE else "UNSAFE" for y in yte]
    ps = ["SAFE" if y in SAFE else "UNSAFE" for y in pred]
    tp = sum(1 for t, p in zip(ts, ps) if t == "UNSAFE" and p == "UNSAFE")
    fn = sum(1 for t, p in zip(ts, ps) if t == "UNSAFE" and p == "SAFE")
    fp = sum(1 for t, p in zip(ts, ps) if t == "SAFE" and p == "UNSAFE")
    tn = sum(1 for t, p in zip(ts, ps) if t == "SAFE" and p == "SAFE")
    ur = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    print(f"\nsafe/unsafe collapse: unsafe_recall={ur:.4f} (target >=0.97)  FP_rate={fpr:.4f} (target <=0.03)")

    samp = Xte[:min(200, len(Xte))]
    for s in samp[:20]:  # warm
        clf.predict(hstack([word.transform([s]), char.transform([s])]).tocsr())
    times = []
    for s in samp:
        t0 = time.perf_counter()
        clf.predict(hstack([word.transform([s]), char.transform([s])]).tocsr())
        times.append((time.perf_counter() - t0) * 1000)
    times.sort()
    print(f"latency ms (single, warm): mean={sum(times)/len(times):.2f} "
          f"p50={times[len(times)//2]:.2f} p99={times[int(len(times)*0.99)]:.2f}")


if __name__ == "__main__":
    main()
