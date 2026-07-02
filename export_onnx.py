#!/usr/bin/env python3
"""Export the fine-tuned model to ONNX (+ optional INT8) for onnxruntime CPU.

Uses torch 2.11's dynamo exporter (the legacy tracer fails on transformers 5.x
SDPA masking). FP32 DistilBERT (~268 MB) is already under the 300 MB gate, so
INT8 is a nice-to-have: we attempt it and fall back to FP32 if quantization
errors. Verifies the shipped model loads in onnxruntime and matches torch.
"""
import os, shutil, torch, numpy as np
import onnxruntime as ort
from transformers import AutoTokenizer, AutoModelForSequenceClassification

HERE = os.path.dirname(os.path.abspath(__file__))
OUTD = os.path.join(HERE, "model")
HFD = os.path.join(OUTD, "hf")
FP32 = os.path.join(OUTD, "model_fp32.onnx")
SHIP = os.path.join(OUTD, "model.onnx")
MAXLEN = 96


def main():
    tok = AutoTokenizer.from_pretrained(HFD)
    tok.save_pretrained(os.path.join(OUTD, "tokenizer"))
    print("wrote tokenizer/", flush=True)

    model = AutoModelForSequenceClassification.from_pretrained(HFD)
    model.eval()
    enc = tok("sudo apt update", return_tensors="pt", max_length=MAXLEN, truncation=True)
    with torch.no_grad():
        ref = model(**enc).logits.numpy()

    prog = torch.onnx.export(
        model, (enc["input_ids"], enc["attention_mask"]),
        input_names=["input_ids", "attention_mask"], output_names=["logits"],
        dynamic_axes={"input_ids": {0: "b", 1: "s"},
                      "attention_mask": {0: "b", 1: "s"}, "logits": {0: "b"}},
        dynamo=True)
    prog.save(FP32)
    print(f"wrote {FP32} {os.path.getsize(FP32)/1e6:.1f} MB (+ .data)", flush=True)

    shipped_is_int8 = False
    try:
        from onnxruntime.quantization import quantize_dynamic, QuantType
        quantize_dynamic(FP32, SHIP, weight_type=QuantType.QInt8)
        print(f"wrote {SHIP} (INT8) {os.path.getsize(SHIP)/1e6:.1f} MB", flush=True)
        shipped_is_int8 = True
    except Exception as e:
        print(f"INT8 quant failed ({type(e).__name__}: {e}); shipping FP32", flush=True)
        shutil.copy(FP32, SHIP)
        if os.path.exists(FP32 + ".data"):
            shutil.copy(FP32 + ".data", SHIP + ".data")

    # verify shipped model loads + matches torch
    s = ort.InferenceSession(SHIP, providers=["CPUExecutionProvider"])
    out = s.run(None, {"input_ids": enc["input_ids"].numpy(),
                       "attention_mask": enc["attention_mask"].numpy()})[0]
    agree = int(ref.argmax()) == int(out.argmax())
    print(f"verify: torch_argmax={int(ref.argmax())} onnx_argmax={int(out.argmax())} "
          f"agree={agree} int8={shipped_is_int8}", flush=True)
    assert agree, "shipped ONNX disagrees with torch on the smoke sample"


if __name__ == "__main__":
    main()
