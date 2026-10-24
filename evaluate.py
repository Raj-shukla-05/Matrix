"""Measure JobShield on labelled messages.

python evaluate.py        -> the 20 demo samples in samples.py
python evaluate.py real   -> YOUR real messages in real_samples.txt (use this number on the slide)
"""
import os
import sys

import engine
from samples import SAMPLES

REAL_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "real_samples.txt")


def load_real(path=REAL_FILE):
    """Format: a line '### scam' or '### genuine' starts each message. Text below it is the message."""
    items, label, buf = [], None, []

    def flush():
        text = "\n".join(buf).strip()
        if label and text:
            items.append({"title": f"real #{len(items) + 1}: {text[:45]!r}", "label": label, "text": text})

    for line in open(path, encoding="utf-8"):
        tag = line.strip().lower()
        if tag in ("### scam", "### genuine"):
            flush()
            label, buf = tag[4:], []
        elif not line.lstrip().startswith("#"):
            buf.append(line.rstrip("\n"))
    flush()
    return items


def run(samples, verbose=True):
    tp = fp = tn = fn = 0
    rows = []
    for s in samples:
        r = engine.analyze(s["text"], live=False)
        flagged = r["verdict"] != "SAFE"
        is_scam = s["label"] == "scam"
        if is_scam and flagged:
            tp += 1
        elif is_scam and not flagged:
            fn += 1
        elif not is_scam and flagged:
            fp += 1
        else:
            tn += 1
        rows.append((flagged == is_scam, s["label"], r["verdict"], r["score"], s["title"], [f.id for f in r["flags"]]))

    total = tp + fp + tn + fn
    if total == 0:
        print("No messages found.")
        return 0, 0, 0
    acc = (tp + tn) / total
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0

    if verbose:
        print(f"{'OK':<4}{'LABEL':<9}{'VERDICT':<12}{'SCORE':<7}TITLE")
        for ok, label, verdict, score, title, ids in rows:
            print(f"{'yes' if ok else 'NO':<4}{label:<9}{verdict:<12}{score:<7}{title}")
            if not ok:
                print(f"      flags: {ids}")
        print()
        print("Confusion matrix (risky = SUSPICIOUS or SCAM)")
        print("            predicted risky   predicted safe")
        print(f"actual scam        {tp:>3}              {fn:>3}")
        print(f"actual genuine     {fp:>3}              {tn:>3}")
        print()
        print(f"Correct: {tp + tn} of {total}  |  accuracy {acc:.0%}  |  precision {prec:.0%}  |  recall {rec:.0%}")
        if tp + fn < 8 or fp + tn < 8:
            print("Warning: fewer than 8 messages in one class. The number is weak evidence.")
    return acc, prec, rec


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "real":
        run(load_real())
    else:
        run(SAMPLES)
