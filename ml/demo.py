"""Demo: classify held-out UNSW-NB15 flows with the saved model (dataset REPLAY, not live traffic).

python -m ml.demo [--per-class 2] [--seed 1]
Prints true vs predicted class + confidence, and appends detections to logs/detections.jsonl.
"""
import argparse
import json
import time

from ml import common
from ml.predict import predict

KEY = ["proto", "service", "state", "dur", "spkts", "dpkts", "sbytes", "dbytes", "rate"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-class", type=int, default=2)
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()
    _, X_te, _, y_te = common.split(common.load_dataset())  # rows the model never trained on
    idx = y_te.groupby(y_te).sample(a.per_class, random_state=a.seed).index
    X, y = X_te.loc[idx], y_te.loc[idx]
    res = predict(X)
    print("MODE: replay of held-out UNSW-NB15 flows (NOT live Mininet traffic)\n")
    print(f"{'true':<15}{'predicted':<15}{'conf':>6}  {'verdict':<8} key features")
    common.RESULTS.parent.joinpath("logs").mkdir(exist_ok=True)
    ok = 0
    with open(common.ROOT / "logs" / "detections.jsonl", "a") as f:
        for i in idx:
            r, t = res.loc[i], y.loc[i]
            ok += r.predicted_class == t
            kf = {k: (round(float(X.loc[i, k]), 4) if k not in common.CATEGORICAL else X.loc[i, k]) for k in KEY}
            print(f"{t:<15}{r.predicted_class:<15}{r.confidence:>6.2f}  "
                  f"{'ATTACK' if r.is_attack else 'normal':<8} {kf['proto']}/{kf['service']} dur={kf['dur']} "
                  f"spkts={kf['spkts']} sbytes={kf['sbytes']}")
            f.write(json.dumps({"timestamp": time.time(), "source": "dataset_replay", "true_class": t,
                                "predicted_class": r.predicted_class, "confidence": float(r.confidence),
                                "is_attack": bool(r.is_attack), "features": kf, "mitigation": None}) + "\n")
    print(f"\n{ok}/{len(idx)} correct on this sample (full held-out metrics: results/metrics.json)")


if __name__ == "__main__":
    main()
