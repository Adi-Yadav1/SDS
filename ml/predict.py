"""Predict on new flows using the saved pipeline (same preprocessing as training).

CLI: python -m ml.predict --csv flows.csv [--limit N]
Input must contain the model's feature columns (UNSW-NB15 schema); extras are ignored.
"""
import argparse

import joblib
import pandas as pd

from ml import common

_cache = {}


def load_model(path=common.MODEL_PATH):
    if not path.is_file():
        raise FileNotFoundError(f"Model not found: {path}. Run `python -m ml.train` first.")
    if path not in _cache:
        _cache[path] = joblib.load(path)
    return _cache[path]


def predict(df: pd.DataFrame, path=common.MODEL_PATH) -> pd.DataFrame:
    art = load_model(path)
    missing = [c for c in art["features"] if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required feature columns: {missing}")
    X = df[art["features"]]
    proba = art["pipeline"].predict_proba(X)
    idx = proba.argmax(axis=1)
    out = pd.DataFrame({"predicted_class": [art["classes"][i] for i in idx],
                        "confidence": proba.max(axis=1)}, index=df.index)
    out["is_attack"] = out["predicted_class"] != "Normal"
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=None)
    ap.add_argument("--limit", type=int, default=10)
    a = ap.parse_args()
    _, X_te, _, y_te = common.split(common.load_dataset(a.csv))
    X_te, y_te = X_te.head(a.limit), y_te.head(a.limit)
    res = predict(X_te)
    res.insert(0, "true_class", y_te.values)
    print(res.to_string())


if __name__ == "__main__":
    main()
