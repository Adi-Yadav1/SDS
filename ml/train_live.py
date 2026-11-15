"""Train the reduced 'live' model: binary attack-vs-normal on OpenFlow-derivable features only.

Same de-duplicated, stratified, seed-42 split as ml/train.py (so test rows are identical), but the
model only sees the 11 columns in ml/live_features.LIVE_FEATURES. This is the model the SDN
controller uses on real Mininet flows.

    python -m ml.train_live            -> results/live_model.joblib, results/live_metrics.json
"""
import argparse
import json
import platform
import time

import joblib
import numpy as np
import sklearn
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

from ml import common
from ml.live_features import LIVE_CATEGORICAL, LIVE_FEATURES

LIVE_MODEL_PATH = common.RESULTS / "live_model.joblib"
LIVE_METRICS_PATH = common.RESULTS / "live_metrics.json"


def build_live_pipeline(n_estimators=100):
    pre = ColumnTransformer(
        [("cat", OneHotEncoder(handle_unknown="ignore"), LIVE_CATEGORICAL)],
        remainder="passthrough")
    clf = RandomForestClassifier(
        n_estimators=n_estimators, class_weight="balanced_subsample", min_samples_leaf=2,
        max_depth=20, n_jobs=-1, random_state=common.SEED)
    return Pipeline([("pre", pre), ("rf", clf)])


def binary_metrics(y_true, prob, threshold):
    pred = (prob >= threshold).astype(int)
    return {
        "threshold": threshold,
        "accuracy": accuracy_score(y_true, pred),
        "precision": precision_score(y_true, pred, zero_division=0),
        "recall": recall_score(y_true, pred, zero_division=0),
        "f1": f1_score(y_true, pred, zero_division=0),
        "confusion_matrix [[TN,FP],[FN,TP]]": confusion_matrix(y_true, pred).tolist(),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=None)
    ap.add_argument("--n-estimators", type=int, default=100)
    a = ap.parse_args()

    df = common.load_dataset(a.data)
    X_tr, X_te, y_tr, y_te = common.split(df)
    X_tr, X_te = X_tr[LIVE_FEATURES], X_te[LIVE_FEATURES]
    yb_tr = (y_tr != "Normal").astype(int).to_numpy()
    yb_te = (y_te != "Normal").astype(int).to_numpy()
    print(f"train={len(X_tr)} test={len(X_te)} features={LIVE_FEATURES}")

    pipe = build_live_pipeline(a.n_estimators)
    t0 = time.time()
    pipe.fit(X_tr, yb_tr)
    fit_s = time.time() - t0
    prob = pipe.predict_proba(X_te)[:, 1]

    # per-category detection rate at the default threshold (how many of each attack type are caught)
    pred = prob >= 0.5
    per_cat = {c: round(float(pred[(y_te == c).to_numpy()].mean()), 4) for c in sorted(y_te.unique())}

    importances = dict(zip(pipe.named_steps["pre"].get_feature_names_out(),
                           pipe.named_steps["rf"].feature_importances_.round(4).tolist()))
    metrics = {
        "task": "binary attack (attack_cat != Normal) vs normal",
        "features": LIVE_FEATURES,
        "roc_auc": roc_auc_score(yb_te, prob),
        "at_threshold_0.5": binary_metrics(yb_te, prob, 0.5),
        "at_threshold_0.8": binary_metrics(yb_te, prob, 0.8),
        "flagged_as_attack_rate_per_true_category@0.5": per_cat,
        "feature_importances": dict(sorted(importances.items(), key=lambda kv: -kv[1])),
        "training_info": {
            "train_rows": len(X_tr), "test_rows": len(X_te),
            "split": "same de-duplicated stratified 80/20 seed=42 split as ml/train.py",
            "model": "RandomForestClassifier", "n_estimators": a.n_estimators, "max_depth": 20,
            "fit_seconds": round(fit_s, 1),
            "versions": {"python": platform.python_version(), "sklearn": sklearn.__version__},
        },
    }
    common.RESULTS.mkdir(exist_ok=True)
    joblib.dump({"pipeline": pipe, "features": LIVE_FEATURES, "positive_class": "attack"},
                LIVE_MODEL_PATH, compress=3)
    LIVE_METRICS_PATH.write_text(json.dumps(metrics, indent=2, default=float))
    m = metrics["at_threshold_0.5"]
    print(f"AUC={metrics['roc_auc']:.4f} acc={m['accuracy']:.4f} prec={m['precision']:.4f} "
          f"rec={m['recall']:.4f} f1={m['f1']:.4f} ({fit_s:.0f}s)")
    print("flagged per category:", per_cat)
    print(f"saved {LIVE_MODEL_PATH}")


if __name__ == "__main__":
    main()
