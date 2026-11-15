"""Train a Random Forest on the processed UNSW-NB15 CSV and save artifacts to results/."""
import argparse
import json
import platform
import time

import joblib
import sklearn
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

from ml import common
from ml.evaluate import compute_metrics, save_confusion_matrix


def build_pipeline(n_estimators=100):
    pre = ColumnTransformer(
        [("cat", OneHotEncoder(handle_unknown="ignore"), common.CATEGORICAL)],
        remainder="passthrough")  # numeric features are used as-is (trees need no scaling)
    clf = RandomForestClassifier(
        n_estimators=n_estimators, class_weight="balanced_subsample",
        min_samples_leaf=2, n_jobs=-1, random_state=common.SEED)
    return Pipeline([("pre", pre), ("rf", clf)])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=None)
    ap.add_argument("--n-estimators", type=int, default=100)
    a = ap.parse_args()

    df = common.load_dataset(a.data)
    n_raw = len(df)
    X_tr, X_te, y_tr, y_te = common.split(df)
    print(f"rows raw={n_raw} dedup={len(X_tr)+len(X_te)} train={len(X_tr)} test={len(X_te)}")

    pipe = build_pipeline(a.n_estimators)
    t0 = time.time()
    pipe.fit(X_tr, y_tr)  # preprocessing is fitted on the training split only
    fit_s = time.time() - t0

    metrics = compute_metrics(pipe, X_te, y_te)
    metrics["training_info"] = {
        "dataset": str(common.DATA_PATH if a.data is None else a.data),
        "rows_raw": n_raw, "rows_after_dedup": len(X_tr) + len(X_te),
        "train_rows": len(X_tr), "test_rows": len(X_te),
        "split": f"stratified {1-common.TEST_SIZE:.0%}/{common.TEST_SIZE:.0%}, seed={common.SEED}",
        "model": "RandomForestClassifier", "params": pipe.named_steps["rf"].get_params(),
        "excluded_columns": common.LEAKY + common.DROPPED_NOISE,
        "fit_seconds": round(fit_s, 1),
        "versions": {"python": platform.python_version(), "sklearn": sklearn.__version__},
    }
    common.RESULTS.mkdir(exist_ok=True)
    joblib.dump({"pipeline": pipe, "features": list(X_tr.columns),
                 "classes": list(pipe.classes_)}, common.MODEL_PATH, compress=3)
    (common.RESULTS / "metrics.json").write_text(json.dumps(metrics, indent=2, default=str))
    save_confusion_matrix(metrics, common.RESULTS / "confusion_matrix.png")
    print(f"accuracy={metrics['accuracy']:.4f} macro_f1={metrics['macro_f1']:.4f} "
          f"binary_f1={metrics['binary']['f1']:.4f} ({fit_s:.0f}s)")
    print(f"saved {common.MODEL_PATH}")


if __name__ == "__main__":
    main()
