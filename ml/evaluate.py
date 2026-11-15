"""Held-out evaluation. `python -m ml.evaluate` reloads the saved model and re-scores the same split."""
import json

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix,
                             precision_recall_fscore_support)

from ml import common


def compute_metrics(pipe, X_te, y_te):
    pred = pipe.predict(X_te)
    classes = list(pipe.classes_)
    p, r, f, _ = precision_recall_fscore_support(y_te, pred, average="macro", zero_division=0)
    yb, pb = (y_te != "Normal"), (pred != "Normal")
    bp, br, bf, _ = precision_recall_fscore_support(yb, pb, average="binary", zero_division=0)
    return {
        "accuracy": accuracy_score(y_te, pred),
        "macro_precision": p, "macro_recall": r, "macro_f1": f,
        "per_class": classification_report(y_te, pred, output_dict=True, zero_division=0),
        "binary": {"definition": "attack = predicted class != Normal",
                   "accuracy": accuracy_score(yb, pb), "precision": bp, "recall": br, "f1": bf},
        "classes": classes,
        "confusion_matrix": confusion_matrix(y_te, pred, labels=classes).tolist(),
    }


def save_confusion_matrix(metrics, path):
    cm, classes = np.array(metrics["confusion_matrix"]), metrics["classes"]
    cmn = cm / cm.sum(axis=1, keepdims=True).clip(min=1)
    fig, ax = plt.subplots(figsize=(9, 7.5))
    im = ax.imshow(cmn, cmap="Blues", vmin=0, vmax=1)
    ax.set_xticks(range(len(classes)), classes, rotation=45, ha="right")
    ax.set_yticks(range(len(classes)), classes)
    for i in range(len(classes)):
        for j in range(len(classes)):
            ax.text(j, i, cm[i, j], ha="center", va="center",
                    color="white" if cmn[i, j] > 0.5 else "black", fontsize=8)
    ax.set_xlabel("Predicted"); ax.set_ylabel("True")
    ax.set_title("UNSW-NB15 held-out confusion matrix (counts; colour = row-normalised)")
    fig.colorbar(im); fig.tight_layout(); fig.savefig(path, dpi=130); plt.close(fig)


def main():
    art = joblib.load(common.MODEL_PATH)
    _, X_te, _, y_te = common.split(common.load_dataset())
    m = compute_metrics(art["pipeline"], X_te, y_te)
    print(f"reloaded model: accuracy={m['accuracy']:.4f} macro_f1={m['macro_f1']:.4f}")
    print(classification_report(y_te, art["pipeline"].predict(X_te), zero_division=0))
    saved = json.loads((common.RESULTS / "metrics.json").read_text())
    print("matches metrics.json:", abs(saved["accuracy"] - m["accuracy"]) < 1e-12)


if __name__ == "__main__":
    main()
