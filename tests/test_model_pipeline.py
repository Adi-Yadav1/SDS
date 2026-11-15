import json

import joblib
import numpy as np
import pytest

from ml import common
from ml.predict import predict
from ml.train import build_pipeline

pytestmark = pytest.mark.skipif(not common.DATA_PATH.is_file(), reason="processed CSV not found")


@pytest.fixture(scope="module")
def df():
    return common.load_dataset()


def test_schema_and_no_missing(df):
    assert df.shape[1] == 47
    assert df[common.TARGET].nunique() == 10
    assert df.isna().sum().sum() == 0
    assert set(df["label"].unique()) == {0, 1}


def test_features_exclude_leaky_columns(df):
    feats = common.feature_columns(df)
    for c in common.LEAKY + common.DROPPED_NOISE:
        assert c not in feats
    assert len(feats) == 40


def test_split_is_reproducible_stratified_and_disjoint(df):
    a = common.split(df)
    b = common.split(df)
    assert a[1].index.equals(b[1].index)
    assert set(a[0].index).isdisjoint(a[1].index)
    assert set(a[2].unique()) == set(a[3].unique())  # every class on both sides


def test_small_training_and_predict_consistency(df):
    sample = df.groupby(common.TARGET, group_keys=False).head(300)
    X, y = sample[common.feature_columns(df)], sample[common.TARGET]
    pipe = build_pipeline(n_estimators=20).fit(X, y)
    art = {"pipeline": pipe, "features": list(X.columns), "classes": list(pipe.classes_)}
    import tempfile, pathlib
    p = pathlib.Path(tempfile.mkdtemp()) / "m.joblib"
    joblib.dump(art, p)
    out = predict(X.head(50), path=p)
    assert list(out.columns) == ["predicted_class", "confidence", "is_attack"]
    assert (out["predicted_class"].values == pipe.predict(X.head(50))).all()
    assert out["confidence"].between(0, 1).all()
    assert (out["is_attack"] == (out["predicted_class"] != "Normal")).all()


def test_predict_rejects_missing_features(df, tmp_path):
    pytest.importorskip("sklearn")
    if not common.MODEL_PATH.is_file():
        pytest.skip("run `python -m ml.train` first")
    with pytest.raises(ValueError, match="Missing required feature"):
        predict(df[["dur", "proto"]].head(2))


def test_saved_model_heldout_metrics_match_metrics_json(df):
    if not common.MODEL_PATH.is_file():
        pytest.skip("run `python -m ml.train` first")
    art = joblib.load(common.MODEL_PATH)
    _, X_te, _, y_te = common.split(df)
    acc = float(np.mean(art["pipeline"].predict(X_te) == y_te))
    saved = json.loads((common.RESULTS / "metrics.json").read_text())
    assert acc == pytest.approx(saved["accuracy"])
    assert saved["training_info"]["test_rows"] == len(X_te)


def test_missing_dataset_raises_clear_error(tmp_path):
    with pytest.raises(FileNotFoundError, match="not found"):
        common.load_dataset(tmp_path / "nope.csv")
