"""Shared dataset / split / paths for the UNSW-NB15 pipeline."""
import os
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"
MODEL_PATH = RESULTS / "model.joblib"
DEFAULT_DATA = "/home/aditya_yadav/Data/Sem 7/SAD/data/processed/unsw_processed.csv"
DATA_PATH = Path(os.environ.get("UNSW_PROCESSED_CSV", DEFAULT_DATA))

TARGET = "attack_cat"  # 10-class label; binary label == (attack_cat != "Normal")
# Never used as inputs: row id, label columns (leakage), source-partition marker.
LEAKY = ["id", "attack_cat", "label", "label_binary", "dataset_name"]
# TCP initial sequence numbers: random per connection, not meaningful features.
DROPPED_NOISE = ["stcpb", "dtcpb"]
CATEGORICAL = ["proto", "service", "state"]
SEED = 42
TEST_SIZE = 0.2


def load_dataset(path=None) -> pd.DataFrame:
    path = Path(path) if path else DATA_PATH
    if not path.is_file():
        raise FileNotFoundError(f"Processed dataset not found: {path} "
                                f"(set UNSW_PROCESSED_CSV or pass --data)")
    df = pd.read_csv(path)
    missing = [c for c in [TARGET, "label", *CATEGORICAL] if c not in df.columns]
    if missing:
        raise ValueError(f"Dataset schema invalid, missing columns: {missing}")
    return df


def feature_columns(df: pd.DataFrame):
    return [c for c in df.columns if c not in LEAKY + DROPPED_NOISE]


def deduplicate(df: pd.DataFrame) -> pd.DataFrame:
    """Drop exact duplicate flows (ignoring id) so copies cannot straddle train/test."""
    feats = feature_columns(df) + [TARGET]
    return df.drop_duplicates(subset=feats).reset_index(drop=True)


def split(df: pd.DataFrame):
    """Reproducible stratified split on the de-duplicated data."""
    df = deduplicate(df)
    X, y = df[feature_columns(df)], df[TARGET]
    return train_test_split(X, y, test_size=TEST_SIZE, stratify=y, random_state=SEED)
