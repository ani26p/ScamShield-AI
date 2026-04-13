import os
from pathlib import Path
from typing import Optional

import pandas as pd

from backend.feature_extractor import FEATURE_NAMES, extract_features, load_openphish_blacklist


BASE_DIR = Path(__file__).resolve().parent
DATASET_DIRS = [
    BASE_DIR / "Datasets",
    BASE_DIR / "datasets",
    BASE_DIR.parent / "Datasets",
    BASE_DIR.parent / "datasets",
]


def _dataset_dir() -> Path:
    for p in DATASET_DIRS:
        if p.exists():
            return p
    raise FileNotFoundError("No datasets folder found")


def _load_csv(name: str, **kwargs) -> pd.DataFrame:
    file_path = _dataset_dir() / name
    if not file_path.exists():
        raise FileNotFoundError(f"Dataset not found: {file_path}")
    return pd.read_csv(file_path, **kwargs)


def _clean_urls(series: pd.Series) -> pd.Series:
    s = series.astype(str).str.strip().str.lower()
    s = s[s != ""]
    s = s.apply(lambda u: f"http://{u}" if "://" not in u else u)
    s = s[s.str.contains(r"[./]", regex=True)]
    return s


def _to_url_label(urls: pd.Series, labels: pd.Series) -> pd.DataFrame:
    out = pd.DataFrame({"url": urls.values, "label": labels.values}).dropna()
    out["label"] = out["label"].astype(int)
    return out.drop_duplicates(subset=["url"])


def _load_openphish() -> pd.DataFrame:
    df = _load_csv("OpenPhish.csv")
    col = next((c for c in df.columns if c.lower() == "url"), df.columns[0])
    urls = _clean_urls(df[col])
    return _to_url_label(urls, pd.Series(1, index=urls.index))


def _load_phishtank() -> pd.DataFrame:
    df = _load_csv("PhishTank.csv")
    col = next((c for c in df.columns if c.lower() == "url"), df.columns[0])
    urls = _clean_urls(df[col])
    return _to_url_label(urls, pd.Series(1, index=urls.index))


def _load_malicious_extra() -> pd.DataFrame:
    df = _load_csv("malicious_phish.csv")
    col = next((c for c in df.columns if c.lower() == "url"), df.columns[0])
    urls = _clean_urls(df[col])

    label_col = next((c for c in df.columns if c.lower() in ["type", "label", "target", "result"]), None)
    if label_col is None:
        labels = pd.Series(1, index=urls.index)
    else:
        labels = (
            df.loc[urls.index, label_col]
            .astype(str)
            .str.lower()
            .map({"benign": 0, "legitimate": 0, "phishing": 1, "malware": 1, "defacement": 1, "0": 0, "1": 1})
            .fillna(1)
            .astype(int)
        )
    return _to_url_label(urls, labels)


def _load_kaggle() -> pd.DataFrame:
    df = _load_csv("dataset.csv")
    lower_map = {c.lower(): c for c in df.columns}

    if "url" in lower_map:
        urls = _clean_urls(df[lower_map["url"]])
        label_col = next((lower_map[name] for name in ["label", "target", "class", "result"] if name in lower_map), None)
        if label_col is None:
            raise ValueError("Kaggle dataset has URL column but no label column.")
        labels = df.loc[urls.index, label_col].map({1: 1, 0: 0, -1: 0, "0": 0, "1": 1}).fillna(1).astype(int)
        return _to_url_label(urls, labels)

    # dataset without URL column is not usable for this URL-based feature pipeline
    print("WARNING: Kaggle dataset has no URL column, skipping it to avoid synthetic-only rows.")
    return pd.DataFrame(columns=["url", "label"])


def _load_tranco() -> pd.DataFrame:
    df = _load_csv("tranco_L76L4.csv", header=None)
    urls = _clean_urls(df.iloc[:, -1])
    return _to_url_label(urls, pd.Series(0, index=urls.index))


def load_data() -> pd.DataFrame:
    blacklist = load_openphish_blacklist()

    sources = [
        ("Tranco", _load_tranco),
        ("OpenPhish", _load_openphish),
        ("PhishTank", _load_phishtank),
        ("MaliciousExtra", _load_malicious_extra),
        ("Kaggle", _load_kaggle),
    ]

    frames = []
    print("=" * 62)
    print("  LOADING DATASETS")
    print("=" * 62)

    for name, loader in sources:
        try:
            df_src = loader()
            print(f"{name:<14}: {len(df_src):,} rows")
            if len(df_src) > 0:
                frames.append(df_src)
        except Exception as e:
            print(f"{name:<14}: load failed -> {e}")

    if not frames:
        raise RuntimeError("No data loaded from datasets.")

    merged = pd.concat(frames, ignore_index=True).dropna(subset=["url", "label"])
    merged = merged.drop_duplicates(subset=["url"])

    # Class balance subsample, preserving minority proportion.
    counts = merged["label"].value_counts()
    if len(counts) < 2 or counts.min() < 10:
        raise RuntimeError("Insufficient class balance after merging datasets.")

    n = int(counts.min())
    balanced = pd.concat(
        [
            merged[merged["label"] == 0].sample(n=n, random_state=42),
            merged[merged["label"] == 1].sample(n=n, random_state=42),
        ],
        ignore_index=True,
    ).sample(frac=1.0, random_state=42).reset_index(drop=True)

    features = balanced["url"].apply(lambda u: extract_features(u, blacklist)).apply(pd.Series)
    features["label"] = balanced["label"].values

    counts = features["label"].value_counts()
    print(f"\nCombined balanced dataset: {len(features):,}")
    print(f"  Legitimate (0): {counts.get(0,0):,}")
    print(f"  Phishing   (1): {counts.get(1,0):,}")

    return features
