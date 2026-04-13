import argparse
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from backend.feature_extractor import FEATURE_NAMES
from data_loader import load_data
from evaluate import evaluate_model, model_comparison
from train import build_ensemble, train_models

BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "models"
MODEL_DIR.mkdir(exist_ok=True)


def select_best_model(results):
    return max(results, key=lambda m: (results[m]["precision"], results[m]["f1"]))


def run_pipeline(save_path: Path = MODEL_DIR / "model.pkl") -> dict:
    print("ScamShield Training Pipeline")
    df = load_data()

    X_df = df[FEATURE_NAMES].astype(float)
    y = df["label"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X_df,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )
    print(f"Train: {len(X_train):,} | Test: {len(X_test):,}")

    feature_names = X_train.columns.tolist()

    scaler = StandardScaler()
    X_train_sc = pd.DataFrame(scaler.fit_transform(X_train), columns=feature_names, index=X_train.index)
    X_test_sc = pd.DataFrame(scaler.transform(X_test), columns=feature_names, index=X_test.index)

    models = train_models(X_train_sc, y_train)
    results = model_comparison(models, X_test_sc, y_test)


    ensemble = build_ensemble(models, X_train_sc, y_train)
    models["Voting Ensemble"] = ensemble
    ens_threshold = 0.5
    ens_metrics = evaluate_model("Voting Ensemble", ensemble, X_test_sc, y_test, ens_threshold)
    results["Voting Ensemble"] = ens_metrics

    print("\nModel comparison")
    print("Name,Threshold,Accuracy,Precision,Recall,F1,FalsePositives")
    for name, m in results.items():
        print(
            f"{name},{m['threshold']:.3f},{m['accuracy']:.4f},{m['precision']:.4f},{m['recall']:.4f},{m['f1']:.4f},{m['false_positives']}"
        )

    best_name = select_best_model(results)
    best_model = models[best_name]
    best_threshold = results[best_name]["threshold"]
    print(f"\nBest model: {best_name}; threshold={best_threshold:.3f}")

    pipeline_obj = {
        "scaler": scaler,
        "model": best_model,
        "model_name": best_name,
        "model_threshold": best_threshold,
        "feature_names": feature_names,
        "all_results": results,
    }

    joblib.dump(pipeline_obj, save_path)
    joblib.dump(FEATURE_NAMES, MODEL_DIR / "feature_names.pkl")
    print(f"Saved pipeline: {save_path}")

    return pipeline_obj


def predict_url(url: str, model_path: Path = MODEL_DIR / "model.pkl") -> dict:
    artifact = joblib.load(model_path)
    scaler = artifact["scaler"]
    model = artifact["model"]
    threshold = artifact.get("model_threshold", 0.5)
    feature_names = artifact.get("feature_names", FEATURE_NAMES)

    from backend.feature_extractor import extract_features, annotate_features

    features = extract_features(url)
    x = pd.DataFrame([{name: features.get(name, 0.0) for name in feature_names}], columns=feature_names)

    if hasattr(scaler, "feature_names_in_") and list(scaler.feature_names_in_) != feature_names:
        x = x[scaler.feature_names_in_]

    x_scaled = scaler.transform(x)
    x_scaled = pd.DataFrame(x_scaled, columns=feature_names)

    if hasattr(model, "predict_proba"):
        phish_proba = float(model.predict_proba(x_scaled)[0][1])
    else:
        phish_proba = float(model.predict(x_scaled)[0])

    is_phish = phish_proba >= threshold
    return {
        "url": url,
        "prediction": "Phishing" if is_phish else "Legitimate",
        "phish_probability": phish_proba,
        "threshold": threshold,
        "features": features,
        "feature_analysis": annotate_features(features),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train the ScamShield phishing detection pipeline.")
    parser.add_argument("--model", choices=["lightgbm", "catboost", "xgboost", "ensemble"], default="ensemble", help="Model to prioritize in selection")
    args = parser.parse_args()

    pipeline = run_pipeline()

    if args.model != "ensemble":
        if args.model.title() in pipeline["all_results"]:
            print(f"Requested model {args.model} is in results; it can be used manually.")

    print("Training done.")
