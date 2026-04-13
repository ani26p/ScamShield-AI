from __future__ import annotations

import logging
import math
from pathlib import Path

import joblib
import pandas as pd

from .feature_extractor import FEATURE_NAMES, annotate_features, extract_features


class ScamShieldPredictor:
    def __init__(self, model_path: str | None = None):
        base = Path(__file__).resolve().parent
        # Look 2 levels up to find models/ since we are now in backend/app/
        path = Path(model_path) if model_path else (base.parent.parent / "models" / "model.pkl")
        if not path.exists():
            raise FileNotFoundError(f"Model not found: {path}. Run train_pipeline.py first.")
        artifact = joblib.load(path)

        self.scaler = artifact["scaler"]
        self.model = artifact["model"]
        self.model_name = artifact.get("model_name", "unknown")
        self.feature_names = artifact.get("feature_names", FEATURE_NAMES)
        self.threshold = artifact.get("model_threshold", 0.5)

    def analyze(self, url: str) -> dict:
        features = extract_features(url)
        # Clip domain_age_days sentinel (-1.0 means WHOIS unavailable) before passing to ML model.
        ml_features = {name: max(0.0, features.get(name, 0.0)) for name in self.feature_names}
        x = pd.DataFrame([ml_features], columns=self.feature_names)

        if hasattr(self.scaler, "feature_names_in_") and list(self.scaler.feature_names_in_) != self.feature_names:
            x = x[self.scaler.feature_names_in_]

        x_scaled = self.scaler.transform(x)
        x_scaled = pd.DataFrame(x_scaled, columns=self.feature_names)

        safe_probability = 0.0
        confidence_value = 0.0

        if hasattr(self.model, "predict_proba"):
            try:
                proba = self.model.predict_proba(x_scaled)[0]
                phish_prob = float(proba[1]) if len(proba) > 1 else 0.0
                safe_probability = 1.0 - phish_prob
                confidence_value = max(min(phish_prob, 1.0), 0.0)
            except Exception as e:
                logging.warning("predict_proba failed (%s), falling back to predict: %s", type(e).__name__, e)
                phish_prob = float(self.model.predict(x_scaled)[0])
                safe_probability = 1.0 - phish_prob
                confidence_value = max(min(phish_prob, 1.0), 0.0)
        else:
            phish_prob = float(self.model.predict(x_scaled)[0])
            safe_probability = 1.0 - phish_prob
            confidence_value = max(min(phish_prob, 1.0), 0.0)

        phish_prob = max(0.0, min(1.0, phish_prob))
        safe_probability = max(0.0, min(1.0, safe_probability))

        is_phish = phish_prob >= self.threshold
        prediction = "phishing" if is_phish else "safe"

        # Feature analysis and score based on safe/risk tags
        feature_analysis = annotate_features(features)
        total_features = len(feature_analysis) if feature_analysis else 0
        safe_features = sum(1 for x in feature_analysis.values() if str(x.get("status")).lower() == "safe")

        if total_features <= 0:
            credibility_score = 0.0
        else:
            credibility_score = float(round((safe_features / total_features) * 100.0, 2))
            credibility_score = max(0.0, min(100.0, credibility_score))

        logging.info("scoring: safe=%d total=%d credibility_score=%.2f", safe_features, total_features, credibility_score)

        confidence_pct = float(round(confidence_value * 100.0, 2))

        result = {
            "url": url,
            "prediction": prediction,
            "is_safe": not is_phish,
            "threshold": float(self.threshold),
            "phish_probability": float(round(phish_prob, 6)),
            "safe_probability": float(round(safe_probability, 6)),
            "confidence": confidence_pct,
            "credibility_score": credibility_score,
            "score": credibility_score,
            "model_used": self.model_name,
            "features": features,
            "feature_analysis": feature_analysis,
        }

        logging.info(
            "analyze: url=%s prediction=%s phish_prob=%.4f safe_prob=%.4f confidence=%.2f credibility_score=%.2f",
            url, prediction, phish_prob, safe_probability, confidence_pct, credibility_score,
        )

        return result
