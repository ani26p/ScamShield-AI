import numpy as np
from sklearn.metrics import confusion_matrix, accuracy_score, f1_score, precision_score, recall_score, precision_recall_curve


def choose_best_threshold(y_true: np.ndarray, y_proba: np.ndarray):
    if len(np.unique(y_true)) < 2:
        return 0.5

    precision, recall, thresholds = precision_recall_curve(y_true, y_proba)
    f1_scores = 2 * (precision * recall) / np.clip(precision + recall, 1e-9, None)

    best = np.nanargmax(f1_scores)
    if best >= len(thresholds):
        return 0.5

    return float(thresholds[best])


def evaluate_model(name: str, model, X_test, y_test, threshold: float = 0.5):
    if hasattr(model, "predict_proba"):
        y_proba = model.predict_proba(X_test)[:, 1]
    else:
        y_proba = model.predict(X_test)

    y_pred = (y_proba >= threshold).astype(int)

    metrics = {
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred, zero_division=0),
        "recall": recall_score(y_test, y_pred, zero_division=0),
        "f1": f1_score(y_test, y_pred, zero_division=0),
        "false_positives": int(((y_test == 0) & (y_pred == 1)).sum()),
        "threshold": threshold,
    }
    metrics["confusion_matrix"] = confusion_matrix(y_test, y_pred).tolist()
    return metrics


def model_comparison(models, X_test, y_test):
    results = {}
    for name, model in models.items():
        threshold = choose_best_threshold(y_test, model.predict_proba(X_test)[:, 1]) if hasattr(model, "predict_proba") else 0.5
        results[name] = evaluate_model(name, model, X_test, y_test, threshold)
    return results
