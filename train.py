import os
import uuid
from pathlib import Path

import numpy as np
from catboost import CatBoostClassifier
from lightgbm import LGBMClassifier
from sklearn.ensemble import VotingClassifier
from sklearn.model_selection import RandomizedSearchCV, StratifiedKFold
from xgboost import XGBClassifier


MODEL_DIR = Path(__file__).resolve().parent / "models"
CATBOOST_DIR = MODEL_DIR / "catboost_info"
MODEL_DIR.mkdir(exist_ok=True)
CATBOOST_DIR.mkdir(exist_ok=True)


def _make_catboost_classifier(temp_dir=None):
    # Required to prevent CatBoost directory errors and conflicting verbosity params.
    if temp_dir is None:
        temp_dir = f"catboost_temp_{uuid.uuid4().hex}"
    os.makedirs(temp_dir, exist_ok=True)
    os.makedirs(os.path.join(temp_dir, "tmp"), exist_ok=True)

    return CatBoostClassifier(
        iterations=200,
        depth=6,
        learning_rate=0.1,
        loss_function="Logloss",
        random_seed=42,
        verbose=0,
        task_type="CPU",
        train_dir=temp_dir,
        allow_writing_files=True,
    )


def train_models(X_train, y_train):
    print("\n" + "=" * 62)
    print("  TRAINING MODELS")
    print("=" * 62)

    cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)

    print("\n[1/3] LightGBM …")
    lgbm = RandomizedSearchCV(
        LGBMClassifier(
            objective="binary",
            class_weight="balanced",
            random_state=42,
            verbosity=-1,
            n_jobs=-1,
        ),
        {"n_estimators": [150, 200, 300], "num_leaves": [31, 63], "learning_rate": [0.03, 0.05, 0.1]},
        n_iter=6,
        cv=cv,
        scoring="f1",
        n_jobs=-1,
        random_state=42,
        verbose=0,
    )
    lgbm.fit(X_train, y_train)
    print(f"     Best params={lgbm.best_params_} | CV F1={lgbm.best_score_:.4f}")

    print("\n[2/3] CatBoost …")

    catboost_temp_dir = f"catboost_temp_{uuid.uuid4().hex}"
    os.makedirs(catboost_temp_dir, exist_ok=True)
    os.makedirs(os.path.join(catboost_temp_dir, "tmp"), exist_ok=True)

    cat = RandomizedSearchCV(
        _make_catboost_classifier(catboost_temp_dir),
        {"depth": [4, 6, 8], "iterations": [200, 300], "learning_rate": [0.03, 0.05, 0.1]},
        n_iter=6,
        cv=cv,
        scoring="f1",
        n_jobs=-1,
        random_state=42,
        verbose=0,
    )
    cat.fit(X_train, y_train)
    print(f"     Best params={cat.best_params_} | CV F1={cat.best_score_:.4f}")

    print("\n[3/3] XGBoost …")
    xgb = RandomizedSearchCV(
        XGBClassifier(
            eval_metric="logloss",
            random_state=42,
            n_jobs=-1,
            use_label_encoder=False,
            verbosity=0,
        ),
        {"n_estimators": [150, 200, 300], "max_depth": [4, 6, 8], "learning_rate": [0.03, 0.05, 0.1]},
        n_iter=6,
        cv=cv,
        scoring="f1",
        n_jobs=-1,
        random_state=42,
        verbose=0,
    )
    xgb.fit(X_train, y_train)
    print(f"     Best params={xgb.best_params_} | CV F1={xgb.best_score_:.4f}")

    return {
        "LightGBM": lgbm.best_estimator_,
        "CatBoost": cat.best_estimator_,
        "XGBoost": xgb.best_estimator_,
    }


def build_ensemble(models, X_train, y_train):
    print("\n" + "=" * 62)
    print("  ENSEMBLE (Soft Voting Classifier)")
    print("=" * 62)
    estimators = [(n.replace(" ", "_"), m) for n, m in models.items()]
    ens = VotingClassifier(estimators=estimators, voting="soft", n_jobs=-1)
    ens.fit(X_train, y_train)
    print("  Ensemble trained successfully.")   
    return ens
