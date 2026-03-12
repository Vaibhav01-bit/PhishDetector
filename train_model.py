"""
Improved Training Pipeline for Phishing Detection
- Uses optimized RandomForest
- Comprehensive evaluation metrics
- Cross-validation
"""

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
import pickle
import warnings

warnings.filterwarnings("ignore")

# Load dataset
print("\n[1] Loading dataset...")
data = pd.read_csv("DataFiles/phishing.csv")
data = data.drop(["Index"], axis=1)
print(f"    Dataset shape: {data.shape}")

# Prepare features and labels
y = data["class"]
X = data.drop("class", axis=1)

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"    Train size: {len(X_train)}, Test size: {len(X_test)}")

# Train RandomForest with optimized parameters
print("\n[2] Training RandomForest...")
rf_model = RandomForestClassifier(
    n_estimators=200,
    max_depth=None,
    min_samples_split=2,
    min_samples_leaf=1,
    max_features="sqrt",
    bootstrap=True,
    random_state=42,
    n_jobs=-1,
)
rf_model.fit(X_train, y_train)

# Cross-validation for RandomForest
print("\n[3] Cross-validation (5-fold)...")
cv_scores_rf = cross_val_score(rf_model, X, y, cv=5, scoring="accuracy")
print(
    f"    RF CV Accuracy: {cv_scores_rf.mean():.4f} (+/- {cv_scores_rf.std() * 2:.4f})"
)

# Also train XGBoost as alternative
print("\n[4] Training XGBoost...")
try:
    from xgboost import XGBClassifier

    y_train_xgb = y_train.replace({-1: 0})
    y_test_xgb = y_test.replace({-1: 0})
    y_xgb = y.replace({-1: 0})

    xgb_model = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        use_label_encoder=False,
        eval_metric="logloss",
        n_jobs=-1,
    )
    xgb_model.fit(X_train, y_train_xgb)

    cv_scores_xgb = cross_val_score(xgb_model, X, y_xgb, cv=5, scoring="accuracy")
    print(
        f"    XGB CV Accuracy: {cv_scores_xgb.mean():.4f} (+/- {cv_scores_xgb.std() * 2:.4f})"
    )

    # Compare and choose best model
    if cv_scores_xgb.mean() > cv_scores_rf.mean():
        print("\n    -> XGBoost performs better, using XGBoost model")
        final_model = xgb_model
        model_name = "XGBoost"
    else:
        print("\n    -> RandomForest performs better, using RandomForest model")
        final_model = rf_model
        model_name = "RandomForest"
except Exception as e:
    print(f"    XGBoost training failed: {e}")
    final_model = rf_model
    model_name = "RandomForest"

# Evaluate on test set
print("\n[5] Evaluating on test set...")
y_pred = final_model.predict(X_test)
y_pred_proba = final_model.predict_proba(X_test)[:, 1]

# Metrics
accuracy = accuracy_score(y_test, y_pred)
print(f"\n    ========== MODEL EVALUATION ==========")
print(f"    Model: {model_name}")
print(f"    Accuracy: {accuracy:.4f} ({accuracy * 100:.2f}%)")

# Confusion Matrix
cm = confusion_matrix(y_test, y_pred)
print(f"\n    Confusion Matrix:")
print(f"    TN: {cm[0][0]:5d}  FP: {cm[0][1]:5d}")
print(f"    FN: {cm[1][0]:5d}  TP: {cm[1][1]:5d}")

# Calculate specific metrics
tn, fp, fn, tp = cm[0][0], cm[0][1], cm[1][0], cm[1][1]
precision = tp / (tp + fp) if (tp + fp) > 0 else 0
recall = tp / (tp + fn) if (tp + fn) > 0 else 0
f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

print(f"\n    Precision: {precision:.4f}")
print(f"    Recall: {recall:.4f}")
print(f"    F1-Score: {f1:.4f}")

# ROC-AUC
roc_auc = roc_auc_score(y_test, y_pred_proba)
print(f"\n    ROC-AUC Score: {roc_auc:.4f}")

# Classification Report
print(f"\n    Classification Report:")
print(classification_report(y_test, y_pred, target_names=["Phishing (-1)", "Safe (1)"]))

# Save model
print("\n[6] Saving model...")
pickle.dump(final_model, open("newmodel.pkl", "wb"))
print("    [*] Model saved to newmodel.pkl")

# Also save individual models for potential use
pickle.dump(rf_model, open("rf_model.pkl", "wb"))
print("    [*] RandomForest saved to rf_model.pkl")

try:
    pickle.dump(xgb_model, open("xgb_model.pkl", "wb"))
    print("    [*] XGBoost saved to xgb_model.pkl")
except:
    pass

print("\n" + "=" * 50)
print("TRAINING COMPLETE!")
print("=" * 50)
