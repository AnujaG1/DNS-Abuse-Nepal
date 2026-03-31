"""
train.py
========
Trains a Random Forest classifier on the domain dataset.
Saves the trained model and scaler to disk.

Why Random Forest?
  - Handles non-linear relationships between features
  - Gives feature importance scores (explainable AI)
  - Robust to outliers and doesn't need feature scaling
  - Works well on tabular data with mixed feature types
  - Better than logistic regression for this problem because
    features like entropy interact non-linearly with TLD score

Pipeline:
  Raw domains → Feature extraction → StandardScaler → Random Forest
"""

import pandas as pd
import numpy as np
import pickle
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

from features import extract_features, FEATURE_NAMES

# ── Load dataset ──────────────────────────────────────────────────────────────
print("=" * 55)
print("  DNS Shield Nepal — Model Training")
print("=" * 55)

df = pd.read_csv("data/domains.csv")
print(f"\n📂 Dataset loaded: {len(df)} domains")
print(df["label_name"].value_counts().to_string())

# ── Extract features ──────────────────────────────────────────────────────────
print("\n⚙️  Extracting features...")

rows = []
for domain in df["domain"]:
    feats = extract_features(domain)
    # Only keep model features (not metadata starting with _)
    row = {k: feats[k] for k in FEATURE_NAMES}
    rows.append(row)

X = pd.DataFrame(rows)
y = df["label"].values

print(f"✅ Feature matrix shape: {X.shape}")
print(f"   Features: {list(X.columns)}")

# ── Check for any NaN ─────────────────────────────────────────────────────────
if X.isnull().any().any():
    print("⚠️  NaN values found — filling with 0")
    X = X.fillna(0)

# ── Train / test split ────────────────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"\n📊 Train size: {len(X_train)}  |  Test size: {len(X_test)}")

# ── Scale features ────────────────────────────────────────────────────────────
# Random Forest doesn't need scaling, but we include it so the
# pipeline works correctly if we swap to SVM or Logistic Regression
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled  = scaler.transform(X_test)

# ── Train Random Forest ───────────────────────────────────────────────────────
print("\n🌲 Training Random Forest classifier...")
print("   n_estimators=200, max_depth=20, min_samples_leaf=2")

model = RandomForestClassifier(
    n_estimators=200,       # 200 decision trees in the forest
    max_depth=20,           # max depth of each tree
    min_samples_leaf=2,     # min samples required at a leaf node
    class_weight="balanced",# handles class imbalance automatically
    random_state=42,
    n_jobs=-1               # use all CPU cores
)

model.fit(X_train_scaled, y_train)
print("✅ Training complete")

# ── Evaluate ──────────────────────────────────────────────────────────────────
print("\n📈 Evaluation on test set:")
y_pred = model.predict(X_test_scaled)
acc = accuracy_score(y_test, y_pred)
print(f"   Accuracy: {acc*100:.1f}%")

print("\n   Classification Report:")
label_names = ["legitimate", "phishing", "malware_dga", "spam"]
report = classification_report(y_test, y_pred, target_names=label_names)
for line in report.split("\n"):
    print("   " + line)

print("\n   Confusion Matrix:")
cm = confusion_matrix(y_test, y_pred)
print("   " + "  ".join(f"{n:>12}" for n in label_names))
for i, row in enumerate(cm):
    print(f"   {label_names[i]:>12}  " + "  ".join(f"{v:>12}" for v in row))

# ── Cross-validation ──────────────────────────────────────────────────────────
print("\n🔁 5-fold cross-validation:")
cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=5, scoring="accuracy")
print(f"   Scores: {[f'{s:.3f}' for s in cv_scores]}")
print(f"   Mean: {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")

# ── Feature importance ────────────────────────────────────────────────────────
print("\n🏆 Top 10 Most Important Features (Random Forest):")
importances = model.feature_importances_
feat_imp = sorted(zip(FEATURE_NAMES, importances), key=lambda x: x[1], reverse=True)
for i, (name, imp) in enumerate(feat_imp[:10], 1):
    bar = "█" * int(imp * 200)
    print(f"   {i:>2}. {name:<25} {imp:.4f}  {bar}")

# ── Save model + scaler ───────────────────────────────────────────────────────
os.makedirs("models", exist_ok=True)

with open("models/rf_model.pkl", "wb") as f:
    pickle.dump(model, f)

with open("models/scaler.pkl", "wb") as f:
    pickle.dump(scaler, f)

# Save feature names so the app knows the column order
with open("models/feature_names.pkl", "wb") as f:
    pickle.dump(FEATURE_NAMES, f)

# Save training metadata
meta = {
    "accuracy": round(acc, 4),
    "cv_mean":  round(cv_scores.mean(), 4),
    "cv_std":   round(cv_scores.std(), 4),
    "n_train":  len(X_train),
    "n_test":   len(X_test),
    "n_features": len(FEATURE_NAMES),
    "feature_importance": {n: round(float(v), 5) for n, v in feat_imp},
    "label_names": label_names,
}

with open("models/meta.pkl", "wb") as f:
    pickle.dump(meta, f)

print(f"\n✅ Model saved   → models/rf_model.pkl")
print(f"✅ Scaler saved  → models/scaler.pkl")
print(f"✅ Meta saved    → models/meta.pkl")
print(f"\n🎯 Final accuracy: {acc*100:.1f}%")
print("=" * 55)