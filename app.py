"""
app.py
======
Flask web server. Serves the frontend and exposes:
  GET  /              → main HTML page
  POST /api/predict   → runs ML model + returns JSON result
  GET  /api/model-info → returns model metadata
"""

from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import pickle
import pandas as pd
import os
import json

from features import extract_features, FEATURE_NAMES

app = Flask(__name__)
CORS(app)

# ── Load trained model ────────────────────────────────────────────────────────
print("Loading trained model...")
with open("models/rf_model.pkl", "rb") as f:
    MODEL = pickle.load(f)
with open("models/scaler.pkl", "rb") as f:
    SCALER = pickle.load(f)
with open("models/feature_names.pkl", "rb") as f:
    FEAT_NAMES = pickle.load(f)
with open("models/meta.pkl", "rb") as f:
    META = pickle.load(f)

LABEL_NAMES  = ["Legitimate", "Phishing", "Malware / DGA", "Spam"]
LABEL_COLORS = ["green", "red", "red", "yellow"]
print(f"✅ Model loaded — trained accuracy: {META['accuracy']*100:.1f}%")


# ── Prediction API ────────────────────────────────────────────────────────────

@app.route("/api/predict", methods=["POST"])
def predict():
    data = request.get_json()
    domain = data.get("domain", "").strip()
    if not domain:
        return jsonify({"error": "No domain provided"}), 400

    # 1. Extract features
    feats = extract_features(domain)

    # 2. Build feature vector in the exact order the model was trained on
    feat_row = {k: feats[k] for k in FEAT_NAMES}
    X = pd.DataFrame([feat_row])

    # 3. Scale
    X_scaled = SCALER.transform(X)

    # 4. Predict
    pred_label  = int(MODEL.predict(X_scaled)[0])
    pred_proba  = MODEL.predict_proba(X_scaled)[0]  # probability per class

    # 5. Risk score: weighted sum leaning on abuse class probabilities
    risk_score = round(
        (pred_proba[1] * 100 * 0.9 +   # phishing weight
         pred_proba[2] * 100 * 0.95 +  # malware weight
         pred_proba[3] * 100 * 0.8),   # spam weight
        1
    )
    risk_score = min(100.0, risk_score)

    # 6. Risk level
    if feats["is_whitelisted"]:
        risk_level = "safe"
    elif risk_score >= 45 or pred_label in [1, 2]:
        risk_level = "danger"
    elif risk_score >= 20 or pred_label == 3:
        risk_level = "warning"
    else:
        risk_level = "safe"

    # 7. Feature importance contribution
    importances = MODEL.feature_importances_
    contributions = {
        name: round(float(importances[i]) * abs(float(feat_row[name])) * 100, 2)
        for i, name in enumerate(FEAT_NAMES)
    }

    return jsonify({
        "domain":       feats["_domain"],
        "prediction":   LABEL_NAMES[pred_label],
        "pred_label":   pred_label,
        "risk_score":   risk_score,
        "risk_level":   risk_level,
        "confidence":   round(float(pred_proba[pred_label]) * 100, 1),
        "probabilities": {
            LABEL_NAMES[i]: round(float(p) * 100, 1)
            for i, p in enumerate(pred_proba)
        },
        "features":     {k: v for k, v in feats.items() if not k.startswith("_")},
        "contributions": contributions,
        "metadata": {
            "tld":            feats["_tld"],
            "sld":            feats["_sld"],
            "found_keywords": feats["_found_kw"],
            "found_brands":   feats["_found_brands"],
            "closest_brand":  feats["_closest_brand"],
            "min_edit_dist":  feats["_min_dist"],
            "is_whitelisted": bool(feats["is_whitelisted"]),
        }
    })


@app.route("/api/model-info", methods=["GET"])
def model_info():
    return jsonify({
        "algorithm":    "Random Forest (200 trees, max_depth=20)",
        "accuracy":     f"{META['accuracy']*100:.1f}%",
        "cv_score":     f"{META['cv_mean']*100:.1f}% ± {META['cv_std']*100:.1f}%",
        "n_train":      META["n_train"],
        "n_features":   META["n_features"],
        "feature_importance": META["feature_importance"],
        "classes":      META["label_names"],
    })


# ── Frontend ──────────────────────────────────────────────────────────────────

HTML = open("templates/index.html").read()

@app.route("/")
def index():
    return render_template_string(HTML, model_accuracy=f"{META['accuracy']*100:.1f}")


if __name__ == "__main__":
    print("\n🌐 Starting DNS Shield Nepal")
    print("   Open: http://127.0.0.1:5000\n")
    app.run(debug=True, port=5000)