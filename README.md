# DNS Shield Nepal — Python ML Project

## Project Structure

```
dns-shield-nepal/
├── generate_dataset.py   ← Step 1: creates training data
├── features.py           ← Feature extraction (22 features)
├── train.py              ← Step 2: trains Random Forest model
├── app.py                ← Step 3: Flask web server
├── templates/
│   └── index.html        ← Frontend (served by Flask)
├── data/
│   └── domains.csv       ← Generated training dataset
└── models/
    ├── rf_model.pkl      ← Trained Random Forest (200 trees)
    ├── scaler.pkl        ← StandardScaler
    ├── feature_names.pkl ← Feature column order
    └── meta.pkl          ← Accuracy, CV scores, importances
```

## Run It (4 commands)

```bash
# 1. Install dependencies
pip install scikit-learn pandas numpy flask flask-cors

# 2. Generate training dataset
python generate_dataset.py

# 3. Train the model (takes ~10 seconds)
python train.py

# 4. Start the web server
python app.py
```

Open http://127.0.0.1:5000 in your browser.

## What Each File Does

**generate_dataset.py** — Creates 1,613 labeled domains (legitimate, phishing, malware/DGA, spam)

**features.py** — Extracts 22 numerical features from any domain string using Shannon entropy, Levenshtein distance, TLD abuse scores, phishing keywords, n-gram matching, and more

**train.py** — Trains a Random Forest classifier (200 trees), evaluates it (98.5% accuracy), and saves the model to models/

