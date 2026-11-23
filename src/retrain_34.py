"""
CyberShield - retrain Random Forest + XGBoost on the 34 features from the report.

Run from the project's `src` folder (so the default paths work):
    python retrain_34.py
or give paths explicitly:
    python retrain_34.py --data ../data/raw_urls.csv --out ../models_34

Nothing in your existing `models` folder is touched. New files go to --out.
Check the printed results first, then copy the files you want into `models`.

Pipeline follows the report (Ch 5):
  * 64% train / 16% calibration / 20% test, stratified, random_state=42
  * RF: 100 trees, max_depth 20, balanced class weights
  * XGBoost: 100 estimators, max_depth 6, lr 0.1, scale_pos_weight = legit/malicious
  * Sigmoid calibration (CalibratedClassifierCV + FrozenEstimator) on the calibration split
  * Ensemble = 0.55 * RF + 0.45 * XGB, threshold 0.5
"""
import argparse
import json
import os
import re
import time
from urllib.parse import urlparse

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.frozen import FrozenEstimator
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score,
                             roc_curve)
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight
from xgboost import XGBClassifier

RF_WEIGHT, XGB_WEIGHT, THRESHOLD = 0.55, 0.45, 0.5

# ---------------------------------------------------------------------------
# Feature extraction - copied from main.py so training and the backend match
# ---------------------------------------------------------------------------
BRAND_DOMAINS = {
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de"],
    "apple": ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com"],
    "google": ["google.com", "gmail.com", "youtube.com"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
    "netflix": ["netflix.com"],
    "ebay": ["ebay.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
}

SUS_WORDS = ["login", "secure", "verify", "account", "update", "confirm",
             "banking", "password", "signin", "free", "lucky", "winner",
             "click", "alert"]
SUS_TLDS = [".ru", ".cn", ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
            ".click", ".download", ".zip", ".review"]

FEATURE_COLS = [
    "url_length", "has_https", "num_dots", "num_hyphens", "num_underscores",
    "num_slashes", "num_question", "num_equals", "num_at", "num_ampersand",
    "num_exclamation", "num_percent", "num_digits", "num_special_chars",
    "domain_length", "num_subdomains", "has_ip", "has_hyphen_domain",
    "path_length", "num_path_segments", "has_php", "has_html", "has_exe",
    "has_zip", "suspicious_words", "has_login", "has_secure", "has_verify",
    "has_account", "has_free", "suspicious_tld", "digit_ratio",
    "special_ratio", "has_brand_mismatch",
]
assert len(FEATURE_COLS) == 34


def has_brand_mismatch(url, netloc):
    url_lower, netloc_lower = url.lower(), netloc.lower()
    for brand, official in BRAND_DOMAINS.items():
        if brand in url_lower:
            legit = any(netloc_lower == d or netloc_lower.endswith("." + d)
                        for d in official)
            if not legit:
                return 1
    return 0


def extract_features(url):
    f = {}
    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        f["url_length"] = len(url)
        f["has_https"] = 1 if parsed.scheme == "https" else 0
        f["num_dots"] = url.count(".")
        f["num_hyphens"] = url.count("-")
        f["num_underscores"] = url.count("_")
        f["num_slashes"] = url.count("/")
        f["num_question"] = url.count("?")
        f["num_equals"] = url.count("=")
        f["num_at"] = url.count("@")
        f["num_ampersand"] = url.count("&")
        f["num_exclamation"] = url.count("!")
        f["num_percent"] = url.count("%")
        f["num_digits"] = sum(c.isdigit() for c in url)
        f["num_special_chars"] = sum(not c.isalnum() for c in url)
        domain = parsed.netloc
        f["domain_length"] = len(domain)
        f["num_subdomains"] = domain.count(".")
        f["has_ip"] = 1 if re.match(r"\d+\.\d+\.\d+\.\d+", domain) else 0
        f["has_hyphen_domain"] = 1 if "-" in domain else 0
        path = parsed.path
        f["path_length"] = len(path)
        f["num_path_segments"] = path.count("/")
        f["has_php"] = 1 if ".php" in url else 0
        f["has_html"] = 1 if ".html" in url else 0
        f["has_exe"] = 1 if ".exe" in url else 0
        f["has_zip"] = 1 if ".zip" in url else 0
        ul = url.lower()
        f["suspicious_words"] = sum(1 for w in SUS_WORDS if w in ul)
        f["has_login"] = 1 if "login" in ul else 0
        f["has_secure"] = 1 if "secure" in ul else 0
        f["has_verify"] = 1 if "verify" in ul else 0
        f["has_account"] = 1 if "account" in ul else 0
        f["has_free"] = 1 if "free" in ul else 0
        f["suspicious_tld"] = 1 if any(ul.endswith(t) for t in SUS_TLDS) else 0
        n = len(url)
        f["digit_ratio"] = f["num_digits"] / n if n > 0 else 0
        f["special_ratio"] = f["num_special_chars"] / n if n > 0 else 0
        f["has_brand_mismatch"] = has_brand_mismatch(url, domain)
    except Exception:
        f = {}
    # make sure every URL gets all 34 columns, in a fixed order
    return [f.get(c, 0) for c in FEATURE_COLS]


# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="../data/raw_urls.csv")
    ap.add_argument("--out", default="../models_34")
    ap.add_argument("--url-col", default=None, help="name of the URL column")
    ap.add_argument("--label-col", default=None, help="name of the label column")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    # ---- load ----
    df = pd.read_csv(args.data)
    print("Loaded", args.data, df.shape, "columns:", list(df.columns))
    url_col = args.url_col or next(c for c in df.columns if c.lower() == "url")
    label_col = args.label_col or next(c for c in df.columns if c.lower() == "label")
    df = df[[url_col, label_col]].dropna()
    df[url_col] = df[url_col].astype(str).str.strip()
    df[label_col] = df[label_col].astype(int)
    assert set(df[label_col].unique()) <= {0, 1}, "label must be 0 (legit) / 1 (malicious)"
    print("Rows:", len(df), "| legit:", (df[label_col] == 0).sum(),
          "| malicious:", (df[label_col] == 1).sum())

    # ---- features ----
    t0 = time.time()
    print("Extracting 34 features (a few minutes for ~650k URLs)...")
    X = pd.DataFrame([extract_features(u) for u in df[url_col]], columns=FEATURE_COLS)
    y = df[label_col].reset_index(drop=True)
    print(f"Done in {time.time() - t0:.0f}s -> X shape {X.shape}")
    feat_out = X.copy()
    feat_out["label"] = y
    feat_out.to_csv(os.path.join(args.out, "features_34.csv"), index=False)

    # ---- split 64 / 16 / 20 ----
    X_tmp, X_test, y_tmp, y_test = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=42)
    X_train, X_cal, y_train, y_cal = train_test_split(
        X_tmp, y_tmp, test_size=0.20, stratify=y_tmp, random_state=42)
    print(f"Split -> train {len(X_train)}, calibration {len(X_cal)}, test {len(X_test)}")

    # ---- class imbalance ----
    classes = np.array([0, 1])
    cw = compute_class_weight("balanced", classes=classes, y=y_train)
    class_weight = {0: float(cw[0]), 1: float(cw[1])}
    spw = float((y_train == 0).sum() / (y_train == 1).sum())
    print("RF class weights:", class_weight, "| XGB scale_pos_weight:", round(spw, 4))

    # ---- train ----
    t0 = time.time()
    rf = RandomForestClassifier(n_estimators=100, max_depth=20,
                                class_weight=class_weight, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    print(f"Random Forest trained in {time.time() - t0:.0f}s")

    t0 = time.time()
    xgb = XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1,
                        scale_pos_weight=spw, random_state=42, n_jobs=-1,
                        eval_metric="logloss")
    xgb.fit(X_train, y_train)
    print(f"XGBoost trained in {time.time() - t0:.0f}s")

    # ---- calibrate ----
    rf_cal = CalibratedClassifierCV(FrozenEstimator(rf), method="sigmoid").fit(X_cal, y_cal)
    xgb_cal = CalibratedClassifierCV(FrozenEstimator(xgb), method="sigmoid").fit(X_cal, y_cal)

    # ---- evaluate ----
    def acc(p):
        return float(accuracy_score(y_test, (p >= THRESHOLD).astype(int)))

    p_rf_raw = rf.predict_proba(X_test)[:, 1]
    p_xgb_raw = xgb.predict_proba(X_test)[:, 1]
    p_rf = rf_cal.predict_proba(X_test)[:, 1]
    p_xgb = xgb_cal.predict_proba(X_test)[:, 1]
    p_ens = RF_WEIGHT * p_rf + XGB_WEIGHT * p_xgb
    pred = (p_ens >= THRESHOLD).astype(int)

    tn, fp, fn, tp = confusion_matrix(y_test, pred).ravel()
    fpr, tpr, _ = roc_curve(y_test, p_ens)
    idx = np.linspace(0, len(fpr) - 1, 60).astype(int)  # small curve for the dashboard

    metrics = {
        "accuracy": float(accuracy_score(y_test, pred)),
        "precision": float(precision_score(y_test, pred)),
        "recall": float(recall_score(y_test, pred)),
        "f1_score": float(f1_score(y_test, pred)),
        "auc_roc": float(roc_auc_score(y_test, p_ens)),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "rf_accuracy_raw": acc(p_rf_raw), "rf_accuracy_calibrated": acc(p_rf),
        "xgb_accuracy_raw": acc(p_xgb_raw), "xgb_accuracy_calibrated": acc(p_xgb),
        "n_train": int(len(X_train)), "n_calibration": int(len(X_cal)),
        "n_test": int(len(X_test)), "n_features": 34,
        "roc": {"fpr": [round(float(v), 5) for v in fpr[idx]],
                "tpr": [round(float(v), 5) for v in tpr[idx]]},
        "rf_feature_importance": sorted(
            [{"feature": c, "importance": round(float(v), 5)}
             for c, v in zip(FEATURE_COLS, rf.feature_importances_)],
            key=lambda d: -d["importance"]),
    }
    config = {
        "rf_weight": RF_WEIGHT, "xgb_weight": XGB_WEIGHT, "threshold": THRESHOLD,
        "ensemble_accuracy": metrics["accuracy"],
        "class_weights": {"legitimate": class_weight[0], "malicious": class_weight[1]},
        "scale_pos_weight": spw,
    }

    # ---- save ----
    joblib.dump(rf_cal, os.path.join(args.out, "random_forest.pkl"))
    joblib.dump(xgb_cal, os.path.join(args.out, "xgboost.pkl"))
    with open(os.path.join(args.out, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)
    with open(os.path.join(args.out, "ensemble_config.json"), "w") as f:
        json.dump(config, f, indent=2)

    print("\n================ RESULTS (test set) ================")
    print(f"Random Forest : raw {metrics['rf_accuracy_raw']:.4f} -> calibrated {metrics['rf_accuracy_calibrated']:.4f}")
    print(f"XGBoost       : raw {metrics['xgb_accuracy_raw']:.4f} -> calibrated {metrics['xgb_accuracy_calibrated']:.4f}")
    print(f"Ensemble      : accuracy {metrics['accuracy']:.4f} | precision {metrics['precision']:.4f} | "
          f"recall {metrics['recall']:.4f} | F1 {metrics['f1_score']:.4f} | AUC {metrics['auc_roc']:.4f}")
    print(f"Confusion     : TP {tp}  TN {tn}  FP {fp}  FN {fn}")
    print("Top 5 RF features:", [d["feature"] for d in metrics["rf_feature_importance"][:5]])
    print("Saved to:", os.path.abspath(args.out))


if __name__ == "__main__":
    main()