from dotenv import load_dotenv
load_dotenv(override=True)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import pickle
import json
import numpy as np
import pandas as pd
import re
from urllib.parse import urlparse
import uvicorn

# ── Init app ──
app = FastAPI(
    title="CyberShield API",
    description="AI-Based Cyber Threat Detection System",
    version="1.0.0"
)

# ── CORS — allows Chrome extension and React to call this API ──
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Load models ──
print("Loading models...")
rf_model  = joblib.load("../models/random_forest.pkl")
print("MODEL EXPECTS:", list(rf_model.feature_names_in_))
xgb_model = joblib.load("../models/xgboost.pkl")
print("RF classes:", rf_model.classes_)
print("XGB classes:", xgb_model.classes_)

with open("../models/ensemble_config.json") as f:
    config = json.load(f)

with open("../models/metrics.json") as f:
    metrics = json.load(f)

RF_WEIGHT  = config["rf_weight"]
XGB_WEIGHT = config["xgb_weight"]
print("✅ Models loaded!")

# ── Brand mismatch config — must match step2_features.ipynb exactly ──
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

def has_brand_mismatch(url, netloc):
    url_lower = url.lower()
    netloc_lower = netloc.lower()

    for brand, official_domains in BRAND_DOMAINS.items():
        if brand in url_lower:
            is_legit = any(
                netloc_lower == d or netloc_lower.endswith("." + d)
                for d in official_domains
            )
            if not is_legit:
                return 1
    return 0

# ── Feature extraction — must match step2_features.ipynb exactly ──
def extract_features(url):
    features = {}
    try:
        parsed = urlparse(url if url.startswith("http")
                         else "http://" + url)
        features["url_length"]        = len(url)
        features["has_https"]         = 1 if parsed.scheme == "https" else 0
        features["num_dots"]          = url.count(".")
        features["num_hyphens"]       = url.count("-")
        features["num_underscores"]   = url.count("_")
        features["num_slashes"]       = url.count("/")
        features["num_question"]      = url.count("?")
        features["num_equals"]        = url.count("=")
        features["num_at"]            = url.count("@")
        features["num_ampersand"]     = url.count("&")
        features["num_exclamation"]   = url.count("!")
        features["num_percent"]       = url.count("%")
        features["num_digits"]        = sum(c.isdigit() for c in url)
        features["num_special_chars"] = sum(not c.isalnum() for c in url)
        domain = parsed.netloc
        features["domain_length"]     = len(domain)
        features["num_subdomains"]    = domain.count(".")
        features["has_ip"]            = 1 if re.match(
            r'\d+\.\d+\.\d+\.\d+', domain) else 0
        features["has_hyphen_domain"] = 1 if "-" in domain else 0
        path = parsed.path
        features["path_length"]       = len(path)
        features["num_path_segments"] = path.count("/")
        features["has_php"]           = 1 if ".php" in url else 0
        features["has_html"]          = 1 if ".html" in url else 0
        features["has_exe"]           = 1 if ".exe" in url else 0
        features["has_zip"]           = 1 if ".zip" in url else 0
        # brand names removed — handled by has_brand_mismatch instead
        sus_words = ["login","secure","verify","account","update",
                     "confirm","banking","password","signin",
                     "free","lucky","winner","click","alert"]
        url_lower = url.lower()
        features["suspicious_words"]  = sum(1 for w in sus_words if w in url_lower)
        features["has_login"]         = 1 if "login"   in url_lower else 0
        features["has_secure"]        = 1 if "secure"  in url_lower else 0
        features["has_verify"]        = 1 if "verify"  in url_lower else 0
        features["has_account"]       = 1 if "account" in url_lower else 0
        features["has_free"]          = 1 if "free"    in url_lower else 0
        suspicious_tlds = [".ru",".cn",".tk",".ml",".ga",".cf",
                          ".gq",".xyz",".top",".click",".download",
                          ".zip",".review"]
        features["suspicious_tld"]    = 1 if any(
            url_lower.endswith(t) for t in suspicious_tlds) else 0
        features["digit_ratio"]       = (features["num_digits"] /
                                         len(url)) if len(url) > 0 else 0
        features["special_ratio"]     = (features["num_special_chars"] /
                                         len(url)) if len(url) > 0 else 0
        # new 34th feature — must match notebook exactly
        features["has_brand_mismatch"] = has_brand_mismatch(url, domain)
    except Exception:
        for key in features:
            features[key] = 0
    return features

# ── Request model ──
class URLRequest(BaseModel):
    url: str
    user_email: str | None = None  # optional — email of the user making the request

# ── Routes ──
@app.get("/")
def root():
    return {
        "message": "CyberShield API is running!",
        "version": "1.0.0",
        "status": "active"
    }

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "models_loaded": True,
        "accuracy": metrics["accuracy"],
        "auc_roc": metrics["auc_roc"]
    }

@app.post("/classify")
def classify_url(request: URLRequest):
    url = request.url.strip()
    # Trusted domains whitelist
    TRUSTED = [
    "google.com",
    "youtube.com",
    "github.com",
    "wikipedia.org",
    "stackoverflow.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "facebook.com",
    "twitter.com",
    "linkedin.com",
    "reddit.com",
    "python.org",
    "npmjs.com",
    "docs.python.org",
    "kaggle.com",
    "aicte-india.org",
    "aicte.india.gov.in",
    "gov.in",
    "nic.in",
    "india.gov.in",
    "mygov.in",
    "geeksforgeeks.org",
    "w3schools.com",
    "medium.com",
    "netflix.com",
    "localhost",
    "127.0.0.1",
    "whatsapp.com",
    "telegram.org",
    "spotify.com",
    "discord.com",
    "zoom.us",
    "slack.com",
    "chatgpt.com",
    "openai.com",
    "anthropic.com"
]
    
    from urllib.parse import urlparse
    try:
        hostname = urlparse(url).hostname or ""
        hostname = hostname.replace("www.", "")
        if any(hostname == d or hostname.endswith("." + d) 
               for d in TRUSTED):
            return {
                "url": url,
                "verdict": "SAFE",
                "confidence": 99.0,
                "prediction": 0,
                "reasons": ["Trusted domain — verified safe"],
                "features": {}
            }
    except:
        pass

    # Extract features
    feat = extract_features(url)
    feat_array = pd.DataFrame([feat])

    # Get predictions from both models
    rf_proba  = rf_model.predict_proba(feat_array)[0][1]
    xgb_proba = xgb_model.predict_proba(feat_array)[0][1]
    print(f"RF says: {rf_proba}, XGB says: {xgb_proba}")

    # Weighted ensemble
    final_proba = RF_WEIGHT * rf_proba + XGB_WEIGHT * xgb_proba
    prediction  = 1 if final_proba >= 0.5 else 0

    # Verdict
# Verdict
    if prediction == 0:
        verdict    = "SAFE"
        confidence = round((1 - final_proba) * 100, 2)
    else:
        verdict    = "MALICIOUS"
        confidence = round(final_proba * 100, 2)

    # Top SHAP-style reasons
    reasons = []
    if feat.get("has_brand_mismatch"):
        reasons.append("Brand name found in URL but domain doesn't match brand's real site")
    if feat["suspicious_tld"]:
        reasons.append("Suspicious TLD detected")
    if feat["has_ip"]:
        reasons.append("IP address used instead of domain")
    if feat["suspicious_words"] > 0:
        reasons.append(f"{feat['suspicious_words']} suspicious keyword(s) found")
    if feat["num_subdomains"] > 2:
        reasons.append("Excessive subdomains detected")
    if feat["url_length"] > 100:
        reasons.append("Unusually long URL")
    if feat["has_login"]:
        reasons.append("Login keyword in URL")
    if feat["has_secure"] and prediction == 1:
        reasons.append("Fake 'secure' keyword used")
    if feat["num_hyphens"] > 3:
        reasons.append("Multiple hyphens in domain")
    if not reasons:
        reasons = ["URL pattern matches known safe structure"] \
            if prediction == 0 else ["URL pattern matches malicious structure"]
    # Send email alert for threats — goes to the requesting user's email if provided,
    # otherwise falls back to the admin email configured in .env
    if prediction == 1:
        from email_alert import send_threat_alert
        send_threat_alert(url, verdict, confidence, reasons[:5], recipient=request.user_email)

    return {
        "url":        url,
        "verdict":    verdict,
        "confidence": confidence,
        "prediction": prediction,
        "reasons":    reasons[:5],
        "features": {
            "url_length":         feat["url_length"],
            "has_https":          feat["has_https"],
            "num_dots":           feat["num_dots"],
            "suspicious_words":   feat["suspicious_words"],
            "suspicious_tld":     feat["suspicious_tld"],
            "has_ip":             feat["has_ip"],
            "has_brand_mismatch": feat["has_brand_mismatch"],
        }
    }

# ── Run ──
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)