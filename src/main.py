from dotenv import load_dotenv
load_dotenv(override=True)

import os
import csv
import json
import re
from datetime import datetime
import numpy as np
import pandas as pd
import joblib
import uvicorn

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse

import google.generativeai as genai

# ── Init app ──
app = FastAPI(
    title="CyberShield API",
    description="AI-Based Cyber Threat Detection System",
    version="1.1.0"
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

# ── Gemini setup ──
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL_NAME = os.getenv("GEMINI_MODEL", "gemini-3.6-flash")

gemini_model = None

# Cache Gemini results so the same URL is not sent repeatedly.
# Persisted to disk (../models/gemini_cache.json) so cached results survive
# a server restart — important the night before a demo with a limited
# free-tier quota.
GEMINI_CACHE_FILE = "../models/gemini_cache.json"
GEMINI_CACHE = {}
if os.path.exists(GEMINI_CACHE_FILE):
    try:
        with open(GEMINI_CACHE_FILE) as f:
            GEMINI_CACHE = json.load(f)
        print(f"✅ Loaded {len(GEMINI_CACHE)} cached Gemini results from disk")
    except Exception as e:
        print(f"⚠️ Could not load Gemini cache file: {e}")

def _save_gemini_cache():
    try:
        with open(GEMINI_CACHE_FILE, "w") as f:
            json.dump(GEMINI_CACHE, f, indent=2)
    except Exception as e:
        print(f"⚠️ Could not save Gemini cache file: {e}")

# If Gemini reaches its quota, disable further NEW calls (cached URLs still work)
GEMINI_QUOTA_EXCEEDED = False

if GEMINI_API_KEY:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        gemini_model = genai.GenerativeModel(GEMINI_MODEL_NAME)
        print(f"✅ Gemini configured ({GEMINI_MODEL_NAME})")
    except Exception as e:
        print(f"⚠️ Gemini setup failed: {e}")
        gemini_model = None
else:
    print("⚠️ GEMINI_API_KEY not set — ML-only mode")

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
        features["has_brand_mismatch"] = has_brand_mismatch(url, domain)
    except Exception:
        for key in features:
            features[key] = 0
    return features

# ── Gemini AI reasoning ──
def ask_llm_for_verdict(url: str):
    """
    Ask Gemini to independently assess a URL.

    Safety/fallback behavior:
    - Uses cached result if the same URL was already analyzed.
    - Does not call Gemini after quota has been exceeded.
    - Returns None if Gemini is unavailable.
    - ML classification continues even when Gemini fails.
    """

    global GEMINI_QUOTA_EXCEEDED

    # Gemini is not configured
    if gemini_model is None:
        return None

    # Normalize URL for caching
    cache_key = url.strip().lower()

    # Return cached result if this URL was already analyzed — checked BEFORE
    # the quota check, so URLs tested earlier still work even after quota runs out
    if cache_key in GEMINI_CACHE:
        print("✅ Using cached Gemini result")
        return GEMINI_CACHE[cache_key]

    # Stop sending NEW requests after quota has been exceeded
    if GEMINI_QUOTA_EXCEEDED:
        print("⚠️ Gemini quota exhausted — using ML result only")
        return None

    prompt = f"""
You are a cybersecurity analyst assessing a single URL for phishing risk.

URL: {url}

Consider:
- Is the domain a well-known legitimate service?
- Does the URL structure look normal?
- Does it look like deceptive brand impersonation?
- Are brand names being used on a domain that does not belong to that brand?
- Does the domain or TLD look suspicious?

Respond with ONLY valid JSON in exactly this format:

{{
  "verdict": "SAFE" or "MALICIOUS",
  "confidence": 0-100,
  "reason": "maximum 15 words"
}}
"""

    try:
        print(f"🤖 Asking Gemini about: {url}")

        response = gemini_model.generate_content(
            prompt,
            generation_config={
                "temperature": 0.1,
                "max_output_tokens": 1024
            }
        )

        raw_text = response.text.strip()

        # Extract JSON object
        match = re.search(r"\{.*\}", raw_text, re.DOTALL)

        if not match:
            print("⚠️ Gemini returned invalid JSON")
            return None

        parsed = json.loads(match.group(0))

        verdict = str(parsed.get("verdict", "")).upper()

        if verdict not in ("SAFE", "MALICIOUS"):
            print("⚠️ Gemini returned invalid verdict")
            return None

        confidence = float(parsed.get("confidence", 50))
        confidence = max(0.0, min(100.0, confidence))

        reason = str(
            parsed.get("reason", "")
        ).strip() or "No reason provided."

        result = {
            "verdict": verdict,
            "confidence": round(confidence, 2),
            "reason": reason
        }

        # Save result so repeated requests don't consume Gemini quota,
        # and persist to disk immediately so it survives a restart
        GEMINI_CACHE[cache_key] = result
        _save_gemini_cache()

        return result

    except Exception as e:

        error_message = str(e)

        # Gemini quota exceeded
        if "429" in error_message or "quota" in error_message.lower():
            GEMINI_QUOTA_EXCEEDED = True

            print(
                "⚠️ Gemini quota exceeded. "
                "Gemini will be disabled for this server session."
            )

            return None

        # Temporary Gemini/network failure
        if "503" in error_message or "timeout" in error_message.lower():
            print(
                "⚠️ Gemini temporarily unavailable. "
                "Continuing with ML result."
            )

            return None

        # Any other Gemini failure
        print(f"⚠️ Gemini call failed: {e}")
        return None

def combine_verdicts(ml_verdict, ml_confidence, llm_result):
    """
    Combines the ML ensemble verdict with the Gemini verdict.
    - Agreement -> average confidence, small boost (two independent signals agreeing).
    - Disagreement -> trust the LLM's contextual reasoning, but discount confidence
      since the two systems disagree (surfaced to the UI via `agreement: false`).
    - LLM unavailable -> ML-only result, unchanged.
    """
    if llm_result is None:
        return {
            "verdict": ml_verdict,
            "confidence": ml_confidence,
            "agreement": None,
            "ai_verdict": None,
            "ai_confidence": None,
            "ai_reason": "AI reasoning unavailable — showing ML model result only.",
        }

    llm_verdict = llm_result["verdict"]
    llm_confidence = llm_result["confidence"]
    llm_reason = llm_result["reason"]

    if ml_verdict == llm_verdict:
        final_verdict = ml_verdict
        final_confidence = round(min(99.0, (ml_confidence + llm_confidence) / 2 + 5), 2)
        agreement = True
    else:
        final_verdict = llm_verdict
        final_confidence = round(llm_confidence * 0.8, 2)
        agreement = False

    return {
        "verdict": final_verdict,
        "confidence": final_confidence,
        "agreement": agreement,
        "ai_verdict": llm_verdict,
        "ai_confidence": llm_confidence,
        "ai_reason": llm_reason,
    }

# ── Auto-log confirmed malicious URLs — for future dataset expansion ──
# Only logs when BOTH the ML ensemble AND Gemini independently agree it's
# malicious (agreement=True). This deliberately excludes the ML-alone case,
# since real-world testing showed the ML model can be confidently wrong on
# modern/unusual legitimate sites (huggingface.co, quora.com, etc.) —
# logging those would poison future training data with false positives.
# Writes to a separate review file, NOT directly into raw_urls.csv, so a
# human can review before promoting entries into the actual training set.
CONFIRMED_MALICIOUS_LOG = "../data/auto_logged_malicious.csv"

def log_confirmed_malicious(url: str, ml_confidence: float,
                              ai_confidence: float, combined_confidence: float):
    try:
        file_exists = os.path.exists(CONFIRMED_MALICIOUS_LOG)
        with open(CONFIRMED_MALICIOUS_LOG, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow([
                    "url", "label", "ml_confidence",
                    "ai_confidence", "combined_confidence", "timestamp"
                ])
            writer.writerow([
                url, 1, ml_confidence, ai_confidence,
                combined_confidence, datetime.now().isoformat()
            ])
    except Exception as e:
        # Never let logging failures affect the actual classification response
        print(f"⚠️ Could not log confirmed malicious URL: {e}")

# ── Request model ──
class URLRequest(BaseModel):
    url: str
    user_email: str | None = None

# ── Routes ──
@app.get("/")
def root():
    return {
        "message": "CyberShield API is running!",
        "version": "1.1.0",
        "status": "active",
        "llm_enabled": gemini_model is not None,
    }

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "models_loaded": True,
        "llm_enabled": gemini_model is not None,
        "accuracy": metrics["accuracy"],
        "auc_roc": metrics["auc_roc"]
    }

@app.post("/classify")
def classify_url(request: URLRequest):
    url = request.url.strip()

    # Trusted domains whitelist
    TRUSTED = [
        "google.com", "youtube.com", "github.com", "wikipedia.org",
        "stackoverflow.com", "microsoft.com", "apple.com", "amazon.com",
        "facebook.com", "twitter.com", "linkedin.com", "reddit.com",
        "python.org", "npmjs.com", "docs.python.org", "kaggle.com",
        "aicte-india.org", "aicte.india.gov.in", "gov.in", "nic.in",
        "india.gov.in", "mygov.in", "geeksforgeeks.org", "w3schools.com",
        "medium.com", "netflix.com", "localhost", "127.0.0.1",
        "whatsapp.com", "telegram.org", "spotify.com", "discord.com",
        "quora.com", "coursera.org", "scrimba.com",
        "huggingface.co", "biet.ac.in", "propeers.in", "internshala.com",
        "zoom.us", "slack.com", "chatgpt.com", "openai.com", "anthropic.com"
    ]

    try:
        hostname = urlparse(url).hostname or ""
        hostname = hostname.replace("www.", "")
        if any(hostname == d or hostname.endswith("." + d) for d in TRUSTED):
            return {
                "url": url,
                "verdict": "SAFE",
                "confidence": 99.0,
                "prediction": 0,
                "reasons": ["Trusted domain — verified safe"],
                "ai_verdict": None,
                "ai_confidence": None,
                "ai_reason": "Skipped — whitelisted domain",
                "agreement": None,
                "features": {}
            }
    except Exception:
        pass

    # ── Not whitelisted: run ML ensemble ──
    feat = extract_features(url)
    feat_array = pd.DataFrame([feat])

    rf_proba  = rf_model.predict_proba(feat_array)[0][1]
    xgb_proba = xgb_model.predict_proba(feat_array)[0][1]
    print(f"RF says: {rf_proba}, XGB says: {xgb_proba}")

    final_proba = RF_WEIGHT * rf_proba + XGB_WEIGHT * xgb_proba
    ml_prediction = 1 if final_proba >= 0.5 else 0

    if ml_prediction == 0:
        ml_verdict = "SAFE"
        ml_confidence = round((1 - final_proba) * 100, 2)
    else:
        ml_verdict = "MALICIOUS"
        ml_confidence = round(final_proba * 100, 2)

    # ── Not whitelisted: also ask Gemini, independently ──
    llm_result = ask_llm_for_verdict(url)
    combined = combine_verdicts(ml_verdict, ml_confidence, llm_result)

    verdict    = combined["verdict"]
    confidence = combined["confidence"]
    prediction = 0 if verdict == "SAFE" else 1

    # Top SHAP-style reasons (from ML features)
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
    if not feat["has_https"]:
        reasons.append("No HTTPS — insecure connection (plain HTTP)")
    if feat["special_ratio"] > 0.2:
        reasons.append(f"High proportion of special characters ({feat['special_ratio']*100:.1f}% of URL)")
    if feat["digit_ratio"] > 0.3:
        reasons.append(f"Unusually high digit ratio ({feat['digit_ratio']*100:.1f}% of URL)")
    if combined.get("agreement") is False:
        reasons.append("AI reasoning overrode the ML model — see ai_reason")
    if not reasons:
        reasons = ["URL pattern matches known safe structure"] \
            if prediction == 0 else ["URL pattern matches malicious structure"]

    # ── Print the ML model's reasoning to the terminal for malicious verdicts ──
    if prediction == 1:
        print(f"🔍 Why flagged {verdict} (ml_confidence={ml_confidence}%):")
        for r in reasons[:5]:
            print(f"   - {r}")

    if prediction == 1:
        from email_alert import send_threat_alert
        send_threat_alert(url, verdict, confidence, reasons[:5], recipient=request.user_email)

        # Auto-log to the dataset review file, but ONLY when ML and AI
        # independently agree — see log_confirmed_malicious() docstring
        # for why ML-alone verdicts are deliberately excluded.
        if combined.get("agreement") is True:
            log_confirmed_malicious(
                url, ml_confidence,
                combined.get("ai_confidence"), confidence
            )

    return {
        "url":            url,
        "verdict":        verdict,
        "confidence":     confidence,
        "prediction":     prediction,
        "reasons":        reasons[:5],
        "ml_verdict":     ml_verdict,
        "ml_confidence":  ml_confidence,
        "ai_verdict":     combined.get("ai_verdict"),
        "ai_confidence":  combined.get("ai_confidence"),
        "ai_reason":      combined.get("ai_reason"),
        "agreement":      combined.get("agreement"),
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