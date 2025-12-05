from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import joblib
import numpy as np
import re

# -----------------------------
# RULE-BASED PHISHING SCORING SYSTEM
# -----------------------------

HIGH_RISK = {
    "passport": 6,
    "ssn": 6,
    "social security": 6,
    "bank account": 6,
    "routing number": 6,
    "credit card": 6,
    "password": 6,
    "verify your identity": 5,
}

MEDIUM_RISK = {
    "renew your pass": 3,
    "renew your permit": 3,
    "renew now": 3,
    "verify your account": 3,
    "update your information": 3,
    "login to continue": 3,
    "sign in and renew": 3,
}

LOW_RISK = {
    "asap": 1,
    "immediately": 1,
    "urgent": 1,
    "action required": 1,
    "right away": 1,
}

SENDER_RISK_DOMAINS = ["gmail.com", "yahoo.com", "hotmail.com"]
NON_UC_LINK_SCORE = 4


def phishing_score(text):
    text = text.lower()
    score = 0

    # HIGH RISK
    for phrase, pts in HIGH_RISK.items():
        if phrase in text:
            score += pts

    # MEDIUM RISK
    for phrase, pts in MEDIUM_RISK.items():
        if phrase in text:
            score += pts

    # LOW RISK
    for phrase, pts in LOW_RISK.items():
        if phrase in text:
            score += pts

    # URL CHECK
    urls = re.findall(r'https?://[^\s]+', text)
    for url in urls:
        if not url.endswith(".uc.edu"):
            score += NON_UC_LINK_SCORE

    return score


def classify_risk(score):
    if score >= 6:
        return "phishing"
    elif score >= 3:
        return "suspicious"
    else:
        return "safe"


# -----------------------------
# Load ML Model + Vectorizer
# -----------------------------
model = joblib.load("model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

MODEL_CLASSES = list(model.classes_)

if MODEL_CLASSES == [0, 1] or MODEL_CLASSES == [1, 0]:
    SAFE_LABEL = 0
    PHISHING_LABEL = 1
elif "safe" in MODEL_CLASSES and "phishing" in MODEL_CLASSES:
    SAFE_LABEL = "safe"
    PHISHING_LABEL = "phishing"
else:
    raise ValueError("Model classes must be either [0,1] or ['safe','phishing'].")

SAFE_INDEX = MODEL_CLASSES.index(SAFE_LABEL)
PHISHING_INDEX = MODEL_CLASSES.index(PHISHING_LABEL)


# -----------------------------
# FastAPI App Setup
# -----------------------------
app = FastAPI(
    title="Phishing Email Detector API",
    description="Hybrid ML + Rule-Based Phishing Classifier",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -----------------------------
# Request + Response Models
# -----------------------------
class EmailRequest(BaseModel):
    email: str

class PredictionResponse(BaseModel):
    prediction: int
    label: str
    safe_prob: float
    phishing_prob: float


# -----------------------------
# Root Endpoint
# -----------------------------
@app.get("/")
def root():
    return {"message": "Phishing detector API is running!", "docs": "/docs"}


# -----------------------------
# PREDICTION ENDPOINT
# -----------------------------
@app.post("/predict", response_model=PredictionResponse)
def predict_email(payload: EmailRequest):
    text = payload.email.strip()

    if not text:
        return PredictionResponse(
            prediction=0,
            label="safe",
            safe_prob=100.0,
            phishing_prob=0.0
        )

    # Vectorize text
    X = vectorizer.transform([text])

    # Predict
    pred_raw = model.predict(X)[0]
    probabilities = model.predict_proba(X)[0]

    # Extract probabilities
    safe_prob = float(probabilities[SAFE_INDEX] * 100)
    phishing_prob = float(probabilities[PHISHING_INDEX] * 100)

    # -----------------------------
    # RULE-BASED FLAGS
    # -----------------------------
    t = text.lower()

    sensitive = any(w in t for w in SENSITIVE_TERMS)
    action = any(w in t for w in ACTION_TERMS)

    mild_suspicious_terms = [
        "confirm your information",
        "verify your details",
        "review your account",
        "we noticed unusual activity",
        "asap",
        "immediately",
        "renew your"
    ]

    mild_flag = any(w in t for w in mild_suspicious_terms)

    # Strong phishing rule
    if sensitive and action:
        label = "phishing"
        phishing_prob = max(phishing_prob, 85.0)
        safe_prob = 100 - phishing_prob
        return PredictionResponse(
            prediction=1,
            label=label,
            safe_prob=round(safe_prob, 2),
            phishing_prob=round(phishing_prob, 2)
        )

    # Mild suspicious rule
    if mild_flag:
        # Push into suspicious range artificially
        if phishing_prob < 40:
            phishing_prob = 50.0
            safe_prob = 50.0

    # -----------------------------
    # ML + RULE-BASED RISK TIERS
    # -----------------------------
    if phishing_prob >= 80:
        label = "phishing"
        prediction = 1
    elif phishing_prob >= 40:
        label = "suspicious"
        prediction = -1  # special code for UI if you want
    else:
        label = "safe"
        prediction = 0

    return PredictionResponse(
        prediction=prediction,
        label=label,
        safe_prob=round(safe_prob, 2),
        phishing_prob=round(phishing_prob, 2)
    )
