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

    # Vectorize
    X = vectorizer.transform([text])

    # ML Prediction
    pred_raw = model.predict(X)[0]
    probabilities = model.predict_proba(X)[0]

    pred = 1 if pred_raw == PHISHING_LABEL else 0

    safe_prob = round(float(probabilities[SAFE_INDEX] * 100), 2)
    phishing_prob = round(float(probabilities[PHISHING_INDEX] * 100), 2)

    ml_label = "phishing" if pred == 1 else "safe"

    # -----------------------------
    # RULE-BASED SCORING
    # -----------------------------
    score = phishing_score(text)
    rule_label = classify_risk(score)

    # -----------------------------
    # Hybrid Decision Logic
    # -----------------------------
    # If rules detect phishing → phishing
    if rule_label == "phishing":
        final_label = "phishing"
        pred = 1
        phishing_prob = max(phishing_prob, 95.0)
        safe_prob = 100 - phishing_prob

    # If rules detect suspicious → override ML safe
    elif rule_label == "suspicious" and ml_label == "safe":
        final_label = "suspicious"
        pred = 1  # treat suspicious as risk
        phishing_prob = max(phishing_prob, 60.0)
        safe_prob = 100 - phishing_prob

    else:
        final_label = ml_label  # ML wins if rules say safe

    return PredictionResponse(
        prediction=pred,
        label=final_label,
        safe_prob=safe_prob,
        phishing_prob=phishing_prob
    )
