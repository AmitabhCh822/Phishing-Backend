from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import joblib
import numpy as np

HIGH_RISK = [
    # financial + identity
    "bank account",
    "account number",
    "social security",
    "ssn",
    "credit card",
    "routing number",
    "debit card",
    "security code",
    "cvv",
    "pin number",
    "identity verification",
    "id card",
    "photo id",
    "driver's license",

    # credential harvesting
    "password",
    "login now",
    "login to continue",
    "reset your password",
    "confirm your password",
    "verify immediately",
    "your account has been suspended",
    "your account will be closed",
    "security alert",
    "unusual activity detected",

    # money movement
    "wire transfer",
    "direct deposit update",
    "payment overdue",
    "billing issue",
    "account compromised",

    # emergency social engineering
    "urgent action required",
    "immediately",
    "within 24 hours",
    "final notice",
    "your access will be revoked",
]

MEDIUM_RISK = [
    # account maintenance phrases
    "verify your account",
    "update your information",
    "update your details",
    "renew your pass",
    "renew your permit",
    "renew your subscription",
    "confirm your details",
    "review your account",
    "validate your account",
    "reactivate your account",
    "your information needs updating",

    # mild urgency but not aggressive
    "as soon as possible",
    "attention required",
    "pending verification",
    "account review needed",
    "incomplete application",

    # common in phishing, sometimes legit
    "document attached",
    "download the form",
    "fill out the form",
    "attached invoice",
    "invoice pending",
    "billing update",

    # link manipulation phrases
    "log in to view",
    "access your account here",
    "update required",
    "review document",
    "shared a document with you",
]

LOW_RISK = [
    # general actions
    "click",
    "click here",
    "sign in",
    "follow the link",
    "access your account",
    "review this",
    "check the link",
    "learn more",
    "view message",

    # neutral email behaviors that can appear in phishing
    "view your statement",
    "see attached",
    "your monthly report",
    "your receipt",
    "confirm below",
    "continue here",

    # cloud service phrases (neutral but sometimes used in attacks)
    "sharepoint link",
    "onedrive link",
    "google drive link",
    "document is available",
    "your file is ready",
]

# ----------------------------------------------------
# Keyword Lists For Rule-Based Flags
# ----------------------------------------------------
SENSITIVE_TERMS = [
    "passport", "ssn", "social security", "id card",
    "bank account", "routing number", "credit card",
    "password", "login", "credentials"
]

ACTION_TERMS = [
    "send", "provide", "reply with", "upload", "share"
]

# ----------------------------------------------------
# Rule-Based Function for High-Risk Manual Override
# ----------------------------------------------------
def rule_based_flags(text: str) -> bool:
    t = text.lower()
    sensitive = any(w in t for w in SENSITIVE_TERMS)
    action = any(w in t for w in ACTION_TERMS)
    return sensitive and action


# ----------------------------------------------------
# Load ML Model + Vectorizer
# ----------------------------------------------------
model = joblib.load("model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

MODEL_CLASSES = list(model.classes_)

# Normalize model class labels
if MODEL_CLASSES == [0, 1] or MODEL_CLASSES == [1, 0]:
    SAFE_LABEL = 0
    PHISHING_LABEL = 1
elif "safe" in MODEL_CLASSES and "phishing" in MODEL_CLASSES:
    SAFE_LABEL = "safe"
    PHISHING_LABEL = "phishing"
else:
    raise ValueError("Model classes must be [0,1] or ['safe','phishing'].")

SAFE_INDEX = MODEL_CLASSES.index(SAFE_LABEL)
PHISHING_INDEX = MODEL_CLASSES.index(PHISHING_LABEL)


# ----------------------------------------------------
# FastAPI App
# ----------------------------------------------------
app = FastAPI(
    title="Phishing Email Detector API",
    description="Hybrid ML + Rule-based phishing detector",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ----------------------------------------------------
# API Request & Response Models
# ----------------------------------------------------
class EmailRequest(BaseModel):
    email: str

class PredictionResponse(BaseModel):
    prediction: int      # 0 = safe, -1 = suspicious, 1 = phishing
    label: str           # "safe", "suspicious", "phishing"
    safe_prob: float     # % confidence safe
    phishing_prob: float # % confidence phishing


# ----------------------------------------------------
# Root Endpoint
# ----------------------------------------------------
@app.get("/")
def root():
    return {"message": "Phishing detector API running", "docs": "/docs"}


# ----------------------------------------------------
# Hybrid Scoring Logic
# ----------------------------------------------------
def compute_manual_score(text: str) -> int:
    t = text.lower()
    score = 0

    # HIGH RISK TERMS → +4 each
    for term in HIGH_RISK:
        if term in t:
            score += 4

    # MEDIUM RISK TERMS → +3 each
    for term in MEDIUM_RISK:
        if term in t:
            score += 3

    # LOW RISK TERMS → +1 each
    for term in LOW_RISK:
        if term in t:
            score += 1

    return score


# ----------------------------------------------------
# ML + Rules + Scoring Prediction Endpoint
# ----------------------------------------------------
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

    # Vectorize for ML model
    X = vectorizer.transform([text])
    ml_label_raw = model.predict(X)[0]
    probs = model.predict_proba(X)[0]

    ml_safe_prob = float(probs[SAFE_INDEX] * 100)
    ml_phishing_prob = float(probs[PHISHING_INDEX] * 100)

    # ----------------------------------------------------
    # Manual Scoring
    # ----------------------------------------------------
    manual_score = compute_manual_score(text)

    # ----------------------------------------------------
    # Combine ML + Rule-based overrides
    # ----------------------------------------------------

    # HARD OVERRIDE: extremely dangerous pattern
    if rule_based_flags(text):
        phishing_prob = 95.0
        safe_prob = 5.0
        label = "phishing"
        prediction = 1
        return PredictionResponse(
            prediction=prediction,
            label=label,
            safe_prob=safe_prob,
            phishing_prob=phishing_prob
        )

    # START WITH ML PROBABILITIES
    phishing_prob = ml_phishing_prob
    safe_prob = ml_safe_prob

    # MEDIUM SUSPICIOUS RANGE (manual score influence)
    if 3 <= manual_score <= 6 and phishing_prob < 60:
        phishing_prob = 50.0
        safe_prob = 50.0

    # FINAL LABEL DECISION
    if phishing_prob >= 80:
        label = "phishing"
        prediction = 1

    elif phishing_prob >= 40:
        label = "suspicious"
        prediction = -1

    else:
        label = "safe"
        prediction = 0

    return PredictionResponse(
        prediction=prediction,
        label=label,
        safe_prob=round(safe_prob, 2),
        phishing_prob=round(phishing_prob, 2)
    )

