from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import joblib
import numpy as np

SENSITIVE_TERMS = ["passport", "ssn", "social security", "id card", "bank account",
                   "routing number", "credit card", "password", "login", "credentials"]

ACTION_TERMS = ["send", "provide", "reply with", "upload", "share"]

def rule_based_flags(text):
    t = text.lower()
    sensitive = any(w in t for w in SENSITIVE_TERMS)
    action = any(w in t for w in ACTION_TERMS)
    return sensitive and action

# -----------------------------
# Load model + vectorizer
# -----------------------------
model = joblib.load("model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

# Detect label format automatically (VERY IMPORTANT)
MODEL_CLASSES = list(model.classes_)

# Normalized mapping
if MODEL_CLASSES == [0, 1] or MODEL_CLASSES == [1, 0]:
    # Numeric labels
    SAFE_LABEL = 0
    PHISHING_LABEL = 1
elif "safe" in MODEL_CLASSES and "phishing" in MODEL_CLASSES:
    # String labels
    SAFE_LABEL = "safe"
    PHISHING_LABEL = "phishing"
else:
    raise ValueError("Model classes must be either [0,1] or ['safe','phishing'].")

SAFE_INDEX = MODEL_CLASSES.index(SAFE_LABEL)
PHISHING_INDEX = MODEL_CLASSES.index(PHISHING_LABEL)

# -----------------------------
# FastAPI App
# -----------------------------
app = FastAPI(
    title="Phishing Email Detector API",
    description="Logistic Regression phishing classifier",
    version="1.0.2"
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
# Prediction Endpoint
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

    # Map prediction to numeric
    pred = 1 if pred_raw == PHISHING_LABEL else 0

    # Extract correct probabilities
    safe_prob = round(float(probabilities[SAFE_INDEX] * 100), 2)
    phishing_prob = round(float(probabilities[PHISHING_INDEX] * 100), 2)

    label = "phishing" if pred == 1 else "safe"

    # Rule-Based Override
    # -----------------------------
    if rule_based_flags(text):
        pred = 1
        label = "phishing"
        phishing_prob = max(phishing_prob, 95.0)
        safe_prob = 100 - phishing_prob

    return PredictionResponse(
        prediction=pred,
        label=label,
        safe_prob=safe_prob,
        phishing_prob=phishing_prob
    )


