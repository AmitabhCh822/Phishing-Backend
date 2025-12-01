from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import joblib
import numpy as np

# -------------------------
# Load model + vectorizer
# -------------------------
model = joblib.load("model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

# Check model class order (VERY important)
MODEL_CLASSES = list(model.classes_)
print("Loaded model classes:", MODEL_CLASSES)

# Figure out index of each label
SAFE_INDEX = MODEL_CLASSES.index("safe")
PHISHING_INDEX = MODEL_CLASSES.index("phishing")

# -------------------------
# FastAPI App
# -------------------------
app = FastAPI(
    title="Phishing Email Detector API",
    description="Logistic Regression phishing classifier API",
    version="1.0.1",
)

# Allow all origins (you can restrict later)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------
# Request + Response Models
# -------------------------
class EmailRequest(BaseModel):
    email: str

class PredictionResponse(BaseModel):
    prediction: int
    label: str
    safe_prob: float
    phishing_prob: float


# -------------------------
# Root Endpoint
# -------------------------
@app.get("/")
def root():
    return {
        "message": "Phishing detector API running",
        "docs": "/docs"
    }


# -------------------------
# Prediction Endpoint
# -------------------------
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
    pred = int(model.predict(X)[0])
    probabilities = model.predict_proba(X)[0]

    # Extract correct probability by index
    safe_prob = round(float(probabilities[SAFE_INDEX] * 100), 2)
    phishing_prob = round(float(probabilities[PHISHING_INDEX] * 100), 2)

    # Convert prediction to label
    label = "phishing" if pred == 1 else "safe"

    return PredictionResponse(
        prediction=pred,
        label=label,
        safe_prob=safe_prob,
        phishing_prob=phishing_prob
    )
