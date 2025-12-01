from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import joblib
import numpy as np

# Load model and vectorizer at startup
# These filenames must match what you put in the folder
model = joblib.load("model.pkl")              # Logistic Regression model
vectorizer = joblib.load("vectorizer.pkl")    # TF-IDF vectorizer

app = FastAPI(
    title="Phishing Email Detector API",
    description="Serves a Logistic Regression phishing classifier trained in Colab.",
    version="1.0.0",
)

# Allow your dashboard to call this API from another origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # you can restrict later to your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class EmailRequest(BaseModel):
    email: str


class PredictionResponse(BaseModel):
    prediction: int           # 0 = safe, 1 = phishing
    label: str
    safe_prob: float
    phishing_prob: float


@app.get("/")
def root():
    return {
        "message": "Phishing detector API is running.",
        "docs": "/docs",
    }


@app.post("/predict", response_model=PredictionResponse)
def predict_email(payload: EmailRequest):
    text = payload.email.strip()
    if not text:
        # simple guard
        return PredictionResponse(
            prediction=0,
            label="safe",
            safe_prob=100.0,
            phishing_prob=0.0,
        )

    # Vectorize
    X = vectorizer.transform([text])

    # Predict label and probabilities
    pred = int(model.predict(X)[0])
    probs = model.predict_proba(X)[0]   # [safe_prob, phishing_prob]

    safe_prob = float(np.round(probs[0] * 100, 2))
    phishing_prob = float(np.round(probs[1] * 100, 2))

    label = "phishing" if pred == 1 else "safe"

    return PredictionResponse(
        prediction=pred,
        label=label,
        safe_prob=safe_prob,
        phishing_prob=phishing_prob,
    )
