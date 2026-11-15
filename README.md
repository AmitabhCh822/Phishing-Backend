# PhishGuard Backend

FastAPI service that classifies an email as safe, suspicious or phishing. It combines a Logistic Regression model on TF-IDF features with a rule-based risk score.

**Live service on Google Cloud Run:** https://phishguard-api-374161060156.us-central1.run.app/docs

The first request after an idle period takes a few seconds while the container starts.

## Paper

A. Chakravorty, M. Price, N. Elsayed and Z. ElSayed, "Context-Aware Phishing Email Detection Using Machine Learning and NLP." [arXiv:2603.27326](https://arxiv.org/abs/2603.27326)

The model was trained on 53,973 labeled emails and reaches 95.41% accuracy.

## Try it

```bash
curl -s -X POST "https://phishguard-api-374161060156.us-central1.run.app/predict" \
  -H "Content-Type: application/json" \
  -d '{"email":"Your account has been suspended. Click the link to verify your password immediately."}'
```

Response:

```json
{"prediction":1,"label":"phishing","safe_prob":10.48,"phishing_prob":89.52}
```

| Field | Meaning |
|---|---|
| `prediction` | 1 phishing, -1 suspicious, 0 safe |
| `label` | phishing, suspicious or safe |
| `safe_prob`, `phishing_prob` | percentages that sum to 100 |

## Run locally

```bash
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8080
```

## Deploy to Cloud Run

```bash
gcloud run deploy phishguard-api --source . --region us-central1 --allow-unauthenticated --max-instances 1
```

## Files

- `main.py`: API, rule lists and the `/predict` endpoint
- `model.pkl`, `vectorizer.pkl`: trained model and TF-IDF vectorizer
- `Dockerfile`: container build for Cloud Run
