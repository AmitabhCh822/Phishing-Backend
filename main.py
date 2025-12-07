from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import joblib
import numpy as np
import functools

# ----------------------------------------------------
# LOAD MODEL + VECTORIZER BEFORE CACHE WRAPPER
# ----------------------------------------------------
model = joblib.load("model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

@functools.lru_cache(maxsize=1)
def get_model():
    return model, vectorizer

# ----------------------------------------------------
# CLEANED + OPTIMIZED KEYWORD SETS
# ----------------------------------------------------
# (Converted to sets → O(1) lookup speed)

HIGH_RISK = set([
    "verify your password","reset your password immediately","reset your password now",
    "password expired","password reset required","your password will expire",
    "confirm your username","login immediately","log in immediately","login now","log in now",
    "confirm your identity","confirm your login","security breach detected",
    "your account has been compromised","your account has been suspended","your account will be closed",
    "your access will be revoked","update your credentials","verify your credentials",
    "unusual activity detected","unauthorized login attempt","multiple failed login attempts",
    "mfa deactivated","mfa reset required","two-factor disabled","2fa disabled","two factor disabled",
    "single-use verification code","one-time login link","single use login","l0gin","log-in now",
    "verify immediately","verifу immеdiately","pаsswоrd",

    # financial fraud
    "bank account","routing number","sort code","account number","direct wire transfer",
    "wire transfer request","urgent payment required","make a payment now","outstanding balance",
    "invoice overdue","immediate invoice payment","your payment failed","billing failure",
    "refund waiting","your refund is ready","tax refund available","irs payment request",
    "update billing information","credit card required","update your credit card",
    "payment authorization needed","payment dispute","your account will be charged",
    "fraudulent transaction detected","paymеnt","trаnsfer","refυnd",

    # ceo fraud
    "are you available right now","i need you to do something urgently","i need a quick favor",
    "don’t share this with anyone","can you purchase gift cards","keep this confidential",
    "urgent company request","i need you to handle this privately","send me your phone number immediately",
    "reply only to this email",

    # malware threats
    "open the attached file","download the attachment","run the attachment","execute the attached program",
    "macro enabled document","enable macros","enable content to view","encrypted attachment",
    "password for attached file","download invoice.zip","extract and run","docx.exe","pdf.exe",

    # shipping scams
    "package held","package detained","customs fee required","delivery attempt failed",
    "shipping address incorrect","dhl urgent notice","fedex urgent notice","ups urgent notice",
    "reschedule delivery now",

    # gov scams
    "irs notice","federal tax violation","court appearance required","outstanding legal complaint",
    "social security administration alert","ssa suspension warning","your benefits will stop",
    "homeland security alert",

    # hr/payroll
    "update your payroll info","your paycheck is on hold","direct deposit failure","w2 verification required",
    "update hr records","employment suspension notice","benefits termination warning",

    # university scams
    "your university account will be disabled","your student portal password expired",
    "financial aid suspension","bursar refund issue","student account verification",
    "registrar hold notice","canvas login failure","blackboard login failure",

    # crypto scams
    "send crypto","send bitcoin","urgent usdt transfer","crypto refund",
    "recover your lost crypto","binance account suspended","coinbase verification required",

    # predatory journal
    "rapid publication","publish your research quickly","processing charge required",
    "indexing guaranteed","journal of advanced machine learning research","global open access journal",
    "submit your manuscript within 48 hours","editorial board invitation fee",
    "your previous work was recognized","we noticed your recent publication",
    "we invite you to join as editor","publication guaranteed","fast-track acceptance",
    "submit your abstract today","reviewer invitation with honorarium","pubⅼicatіon","manuscrіpt",
    "rеsеarch",

    # pressure
    "immediate action required","final warning","last notice","failure to act will result",
    "you will lose access","your service will be terminated","deadline within 24 hours",
    "respond within 2 hours","act now to avoid suspension",

    # it internal
    "vpn access expired","vpn password reset","vpn credentials","your email has been deactivated",
    "your email will be disabled","reset your single sign on","sso reset required",
    "company portal login failed","company portal access issue","your mailbox settings were changed",

    # hr repeats
    "payroll account is locked","salary update required","benefits have been suspended",
    "hr has flagged your account","direct deposit issue","update your payroll information immediately",

    # cloud platform
    "aws account suspended","aws root access alert","azure sign in alert","gcp project suspension",
    "billing account suspended","your api key has been exposed","rotate your access key",

    # messaging apps
    "contact me on telegram immediately","whatsapp me urgently","send your info via whatsapp",
    "continue the conversation on telegram","urgent teams message",

    # utility scams
    "your electricity will be disconnected","utility bill overdue","water service interruption",
    "your phone service will be suspended","internet service termination notice",

    # subscriptions
    "your subscription will auto-renew for","unexpected charge","your payment method was rejected",
    "failed payment for your subscription",

    # university parking (high urgency)
    "sign in now","urgent renewal","your spot will be reassigned"
])


# ----------------------------------------------------
# MEDIUM RISK — CLEANED + SET
# ----------------------------------------------------
MEDIUM_RISK = set([
    "verify your account","verify your email","update your information","update your profile",
    "review your account","confirm your account","your account requires attention",
    "account review required","your account has pending issues","your profile needs updating",
    "we noticed an issue with your account","your information appears outdated",
    "your account requires manual review","sign in to review","log into your portal",
    "login to your dashboard","temporary access issue","acc0unt verification",

    # university admin + parking
    "renew your pass","renew your parking permit","parking permit renewal",
    "parking pass renewal","sign in to renew","your permit is pending",
    "your parking is pending","your spot may be reassigned","renew asap",
    "update your parking information","high volume of incoming students",

    # hr
    "review your payroll information","benefits update required",
    "employment verification request","please update hr records",

    # soft personal info requests
    "please send your phone number","share your updated contact information",
    "send updated documentation","your confirmation will help us proceed",

    # financial mild
    "payment confirmation required","review your billing information",
    "update payment preferences","confirm subscription renewal",

    # IT soft warnings
    "it support team","manual account verification required",
    "security settings require review","unexpected logout",
    "system upgrade notification",

    # shipping mild
    "delivery confirmation requested","address verification needed",

    # billing mild
    "billing statement available","account update required for your service provider",

    # subscription / billing
    "renew your subscription","verify your billing details",

    # medium risk Unicode
    "confіrm your details","revіew your account","updаte your information"
])

# ----------------------------------------------------
# LOW RISK — unchanged (but now a set)
# ----------------------------------------------------
LOW_RISK = set([
    "please let me know","just checking in","following up","as discussed","as requested",
    "attached for review","thank you for your time","looking forward to hearing from you",
    "gentle reminder","please confirm receipt",

    "meeting agenda","calendar invite","schedule a call","zoom link","teams link",

    "share the file","send the document","review the draft","provide feedback",
    "upload your assignment","submit your report",

    "hope you're doing well","good morning","thank you","best regards",
    
    "routine maintenance","scheduled maintenance","system update completed",

    "your receipt is ready","your subscription has renewed","your plan has been updated",
    "your order has shipped","tracking information available",

    "class reminder","course update","assignment posted","office hours update",

    "newsletter update","product update","promo offer",

    "your package is on the way","standard shipping","order confirmation",

    "click here for more details","view this online","read more",

    "this is an automated message","do not reply to this email",
])

# ----------------------------------------------------
# Predatory Journals
# ----------------------------------------------------
PREDATORY_JOURNAL_TERMS = set([
    "submit your manuscript","submit manuscript","submit your paper",
    "send your manuscript","call for papers","call for submissions",
    "special issue invitation","editorial board invitation",
    "join our editorial board","rapid peer review","fast-track acceptance",
    "publication guaranteed","processing charge","article processing charge"
])


# ----------------------------------------------------
# Sensitive + Action Terms
# ----------------------------------------------------
SENSITIVE_TERMS = set([
    "bank account","account number","routing number","credit card","cvv",
    "passport","passport number","ssn","social security","id card","driver's license",
    "password","verification code","otp","login","username","seed phrase",
    "private key","wallet address"
])

ACTION_TERMS = set([
    "send","send me","send your","provide","upload","reply with","share",
    "submit","fill out","enter your details","enter your information",
    "scan and send","attach","transfer the funds","submit payment details"
])


# ----------------------------------------------------
# RULE ENGINE
# ----------------------------------------------------
def rule_based_flags(t: str) -> bool:
    return any(term in t for term in SENSITIVE_TERMS) and any(term in t for term in ACTION_TERMS)


# ----------------------------------------------------
# MANUAL SCORE
# ----------------------------------------------------
def compute_manual_score(t: str) -> int:
    score = 0
    for w in HIGH_RISK:
        if w in t: score += 3
    for w in MEDIUM_RISK:
        if w in t: score += 2
    for w in LOW_RISK:
        if w in t: score += 1
    for w in PREDATORY_JOURNAL_TERMS:
        if w in t: score += 2
    return score


# ----------------------------------------------------
# FASTAPI APP
# ----------------------------------------------------
app = FastAPI(
    title="Phishing Email Detector API",
    description="Hybrid ML + rule-based phishing detector",
    version="4.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class EmailRequest(BaseModel):
    email: str


class PredictionResponse(BaseModel):
    prediction: int
    label: str
    safe_prob: float
    phishing_prob: float


# ----------------------------------------------------
# PREDICTION ENDPOINT
# ----------------------------------------------------
@app.post("/predict", response_model=PredictionResponse)
def predict_email(payload: EmailRequest):

    model, vectorizer = get_model()

    text = payload.email.strip()
    t = text.lower()

    if not text:
        return PredictionResponse(
            prediction=0, label="safe",
            safe_prob=100.0, phishing_prob=0.0
        )

    # ML prediction
    X = vectorizer.transform([text])
    probs = model.predict_proba(X)[0]

    safe_prob = float(probs[0] * 100)
    phishing_prob = float(probs[1] * 100)

    # Predatory journals → suspicious
    if any(term in t for term in PREDATORY_JOURNAL_TERMS):
        phishing_prob = max(phishing_prob, 55.0)
        safe_prob = 45.0

    # manual score
    manual_score = compute_manual_score(t)

    # Hard override (sensitive + action)
    if rule_based_flags(t):
        return PredictionResponse(
            prediction=1, label="phishing",
            safe_prob=5.0, phishing_prob=95.0
        )

    # mailbox quota mild suspicious
    quota_terms = [
        "mailbox storage is almost full","your mailbox is almost full",
        "mailbox storage full","increase your quota","quota limit"
    ]
    if any(term in t for term in quota_terms):
        phishing_prob = max(phishing_prob, 60.0)
        safe_prob = 40.0

    # scoring thresholds
    if manual_score >= 9:
        phishing_prob = max(phishing_prob, 85.0)
        safe_prob = 15.0

    elif 5 <= manual_score <= 8:
        phishing_prob = max(phishing_prob, 60.0)
        safe_prob = 40.0

    elif 3 <= manual_score <= 4:
        phishing_prob = max(phishing_prob, 45.0)
        safe_prob = 55.0

    # Final labels
    if phishing_prob >= 80:
        return PredictionResponse(
            prediction=1, label="phishing",
            safe_prob=safe_prob, phishing_prob=phishing_prob
        )

    if 40 <= phishing_prob < 80:
        return PredictionResponse(
            prediction=-1, label="suspicious",
            safe_prob=safe_prob, phishing_prob=phishing_prob
        )

    return PredictionResponse(
        prediction=0, label="safe",
        safe_prob=safe_prob, phishing_prob=phishing_prob
    )
