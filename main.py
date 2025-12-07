from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import joblib
import numpy as np

HIGH_RISK = [
    # ===============================
    #  CREDENTIAL HARVESTING
    # ===============================
    "verify your password",
    "reset your password immediately",
    "reset your password now",
    "password expired",
    "password reset required",
    "your password will expire",
    "confirm your username",
    "login immediately",
    "log in immediately",
    "login now",
    "log in now",
    "confirm your identity",
    "confirm your login",
    "security breach detected",
    "your account has been compromised",
    "your account has been suspended",
    "your account will be closed",
    "your access will be revoked",
    "update your credentials",
    "verify your credentials",
    "unusual activity detected",
    "unauthorized login attempt",
    "multiple failed login attempts",
    "mfa deactivated",
    "mfa reset required",
    "two-factor disabled",
    "2fa disabled",
    "two factor disabled",
    "single-use verification code",
    "one-time login link",
    "single use login",

    # Obfuscated login variants
    "l0gin",
    "log-in now",
    "verify immediately",
    "verifу immеdiately",  # Cyrillic spoofing
    "pаsswоrd" ,            # Cyrillic a/o

    # ===============================
    # FINANCIAL / PAYMENT FRAUD
    # ===============================
    "bank account",
    "routing number",
    "sort code",
    "account number",
    "direct wire transfer",
    "wire transfer request",
    "urgent payment required",
    "make a payment now",
    "outstanding balance",
    "invoice overdue",
    "immediate invoice payment",
    "your payment failed",
    "billing failure",
    "refund waiting",
    "your refund is ready",
    "tax refund available",
    "irs payment request",
    "update billing information",
    "credit card required",
    "update your credit card",
    "payment authorization needed",
    "payment dispute",
    "your account will be charged",
    "fraudulent transaction detected",

    # Obfuscated money variants
    "paymеnt",  # Unicode
    "trаnsfer",
    "refυnd",

    # ===============================
    # SPEAR-PHISHING (CEO FRAUD)
    # ===============================
    "are you available right now",
    "i need you to do something urgently",
    "i need a quick favor",
    "don’t share this with anyone",
    "can you purchase gift cards",
    "keep this confidential",
    "urgent company request",
    "i need you to handle this privately",
    "send me your phone number immediately",
    "reply only to this email",

    # ===============================
    # MALWARE / ATTACHMENT THREATS
    # ===============================
    "open the attached file",
    "download the attachment",
    "run the attachment",
    "execute the attached program",
    "macro enabled document",
    "enable macros",
    "enable content to view",
    "encrypted attachment",
    "password for attached file",
    "download invoice.zip",
    "extract and run",
    "docx.exe",
    "pdf.exe",

    # ===============================
    # DELIVERY / SHIPPING SCAMS
    # ===============================
    "package held",
    "package detained",
    "customs fee required",
    "delivery attempt failed",
    "shipping address incorrect",
    "dhl urgent notice",
    "fedex urgent notice",
    "ups urgent notice",
    "reschedule delivery now",

    # ===============================
    # GOVERNMENT IMPOSTER SCAMS
    # ===============================
    "irs notice",
    "federal tax violation",
    "court appearance required",
    "outstanding legal complaint",
    "social security administration alert",
    "ssa suspension warning",
    "your benefits will stop",
    "homeland security alert",

    # ===============================
    # PAYROLL / HR FRAUD
    # ===============================
    "update your payroll info",
    "your paycheck is on hold",
    "direct deposit failure",
    "w2 verification required",
    "update hr records",
    "employment suspension notice",
    "benefits termination warning",

    # ===============================
    # UNIVERSITY / EDUCATION SCAMS
    # ===============================
    "your university account will be disabled",
    "your student portal password expired",
    "financial aid suspension",
    "bursar refund issue",
    "student account verification",
    "registrar hold notice",
    "canvas login failure",
    "blackboard login failure",

    # ===============================
    # CRYPTOCURRENCY SCAMS
    # ===============================
    "send crypto",
    "send bitcoin",
    "urgent usdt transfer",
    "crypto refund",
    "recover your lost crypto",
    "binance account suspended",
    "coinbase verification required",

    # ===============================
    # FAKE JOURNAL / PREDATORY PUBLISHING
    # ===============================
    "rapid publication",
    "publish your research quickly",
    "processing charge required",
    "indexing guaranteed",
    "journal of advanced machine learning research",
    "global open access journal",
    "submit your manuscript within 48 hours",
    "editorial board invitation fee",
    "your previous work was recognized",
    "we noticed your recent publication",
    "we invite you to join as editor",
    "gold oa model",
    "publication guaranteed",
    "fast-track acceptance",
    "submit your abstract today",
    "reviewer invitation with honorarium",

    # Unicode spoofing variants
    "pubⅼicatіon",   # L replaced with ⅼ etc.
    "manuscrіpt",
    "rеsеarch",

    # ===============================
    # SOCIAL ENGINEERING PRESSURE
    # ===============================
    "immediate action required",
    "final warning",
    "last notice",
    "failure to act will result",
    "you will lose access",
    "your service will be terminated",
    "deadline within 24 hours",
    "respond within 2 hours",
    "act now to avoid suspension",

    # ===============================
    # OBSCURE BUT HIGH-RISK SIGNALS
    # ===============================
    "update your security token",
    "your email storage is full",
    "quota exceeded",
    "mailbox upgrade required",
    "legacy system authentication failure",

    # Unicode homoglyph phishing
    "verifу",
    "confіrm",
    "lоgin",
    "аccount",    # Cyrillic 'a'
]

MEDIUM_RISK = [

    # =======================================
    # ACCOUNT / VERIFICATION (non-urgent phrasing)
    # =======================================
    "verify your account",
    "verify your profile",
    "verify your email",
    "update your information",
    "update your profile",
    "update your account",
    "review your account",
    "review your details",
    "confirm your details",
    "confirm your account",
    "validate your account",
    "validate your information",
    "your account requires attention",
    "account review required",
    "your account has pending issues",
    "your profile needs updating",

    # Light urgency (not high-risk but concerning)
    "please review at your earliest convenience",
    "we noticed an issue with your account",
    "we detected a small problem",
    "your information appears outdated",
    "we need you to confirm something",
    "please double-check your details",
    "your account requires manual review",
    "minor issue detected",

    # =======================================
    # LOGIN / ACCESS (non-panic phrasing)
    # =======================================
    "sign in to review",
    "log into your portal",
    "login to your dashboard",
    "access your account to continue",
    "update your login settings",
    "your login information may be incorrect",
    "temporary access issue",
    "small discrepancy in your account",
    "your access may be limited",
    "you may experience login delays",

    # Obfuscated but not fully malicious sounding
    "acc0unt verification",
    "pr0file update",

    # =======================================
    # UNIVERSITY-SPECIFIC GRAY AREA
    # =======================================
    "your student account needs review",
    "your university profile needs updating",
    "please review your registration details",
    "your course access may be affected",
    "form submission required",
    "university system update",
    "manually verify your student information",
    "your financial aid information needs confirmation",
    "academic update request",
    "student portal update",
    "manual confirmation requested",
    "your access may be temporarily limited",
    "review your bursar information",
    "review your enrollment details",
    "please confirm your student status",

    # =======================================
    # HR / EMPLOYMENT (not explicitly harmful)
    # =======================================
    "review your payroll information",
    "confirm your employment details",
    "please update hr records",
    "benefits update required",
    "review your timesheet",
    "incorrect hr information detected",
    "update your direct deposit details",
    "employment verification request",
    "please confirm employment data",

    # =======================================
    # SOFT REQUESTS FOR PERSONAL INFO
    # =======================================
    "can you share your updated contact information",
    "please send your phone number",
    "please confirm your availability",
    "share your updated mailing address",
    "provide a brief confirmation",
    "send updated documentation",
    "reply with your preferred contact information",

    # =======================================
    # JOURNAL / CONFERENCE (not predatory but sketchy)
    # =======================================
    "we invite you to submit your manuscript",
    "we noticed your recent publication",
    "call for manuscript submissions",
    "conference invites you to present",
    "editorial board membership invitation",
    "journal invites you to contribute",
    "seeking reviewers for upcoming issue",
    "opportunity to join reviewer panel",
    "we welcome your research submission",
    "your previous work caught our attention",
    "we are expanding our editorial team",
    "special issue invitation",
    "submit your abstract for consideration",
    "rapid review available",
    "expedited review request",

    # =======================================
    # PAYMENT / FINANCIAL (non-threatening)
    # =======================================
    "please review the attached invoice",
    "your invoice is ready",
    "payment confirmation required",
    "review your billing information",
    "billing update request",
    "incorrect billing details found",
    "update payment preferences",
    "small discrepancy in your payment info",
    "confirm subscription renewal",
    "membership renewal reminder",

    # =======================================
    # SHIPPING / DELIVERY (mild wording)
    # =======================================
    "your package may be delayed",
    "delivery confirmation requested",
    "please verify your shipping address",
    "your shipment information needs updating",
    "review your delivery preferences",
    "carrier requires address verification",

    # =======================================
    # IT SUPPORT (soft wording)
    # =======================================
    "your system profile was flagged",
    "it team requests confirmation",
    "manual validation needed",
    "your mailbox storage is nearing limit",
    "please review your security settings",
    "update recommended",
    "small issue detected in your system",
    "temporary configuration issue",
    "please check your security preferences",

    # =======================================
    # AMBIGUOUS BUSINESS LANGUAGE
    # =======================================
    "please review attached document",
    "kindly confirm receipt",
    "action may be required",
    "follow up requested",
    "your feedback is needed",
    "internal confirmation required",
    "team requires your acknowledgment",
    "update pending approval",
    "complete your profile update",
    "your consent is required",

    # =======================================
    # LIGHT SUSPICIOUS PHRASES
    # =======================================
    "click below to review",
    "follow the link to continue",
    "access details below",
    "see updated information here",
    "review information using the link",
    "form may require your attention",
    "update your preferences",
    "your confirmation will help us proceed",

    # =======================================
    # AI-GENERATED SCAMMY TONE (but subtle)
    # =======================================
    "we are reaching out regarding your account",
    "we have observed something unusual",
    "we kindly request your cooperation",
    "your prompt response will help us",
    "your confirmation is highly appreciated",
    "we regret to inform you of an issue",
    "for your convenience, use the link below",

    # =======================================
    # UNICODE / OBFUSCATED MEDIUM-RISK
    # =======================================
    "confіrm your details",  # Cyrillic i
    "revіew your account",
    "updаte your information",
    "verіfy your email",
    "actіon may be required",
]


LOW_RISK = [

    # =======================================
    # Generic professional communication
    # =======================================
    "please let me know",
    "just checking in",
    "following up",
    "as discussed",
    "as requested",
    "for your reference",
    "attached for review",
    "attached here",
    "attached below",
    "thank you for your time",
    "appreciate your help",
    "looking forward to hearing from you",
    "please advise",
    "at your convenience",
    "when you get a chance",
    "kind reminder",
    "gentle reminder",
    "just wanted to confirm",
    "please confirm receipt",
    "thanks in advance",

    # =======================================
    # Meeting & scheduling language
    # =======================================
    "meeting agenda",
    "calendar invite",
    "schedule a call",
    "book a meeting",
    "join the meeting",
    "meeting notes attached",
    "zoom link",
    "teams link",
    "google meet link",
    "availability",
    "when works for you",
    "reschedule request",
    "updated meeting time",

    # =======================================
    # Non-sensitive work or academic requests
    # =======================================
    "share the file",
    "send the document",
    "review the draft",
    "provide feedback",
    "submit the form",
    "upload your assignment",
    "submit your report",
    "finalize your edits",
    "revise the document",
    "update the slide deck",
    "please check the attached notes",
    "submit before the meeting",

    # =======================================
    # Harmless email/common expressions
    # =======================================
    "hope you're doing well",
    "hope you're having a great week",
    "good morning",
    "good afternoon",
    "good evening",
    "thank you",
    "best regards",
    "sincerely",
    "warm regards",
    "let me know if you need anything",
    "reaching out to see",
    "checking if you're available",

    # =======================================
    # Internal workflow language
    # =======================================
    "for internal use",
    "project update",
    "task completed",
    "status update",
    "review pending",
    "pending approval",
    "draft version",
    "revision required",
    "team update",
    "shared document",
    "shared folder",
    "internal notes",

    # =======================================
    # Collaboration language
    # =======================================
    "please collaborate",
    "team feedback requested",
    "add your comments",
    "review the shared file",
    "finalize the project",
    "working on the next steps",
    "please continue with your part",
    "action items attached",
    "work together on this",
    "project outline",

    # =======================================
    # IT / system non-threatening notices
    # =======================================
    "routine maintenance",
    "scheduled maintenance",
    "system update completed",
    "patch has been applied",
    "no action needed",
    "informational notice",
    "expected downtime",
    "service restored",
    "performance improvements",
    "general system update",

    # =======================================
    # harmless account notifications
    # =======================================
    "your receipt is ready",
    "your subscription has renewed",
    "your plan has been updated",
    "your order has shipped",
    "tracking information available",
    "package delivered",
    "download your purchase",
    "your invoice is available",
    "view your receipt",
    "download statement",
    "your subscription details",

    # =======================================
    # University low-risk communication
    # =======================================
    "class reminder",
    "course update",
    "assignment posted",
    "syllabus update",
    "office hours update",
    "course materials uploaded",
    "university announcement",
    "department update",
    "campus event",
    "registration opens soon",
    "academic reminder",
    "student resources available",

    # =======================================
    # Subscription or marketing (non-suspicious)
    # =======================================
    "newsletter update",
    "monthly roundup",
    "blog post",
    "new feature available",
    "product update",
    "your preferences have been saved",
    "promo offer",
    "limited-time discount",
    "your subscription settings",
    "follow us on social media",
    "check out our latest article",

    # =======================================
    # Delivery / shipping (non-urgent)
    # =======================================
    "your package is on the way",
    "standard shipping",
    "your item has shipped",
    "delivery scheduled",
    "tracking number",
    "order confirmation",
    "purchase confirmation",

    # =======================================
    # Terms harmless in 95% of emails
    # =======================================
    "click here for more details",
    "view this online",
    "read more",
    "see full details",
    "learn more",
    "check the link below",
    "see the attached file",
    "click below to continue",
    "view the attached document",

    # =======================================
    # Slightly automated / generic language
    # =======================================
    "this is an automated message",
    "do not reply to this email",
    "system notification",
    "automated confirmation",
    "this message was generated automatically",

    # =======================================
    # Obfuscated low-risk tokens (harmless)
    # =======================================
    "c1ick here for more info",
    "v1ew document",
    "rev1ew attached",
    "f0llow link below",
    "clіck here",  # Cyrillic i
    "lоg details attached",  # Cyrillic o
]

# ----------------------------------------------------
# Keyword Lists For Rule-Based Flags
# ----------------------------------------------------
SENSITIVE_TERMS = [

    # Financial & banking
    "bank account",
    "bank details",
    "account number",
    "routing number",
    "sort code",
    "iban",
    "swift code",
    "fund transfer",
    "direct deposit",
    "payment information",
    "billing information",
    "credit card",
    "debit card",
    "cvv",
    "card number",
    "checking account",
    "savings account",
    "financial information",

    # Government ID / personal identity
    "passport",
    "passport number",
    "ssn",
    "social security",
    "social security number",
    "national id",
    "identity number",
    "id card",
    "driver's license",
    "government id",
    "tax id",
    "itin",
    "nin",  # national insurance number

    # Authentication / login
    "password",
    "passcode",
    "one-time code",
    "verification code",
    "otp",
    "mfa code",
    "security code",
    "login",
    "log in",
    "username",
    "user id",
    "account credentials",
    "authentication token",
    "auth token",
    "reset code",

    # Crypto / digital finance
    "wallet address",
    "seed phrase",
    "private key",
    "crypto account",
    "binance login",
    "coinbase login",
    "metamask",

    # Benefits / government money
    "medicare number",
    "unemployment number",
    "tax refund",
    "irs id",
    "w2 information",
    "employment id",

    # Slightly obfuscated variants used in phishing
    "pаsswоrd",  # Cyrillic a/o
    "lоgin",     # Cyrillic o
    "сredentials", # Cyrillic c
    "sосial security", # Cyrillic o
]

ACTION_TERMS = [

    # Direct requests
    "send",
    "send me",
    "send us",
    "send your",
    "provide",
    "provide your",
    "provide me with",
    "upload",
    "upload your",
    "upload the document",
    "reply with",
    "reply back with",
    "share",
    "share your",
    "submit",
    "submit your",
    "submit the form",
    "fill out",
    "complete the form",
    "enter your details",
    "enter your information",
    "enter your credentials",
    "confirm your information",
    "verify your information",

    # Commands that show authority or pressure
    "forward to me",
    "send urgently",
    "update your",
    "update the information",
    "update immediately",
    "confirm immediately",

    # File & document related
    "attach",
    "attach your",
    "attach the file",
    "attach your id",
    "scan and send",
    "email me the document",
    "email back your information",

    # Payment or transaction related
    "make a payment",
    "transfer the funds",
    "send the payment",
    "submit payment details",
    "enter your billing details",

    # Slightly obfuscated variants
    "prоvide",    # Cyrillic o
    "shаre",      # Cyrillic a
    "uрload",     # Cyrillic р
    "reрly with",
]

# ----------------------------------------------------
# RULE: Sensitive-term + Action-term = ALWAYS PHISHING
# ----------------------------------------------------
def rule_based_flags(t: str) -> bool:
    return any(term in t for term in SENSITIVE_TERMS) and any(term in t for term in ACTION_TERMS)


# ----------------------------------------------------
# MODEL LOAD
# ----------------------------------------------------
model = joblib.load("model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

MODEL_CLASSES = list(model.classes_)

# Bulletproof class indexing
if isinstance(MODEL_CLASSES[0], str):
    SAFE_INDEX = MODEL_CLASSES.index("safe")
    PHISHING_INDEX = MODEL_CLASSES.index("phishing")
else:
    SAFE_INDEX = MODEL_CLASSES.index(0)
    PHISHING_INDEX = MODEL_CLASSES.index(1)


# ----------------------------------------------------
# FASTAPI CONFIG
# ----------------------------------------------------
app = FastAPI(
    title="Phishing Email Detector API",
    description="Hybrid ML + Rule-based phishing detector",
    version="3.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ----------------------------------------------------
# REQUEST / RESPONSE MODELS
# ----------------------------------------------------
class EmailRequest(BaseModel):
    email: str

class PredictionResponse(BaseModel):
    prediction: int
    label: str
    safe_prob: float
    phishing_prob: float


# ----------------------------------------------------
# MANUAL SCORING (weights: high=3, med=2, low=1)
# ----------------------------------------------------
def compute_manual_score(t: str) -> int:
    score = 0
    for w in HIGH_RISK:
        if w in t:
            score += 3
    for w in MEDIUM_RISK:
        if w in t:
            score += 2
    for w in LOW_RISK:
        if w in t:
            score += 1
    return score


# ----------------------------------------------------
# PATCHED /predict ENDPOINT (FINAL VERSION)
# ----------------------------------------------------
@app.post("/predict", response_model=PredictionResponse)
def predict_email(payload: EmailRequest):

    text = payload.email.strip()
    t = text.lower()

    if not text:
        return PredictionResponse(
            prediction=0,
            label="safe",
            safe_prob=100.0,
            phishing_prob=0.0
        )

    # =====================================================
    # 1) ML PREDICTION
    # =====================================================
    X = vectorizer.transform([text])
    probs = model.predict_proba(X)[0]

    ml_safe = float(probs[SAFE_INDEX] * 100)
    ml_phish = float(probs[PHISHING_INDEX] * 100)

    safe_prob = ml_safe
    phishing_prob = ml_phish

    # =====================================================
    # 2) MANUAL DICTIONARY SCORE
    # =====================================================
    manual_score = compute_manual_score(t)

    # =====================================================
    # 3) HARD OVERRIDE → Sensitive + Action = PHISHING
    # =====================================================
    if rule_based_flags(t):
        return PredictionResponse(
            prediction=1,
            label="phishing",
            safe_prob=5.0,
            phishing_prob=95.0
        )

    # =====================================================
    # 4) SPECIAL CASE: Mailbox / storage quota → ALWAYS suspicious
    # =====================================================
    mild_storage_terms = [
        "mailbox storage is almost full",
        "your mailbox is almost full",
        "mailbox storage full",
        "storage is almost full",
        "increase your quota",
        "quota limit",
        "quota warning"
    ]

    if any(term in t for term in mild_storage_terms):
        phishing_prob = min(phishing_prob, 60.0)
        safe_prob = 100 - phishing_prob

    # =====================================================
    # 5) EXTREME DICTIONARY RISK (new threshold = 9)
    # =====================================================
    if manual_score >= 9:
        phishing_prob = max(phishing_prob, 85.0)
        safe_prob = 100 - phishing_prob

    # =====================================================
    # 6) MODERATE RISK (new range = 5–8)
    # =====================================================
    elif 5 <= manual_score <= 8:
        phishing_prob = max(phishing_prob, 60.0)
        safe_prob = 40.0

    # =====================================================
    # 7) MILD RISK (new range = 3–4)
    # =====================================================
    elif 3 <= manual_score <= 4:
        phishing_prob = max(phishing_prob, 45.0)
        safe_prob = 55.0

    # =====================================================
    # 8) FINAL LABEL ASSIGNMENT
    # =====================================================
    # Phishing
    if phishing_prob >= 80:
        return PredictionResponse(
            prediction=1,
            label="phishing",
            safe_prob=round(safe_prob, 2),
            phishing_prob=round(phishing_prob, 2)
        )

    # Suspicious
    if 40 <= phishing_prob < 80:
        return PredictionResponse(
            prediction=-1,
            label="suspicious",
            safe_prob=round(safe_prob, 2),
            phishing_prob=round(phishing_prob, 2)
        )

    # Safe
    return PredictionResponse(
        prediction=0,
        label="safe",
        safe_prob=round(safe_prob, 2),
        phishing_prob=round(phishing_prob, 2)
    )

