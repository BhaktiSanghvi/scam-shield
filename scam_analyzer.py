import pandas as pd
import re

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression


# ==========================================
# 1. LOAD DATA
# ==========================================

file_path = "data/sms+spam+collection/SMSSpamCollection"

data = pd.read_csv(
    file_path,
    sep="\t",
    header=None,
    names=["label", "message"],
    encoding="utf-8"
)


# ==========================================
# 2. SPLIT DATA
# ==========================================

X = data["message"]
y = data["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


# ==========================================
# 3. TF-IDF
# ==========================================

vectorizer = TfidfVectorizer()

X_train_tfidf = vectorizer.fit_transform(X_train)


# ==========================================
# 4. TRAIN MODEL
# ==========================================

model = LogisticRegression(max_iter=1000)

model.fit(X_train_tfidf, y_train)


# ==========================================
# 5. RISK PATTERNS
# ==========================================

RISK_PATTERNS = {

    "urgency": [
        "urgent",
        "immediately",
        "act now",
        "right now",
        "as soon as possible",
        "expires today",
        "now"
    ],

    "financial": [
        "bank",
        "account",
        "payment",
        "money",
        "refund",
        "transfer",
        "credit card"
    ],

    "security": [
        "verify",
        "verification",
        "otp",
        "password",
        "pin",
        "kyc"
    ],

    "threat": [
        "blocked",
        "suspended",
        "locked",
        "terminated",
        "will be closed",
        "will be blocked"
    ],

    "reward": [
        "winner",
        "won",
        "prize",
        "free",
        "reward",
        "congratulations"
    ]
}


# ==========================================
# 6. LEGITIMATE CONTEXT
# ==========================================

LEGITIMATE_CONTEXTS = [

    "college portal",
    "college fees",
    "college fee",
    "attendance",
    "assignment",
    "lecture",
    "official banking app",
    "bank statement",
    "official app"
]


# ==========================================
# 7. DETECT RISK INDICATORS
# ==========================================

def detect_risk_indicators(message):

    message_lower = message.lower()

    detected = {}

    # --------------------------------------
    # Basic risk categories
    # --------------------------------------

    for category, keywords in RISK_PATTERNS.items():

        matches = []

        for keyword in keywords:

            pattern = r"\b" + re.escape(keyword) + r"\b"

            if re.search(pattern, message_lower):
                matches.append(keyword)

        if matches:
            detected[category] = matches


    # --------------------------------------
    # URLs
    # --------------------------------------

    urls = re.findall(
        r"https?://[^\s]+",
        message_lower
    )

    if urls:
        detected["suspicious_link"] = urls


    # --------------------------------------
    # Money amounts
    # --------------------------------------

    money_patterns = re.findall(
        r"(?:₹|\$|€|£)\s?\d+(?:[,.]\d+)*",
        message_lower
    )

    if money_patterns:
        detected["money_amount"] = money_patterns


    # --------------------------------------
    # Financial information requests
    # --------------------------------------

    financial_detail_phrases = [
        "bank details",
        "card details",
        "account details",
        "bank information",
        "personal details",
        "payment details"
    ]

    financial_matches = []

    for phrase in financial_detail_phrases:

        if phrase in message_lower:
            financial_matches.append(phrase)

    if financial_matches:
        detected["financial_request"] = financial_matches


    # --------------------------------------
    # Job scam patterns
    # --------------------------------------

    job_scam_phrases = [
        "work from home",
        "earn ₹",
        "earn $",
        "earn money",
        "easy money",
        "guaranteed income",
        "weekly income",
        "send your details"
    ]

    job_matches = []

    for phrase in job_scam_phrases:

        if phrase in message_lower:
            job_matches.append(phrase)

    if job_matches:
        detected["job_scam"] = job_matches


    return detected


# ==========================================
# 8. ANALYZE MESSAGE
# ==========================================

def analyze_message(message):

    message_lower = message.lower()

    # --------------------------------------
    # ML probability
    # --------------------------------------

    message_tfidf = vectorizer.transform([message])

    probabilities = model.predict_proba(message_tfidf)[0]

    spam_index = list(model.classes_).index("spam")

    spam_probability = probabilities[spam_index]


    # --------------------------------------
    # Rule indicators
    # --------------------------------------

    indicators = detect_risk_indicators(message)


    # --------------------------------------
    # Starting ML score
    # --------------------------------------

    risk_score = spam_probability * 50


    # --------------------------------------
    # Category weights
    # --------------------------------------

    category_weights = {

        "urgency": 8,
        "financial": 10,
        "security": 10,
        "threat": 12,
        "reward": 12,
        "suspicious_link": 18,
        "money_amount": 5,
        "financial_request": 18,
        "job_scam": 15
    }


    # --------------------------------------
    # Add category scores
    # --------------------------------------

    for category in indicators:

        risk_score += category_weights.get(
            category,
            0
        )


    # ======================================
    # CONTEXTUAL RULES
    # ======================================

    # Legitimate context reduces the impact
    # of generic indicators.

    legitimate_context_found = any(
        context in message_lower
        for context in LEGITIMATE_CONTEXTS
    )


    # --------------------------------------
    # Account + verification
    # --------------------------------------

    if (
        "financial" in indicators
        and "security" in indicators
    ):

        risk_score += 10


    # --------------------------------------
    # Threat + verification
    # --------------------------------------

    if (
        "threat" in indicators
        and "security" in indicators
    ):

        risk_score += 15


    # --------------------------------------
    # Reward combination
    # --------------------------------------

    if "reward" in indicators:

        if len(indicators["reward"]) >= 2:

            risk_score += 15


    # --------------------------------------
    # KYC + urgency
    # --------------------------------------

    if (
        "kyc" in message_lower
        and "urgency" in indicators
    ):

        risk_score += 15


    # --------------------------------------
    # OTP / PIN / password + urgency
    # --------------------------------------

    if (
        any(
            word in message_lower
            for word in [
                "otp",
                "pin",
                "password"
            ]
        )
        and "urgency" in indicators
    ):

        risk_score += 15


    # --------------------------------------
    # Financial information request
    # --------------------------------------

    if "financial_request" in indicators:

        risk_score += 15


    # --------------------------------------
    # Job scam + money
    # --------------------------------------

    if (
        "job_scam" in indicators
        and "money_amount" in indicators
    ):

        risk_score += 20


    # --------------------------------------
    # Reward + link
    # --------------------------------------

    if (
        "reward" in indicators
        and "suspicious_link" in indicators
    ):

        risk_score += 15


    # ======================================
    # LEGITIMATE CONTEXT ADJUSTMENT
    # ======================================

    if legitimate_context_found:

        # Generic verification/account/payment
        # language should not automatically
        # become HIGH risk.

        if (
            "threat" not in indicators
            and "suspicious_link" not in indicators
            and "reward" not in indicators
            and "job_scam" not in indicators
        ):

            risk_score -= 20


    # ======================================
    # KEEP SCORE IN RANGE
    # ======================================

    risk_score = max(
        0,
        min(risk_score, 100)
    )


    # ======================================
    # RISK LEVEL
    # ======================================

    if risk_score >= 70:

        risk_level = "HIGH"

    elif risk_score >= 40:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"


    return (
        spam_probability,
        indicators,
        risk_score,
        risk_level
    )


# ==========================================
# 9. DIRECT TEST
# ==========================================

if __name__ == "__main__":

    test_messages = [

        "Congratulations! You have won a free prize. Click the link now!",

        "Hey, are you coming to college tomorrow?",

        "URGENT! Your bank account will be blocked. Verify your account immediately.",

        "Can you send me the notes from today's lecture?"
    ]


    for message in test_messages:

        (
            spam_probability,
            indicators,
            risk_score,
            risk_level
        ) = analyze_message(message)


        print("\n" + "=" * 60)

        print("Message:")
        print(message)

        print("\nML spam probability:")
        print(f"{spam_probability:.2%}")

        print("\nRisk indicators:")

        if indicators:

            for category, matches in indicators.items():

                print(f"  {category}: {matches}")

        else:

            print("  None")

        print("\nFinal Risk Score:")
        print(f"{risk_score:.1f}/100")

        print("Risk Level:")
        print(risk_level)