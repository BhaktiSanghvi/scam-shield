import streamlit as st
import joblib
import re


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="SCAMSHIELD",
    page_icon="🛡️",
    layout="centered"
)


# ============================================================
# CUSTOM STYLING
# ============================================================

st.markdown(
    """
    <style>

    .main-title {
        text-align: center;
        font-size: 48px;
        font-weight: 800;
        margin-bottom: 0px;
    }

    .subtitle {
        text-align: center;
        font-size: 20px;
        color: #9ca3af;
        margin-top: 5px;
    }

    .description {
        text-align: center;
        color: #cbd5e1;
        font-size: 16px;
        margin-bottom: 25px;
    }

    .section-title {
        font-size: 24px;
        font-weight: 700;
        margin-top: 20px;
    }

    .indicator {
        padding: 8px 12px;
        margin: 5px 0px;
        border-radius: 8px;
        background-color: #20242d;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# LOAD SAVED MODEL
# ============================================================

model = joblib.load("model.pkl")
vectorizer = joblib.load("vectorizer.pkl")


# ============================================================
# RISK PATTERNS
# ============================================================

RISK_PATTERNS = {

    "Urgency": [
        "urgent",
        "immediately",
        "act now",
        "right now",
        "as soon as possible",
        "expires today",
        "now"
    ],

    "Financial": [
        "bank",
        "account",
        "payment",
        "money",
        "refund",
        "transfer",
        "credit card"
    ],

    "Security": [
        "verify",
        "verification",
        "otp",
        "password",
        "pin",
        "kyc"
    ],

    "Threat": [
        "blocked",
        "suspended",
        "locked",
        "terminated",
        "will be closed",
        "will be blocked"
    ],

    "Reward": [
        "winner",
        "won",
        "win",
        "prize",
        "free",
        "reward",
        "congratulations",
        "lottery",
        "jackpot",
        "cash prize",
        "cash reward",
        "selected",
        "lucky"
    ]
}


# ============================================================
# DETECT RISK INDICATORS
# ============================================================

def detect_risk_indicators(message):

    message_lower = message.lower()

    detected = {}

    # --------------------------------------------------------
    # Keyword indicators
    # --------------------------------------------------------

    for category, keywords in RISK_PATTERNS.items():

        matches = []

        for keyword in keywords:

            pattern = r"\b" + re.escape(keyword) + r"\b"

            if re.search(pattern, message_lower):
                matches.append(keyword)

        if matches:
            detected[category] = matches

    # --------------------------------------------------------
    # Detect URLs
    # --------------------------------------------------------

    urls = re.findall(
        r"https?://[^\s]+",
        message_lower
    )

    if urls:
        detected["Suspicious Link"] = urls

    # --------------------------------------------------------
    # Detect money amounts
    # --------------------------------------------------------

    money_patterns = re.findall(
        r"(?:₹|\$|€|£)\s?\d+(?:[,.]\d+)*",
        message_lower
    )

    if money_patterns:
        detected["Money Amount"] = money_patterns

    # --------------------------------------------------------
    # Financial information requests
    # --------------------------------------------------------

    financial_phrases = [
        "bank details",
        "card details",
        "account details",
        "bank information",
        "personal details",
        "payment details"
    ]

    financial_matches = []

    for phrase in financial_phrases:

        if phrase in message_lower:
            financial_matches.append(phrase)

    if financial_matches:
        detected["Financial Request"] = financial_matches

    # --------------------------------------------------------
    # Job scam patterns
    # --------------------------------------------------------

    job_phrases = [
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

    for phrase in job_phrases:

        if phrase in message_lower:
            job_matches.append(phrase)

    if job_matches:
        detected["Job Scam"] = job_matches

    return detected


# ============================================================
# ANALYZE MESSAGE
# ============================================================

def analyze_message(message):

    # --------------------------------------------------------
    # Machine Learning prediction
    # --------------------------------------------------------

    message_tfidf = vectorizer.transform([message])

    probabilities = model.predict_proba(message_tfidf)[0]

    spam_index = list(model.classes_).index("spam")

    spam_probability = probabilities[spam_index]

    # --------------------------------------------------------
    # Rule-based indicators
    # --------------------------------------------------------

    indicators = detect_risk_indicators(message)

    message_lower = message.lower()

    # --------------------------------------------------------
    # Base score from ML
    # --------------------------------------------------------

    risk_score = spam_probability * 50

    # --------------------------------------------------------
    # Category weights
    # --------------------------------------------------------

    weights = {

        "Urgency": 8,

        "Financial": 10,

        "Security": 10,

        "Threat": 12,

        "Reward": 12,

        "Suspicious Link": 18,

        "Money Amount": 5,

        "Financial Request": 18,

        "Job Scam": 15
    }

    # --------------------------------------------------------
    # Add indicator scores
    # --------------------------------------------------------

    for category in indicators:

        risk_score += weights.get(
            category,
            0
        )

    # ========================================================
    # STRONG COMBINATIONS
    # ========================================================

    # Threat + security
    if (
        "Threat" in indicators
        and "Security" in indicators
    ):

        risk_score += 15

    # Financial + security
    if (
        "Financial" in indicators
        and "Security" in indicators
    ):

        risk_score += 10

    # Multiple reward signals
    if (
        "Reward" in indicators
        and len(indicators["Reward"]) >= 2
    ):

        risk_score += 15

    # Reward + money
    if (
        "Reward" in indicators
        and "Money Amount" in indicators
    ):

        risk_score += 30

    # Lottery + money
    if (
        "lottery" in message_lower
        and "Money Amount" in indicators
    ):

        risk_score += 25

    # Reward + suspicious link
    if (
        "Reward" in indicators
        and "Suspicious Link" in indicators
    ):

        risk_score += 15

    # KYC + urgency
    if (
        "kyc" in message_lower
        and "Urgency" in indicators
    ):

        risk_score += 15

    # OTP / PIN / password + urgency
    if (
        any(
            word in message_lower
            for word in [
                "otp",
                "pin",
                "password"
            ]
        )
        and "Urgency" in indicators
    ):

        risk_score += 15

    # Financial information request
    if "Financial Request" in indicators:

        risk_score += 15

    # Job scam + money
    if (
        "Job Scam" in indicators
        and "Money Amount" in indicators
    ):

        risk_score += 20

    # ========================================================
    # LEGITIMATE CONTEXT
    # ========================================================

    legitimate_contexts = [

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

    legitimate_context = any(
        context in message_lower
        for context in legitimate_contexts
    )

    # Only reduce score when there are no strong scam signals
    if legitimate_context:

        if (
            "Threat" not in indicators
            and "Suspicious Link" not in indicators
            and "Reward" not in indicators
            and "Job Scam" not in indicators
        ):

            risk_score -= 20

    # ========================================================
    # ADDITIONAL STRONG REWARD DETECTION
    # ========================================================

    strong_reward_words = [

        "lottery",
        "jackpot",
        "winner",
        "won",
        "prize"
    ]

    reward_word_found = any(
        word in message_lower
        for word in strong_reward_words
    )

    # Reward + money
    if (
        reward_word_found
        and "Money Amount" in indicators
    ):

        risk_score += 20

    # Reward + link
    if (
        reward_word_found
        and "Suspicious Link" in indicators
    ):

        risk_score += 20

    # ========================================================
    # SPECIAL CASES
    # ========================================================

    # A message claiming someone won money is highly suspicious
    if (
        reward_word_found
        and "Money Amount" in indicators
    ):

        risk_score = max(
            risk_score,
            75
        )

    # A message combining urgency + bank + verification
    if (
        "Urgency" in indicators
        and "Financial" in indicators
        and "Security" in indicators
    ):

        risk_score = max(
            risk_score,
            75
        )

    # A message combining threat + bank + verification
    if (
        "Threat" in indicators
        and "Financial" in indicators
        and "Security" in indicators
    ):

        risk_score = max(
            risk_score,
            80
        )

    # ========================================================
    # KEEP SCORE BETWEEN 0 AND 100
    # ========================================================

    risk_score = max(
        0,
        min(risk_score, 100)
    )

    # ========================================================
    # RISK LEVEL
    # ========================================================

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


# ============================================================
# HEADER
# ============================================================

st.markdown(
    '<div class="main-title">🛡️ SCAMSHIELD</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">AI-Powered Scam Message Detector</div>',
    unsafe_allow_html=True
)

st.markdown(
    """
    <div class="description">
    Analyze suspicious messages using machine learning
    and rule-based scam detection.
    </div>
    """,
    unsafe_allow_html=True
)


# ============================================================
# HOW IT WORKS
# ============================================================

with st.expander("🧠 How does SCAMSHIELD work?"):

    st.write(
        """
        SCAMSHIELD uses a hybrid detection approach.

        **1. Machine Learning**

        The message is converted into numerical features using
        TF-IDF and analyzed by the trained spam classification model.

        **2. Risk Indicators**

        The system looks for common scam signals such as urgency,
        financial requests, security verification, threats,
        rewards and suspicious links.

        **3. Risk Scoring**

        The ML prediction and detected indicators are combined
        into a final risk score from 0 to 100.

        **4. Risk Level**

        The final score is classified as LOW, MEDIUM or HIGH risk.
        """
    )


# ============================================================
# MESSAGE INPUT
# ============================================================

st.markdown(
    '<div class="section-title">📩 Analyze a Message</div>',
    unsafe_allow_html=True
)

message = st.text_area(
    "Paste a suspicious message below:",
    height=180,
    placeholder=(
        "Example: Your bank account will be blocked. "
        "Verify immediately..."
    )
)


# ============================================================
# EXAMPLE MESSAGES
# ============================================================

st.caption("💡 Try an example:")

example_col1, example_col2, example_col3 = st.columns(3)

with example_col1:

    st.code(
        "Hey, are you coming to college tomorrow?",
        language=None
    )

with example_col2:

    st.code(
        "Congratulations! You won a free prize!",
        language=None
    )

with example_col3:

    st.code(
        "URGENT! Verify your bank account immediately.",
        language=None
    )


# ============================================================
# ANALYZE BUTTON
# ============================================================

if st.button(
    "🔍 ANALYZE MESSAGE",
    use_container_width=True
):

    if not message.strip():

        st.warning(
            "⚠️ Please enter a message first."
        )

    else:

        (
            spam_probability,
            indicators,
            risk_score,
            risk_level
        ) = analyze_message(message)

        st.divider()

        # ====================================================
        # RISK RESULT
        # ====================================================

        if risk_level == "HIGH":

            st.error(
                "🚨 HIGH RISK — Potential Scam"
            )

            recommendation = (
                "Do not click links, share OTPs, passwords "
                "or financial information. Verify the sender "
                "through an official source."
            )

        elif risk_level == "MEDIUM":

            st.warning(
                "⚠️ MEDIUM RISK — Be Careful"
            )

            recommendation = (
                "Be cautious. Avoid sharing sensitive "
                "information and independently verify the "
                "message before taking action."
            )

        else:

            st.success(
                "🟢 LOW RISK — No Strong Scam Signals"
            )

            recommendation = (
                "No strong scam signals were detected. "
                "Still remain cautious with unexpected messages."
            )

        # ====================================================
        # SCORE + ML PROBABILITY
        # ====================================================

        col1, col2 = st.columns(2)

        with col1:

            st.metric(
                "🛡️ SCAM RISK SCORE",
                f"{risk_score:.1f} / 100"
            )

        with col2:

            st.metric(
                "🤖 AI SPAM PROBABILITY",
                f"{spam_probability:.2%}"
            )

        st.progress(
            int(risk_score)
        )

        # ====================================================
        # RECOMMENDED ACTION
        # ====================================================

        st.subheader("🎯 Recommended Action")

        st.info(
            recommendation
        )

        # ====================================================
        # RISK INDICATORS
        # ====================================================

        st.subheader(
            "🔎 Detected Risk Indicators"
        )

        if indicators:

            for category, matches in indicators.items():

                st.markdown(
                    f"""
                    <div class="indicator">
                    ⚠️ <strong>{category}</strong>:
                    {", ".join(matches)}
                    </div>
                    """,
                    unsafe_allow_html=True
                )

        else:

            st.success(
                "No obvious risk indicators detected."
            )

        # ====================================================
        # EXPLANATION
        # ====================================================

        st.subheader(
            "🧠 Why was this message flagged?"
        )

        if indicators:

            st.write(
                "SCAMSHIELD detected the following signals:"
            )

            for category in indicators:

                st.write(
                    f"• **{category}** indicators were detected."
                )

            st.write(
                "These signals were combined with the "
                "machine learning prediction to calculate "
                "the final risk score."
            )

        else:

            st.write(
                "The message did not contain strong "
                "rule-based scam indicators, and the "
                "machine learning model assigned it a "
                "relatively low spam probability."
            )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "SCAMSHIELD combines machine learning and rule-based "
    "risk detection. It is a prototype and should not be "
    "used as the sole basis for financial or security decisions."
)
