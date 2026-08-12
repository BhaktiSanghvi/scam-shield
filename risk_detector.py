import re

# Words and patterns that may indicate scam behavior

RISK_PATTERNS = {
    "urgency": [
        "urgent",
        "immediately",
        "act now",
        "right now",
        "as soon as possible",
        "expires today"
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
        "will be closed"
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


def detect_risk_indicators(message):
    message_lower = message.lower()

    detected = {}

    for category, keywords in RISK_PATTERNS.items():
        matches = []

        for keyword in keywords:
            pattern = r"\b" + re.escape(keyword) + r"\b"

            if re.search(pattern, message_lower):
                matches.append(keyword)

        if matches:
            detected[category] = matches

    # Detect URLs
    urls = re.findall(r"https?://\S+", message_lower)

    if urls:
        detected["suspicious_link"] = urls

    return detected


# Test messages

messages = [
    "Congratulations! You have won a free prize. Click the link now!",
    "Hey, are you coming to college tomorrow?",
    "URGENT! Your bank account will be blocked. Verify your account immediately.",
    "Can you send me the notes from today's lecture?"
]


for message in messages:
    print("\nMessage:", message)

    indicators = detect_risk_indicators(message)

    if indicators:
        print("Risk indicators detected:")

        for category, matches in indicators.items():
            print(f"  {category}: {matches}")

    else:
        print("No obvious risk indicators detected.")