from scam_analyzer import analyze_message


test_messages = [

    # =========================
    # NORMAL MESSAGES
    # =========================

    "Hey, are you coming to college tomorrow?",

    "Can you send me the notes from today's lecture?",

    "Mom, I'll be home by 8 pm.",

    "Your assignment submission is tomorrow at 11:59 PM.",

    "Please verify your attendance before Friday.",


    # =========================
    # OBVIOUS SCAMS
    # =========================

    "Congratulations! You have won a free iPhone. Claim your prize now!",

    "URGENT! Your bank account will be blocked. Verify immediately.",

    "Your OTP is 458921. Do not share this OTP with anyone.",

    "Your KYC has expired. Update your details immediately.",

    "You have won ₹50,000. Click http://claim-prize.com to collect your reward.",

    "Your account has been suspended. Click https://verify-account.com now.",

    "Congratulations! You are selected for a free cash reward.",

    "Your refund is waiting. Enter your bank details to receive it.",

    "Work from home and earn ₹50,000 per week. Send your details now.",

    "Your credit card will be blocked unless you verify your information.",


    # =========================
    # TRICKY / AMBIGUOUS
    # =========================

    "Please verify your account details in the college portal.",

    "Your payment for the college fees was successful.",

    "Please update your password before the account expires.",

    "Your bank statement is available in the official banking app.",

    "Please check your email for the verification code."
]


print("=" * 70)
print("SCAMSHIELD TEST SET")
print("=" * 70)


for number, message in enumerate(test_messages, start=1):

    spam_probability, indicators, risk_score, risk_level = analyze_message(message)

    print(f"\nTest {number}")
    print("-" * 70)

    print("Message:")
    print(message)

    print(f"\nML spam probability: {spam_probability:.2%}")

    print("Risk indicators:")

    if indicators:
        for category, matches in indicators.items():
            print(f"  {category}: {matches}")
    else:
        print("  None")

    print(f"\nRisk score: {risk_score:.1f}/100")
    print(f"Risk level: {risk_level}")