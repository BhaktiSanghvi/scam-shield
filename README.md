# SCAMSHIELD 🛡️

### AI-Based Scam Message Detector

SCAMSHIELD is a project I built to detect suspicious or scam-like messages using machine learning.

The basic idea is simple: you paste a message into the app and it checks the message in two ways. First, an ML model estimates how likely the message is to be spam. Then, a rule-based system looks for things that are commonly seen in scams such as urgency, fake rewards, account threats, suspicious links or requests for financial information.

The two results are combined to give a risk score from 0 to 100.

---

## Why I built this

Scam messages are becoming more common and many of them use similar tricks.

For example, a message might say that your bank account will be blocked unless you verify something immediately or that you have won a prize and need to click a link.

I wanted to make a small project that could recognize some of these patterns and give a more useful result than simply saying "spam" or "not spam."

---

## What SCAMSHIELD does

The app can detect things like:

- Urgent or threatening language
- Bank and payment-related terms
- Requests to verify an account
- OTP, password and KYC related messages
- Fake prizes and rewards
- Suspicious URLs
- Money amounts
- Requests for bank or account details
- Possible work-from-home scams

It then combines these signals with the ML prediction and produces a risk score.

### Risk levels

| Score | Level |
|------:|-------|
| 0–39 | 🟢 LOW |
| 40–69 | 🟡 MEDIUM |
| 70–100 | 🔴 HIGH |

---

## Machine Learning part

For the ML side of the project, I used the **SMS Spam Collection dataset**.

The dataset contains **5,572 SMS messages**:

- 4,825 ham messages
- 747 spam messages

I split the data into training and testing sets using an 80/20 stratified split.

This gave me:

- 4,457 training messages
- 1,115 testing messages

### TF-IDF

Before training the model, the messages are converted into numerical features using **TF-IDF (Term Frequency–Inverse Document Frequency)**.

The training data resulted in a matrix with **7,668 features**.

### Model

I used **Logistic Regression** as the classifier.

```python
LogisticRegression(max_iter=1000)
```

---

## Model Performance

The model achieved **97.31% accuracy** on the test dataset.

The classification results were:

| Class | Precision | Recall | F1-Score |
|-------|-----------|--------|----------|
| Ham | 0.97 | 1.00 | 0.98 |
| Spam | 1.00 | 0.80 | 0.89 |

The confusion matrix was:

```text
[[966   0]
 [ 30 119]]
```

The model correctly classified 966 normal messages and 119 spam messages in the test set.

---

## Rule-Based Detection

The ML model is not the only part of SCAMSHIELD.

I also created a rule-based detector that checks the message for specific patterns.

For example:

> "URGENT! Your bank account will be blocked. Verify immediately."

The system can identify:

- Urgency
- Financial terms
- Verification requests
- Threat language

These indicators are then used along with the ML spam probability when calculating the final risk score.

This also makes the result easier to understand because the user can see some of the reasons why a message was considered risky.

---

## Streamlit Interface

I built a simple interface using Streamlit.

The user can:

- Paste a message
- Click **Analyze Message**
- See the ML spam probability
- See the overall scam risk score
- See the detected risk indicators
- Get a recommended action

The application currently runs locally through Streamlit.

---

## Technologies Used

- Python
- Pandas
- Scikit-learn
- TF-IDF
- Logistic Regression
- Streamlit
- Joblib

---

## Project Structure

```text
scam-shield/
│
├── app.py
├── scam_analyzer.py
├── risk_detector.py
├── train_model.py
├── save_model.py
├── explore_data.py
├── test.py
├── test_messages.py
├── model.pkl
├── vectorizer.pkl
└── README.md
```

---

## What I Learned

This project helped me understand how a basic machine learning pipeline works from start to finish.

I worked with:

- Dataset exploration
- Train/test splitting
- Text preprocessing
- TF-IDF feature extraction
- Model training
- Model evaluation
- Probability prediction
- Rule-based detection
- Combining ML results with custom logic
- Building a Streamlit application

One of the interesting parts was realizing that an ML prediction alone isn't always enough. Adding simple rules made it possible to explain why a message was considered risky.

---

## How to Run Locally

Create and activate a virtual environment, then install the required libraries:

```bash
pip install pandas scikit-learn streamlit joblib
```

Run the Streamlit application:

```bash
streamlit run app.py
```

The application will open locally in your browser.

---

## Future Improvements

Some ideas for future versions include:

- Better scam and phishing URL detection
- Multilingual message detection
- More training data
- More advanced NLP models
- Email or SMS integration
- Improved detection of social engineering techniques
- Online deployment

---

## Note

SCAMSHIELD is a learning and project prototype. Its results should not be treated as a guarantee that a message is safe or malicious.

The project is intended for experimentation, learning and demonstration.
