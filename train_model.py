import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# Load the dataset
file_path = "data/sms+spam+collection/SMSSpamCollection"

data = pd.read_csv(
    file_path,
    sep="\t",
    header=None,
    names=["label", "message"],
    encoding="utf-8"
)

# Separate messages and labels
X = data["message"]
y = data["label"]

# Split the dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

# Create TF-IDF vectorizer
vectorizer = TfidfVectorizer()

# Learn vocabulary from training data and transform it
X_train_tfidf = vectorizer.fit_transform(X_train)

# Transform testing data using the same vocabulary
X_test_tfidf = vectorizer.transform(X_test)

# Display information
print("Training messages:", len(X_train))
print("Testing messages:", len(X_test))

print("\nTF-IDF training matrix shape:")
print(X_train_tfidf.shape)

print("\nTF-IDF testing matrix shape:")
print(X_test_tfidf.shape)
# Train the Logistic Regression model
model = LogisticRegression(max_iter=1000)

model.fit(X_train_tfidf, y_train)

print("\nModel training completed!")

# Make predictions on the test data
y_pred = model.predict(X_test_tfidf)

# Calculate accuracy
accuracy = accuracy_score(y_test, y_pred)

print("\nAccuracy:", accuracy)

# Detailed evaluation
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# Confusion matrix
print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# Test the model with new messages

new_messages = [
    "Congratulations! You have won a free prize. Click the link now!",
    "Hey, are you coming to college tomorrow?",
    "URGENT! Your bank account will be blocked. Verify your account immediately.",
    "Can you send me the notes from today's lecture?"
]

# Convert new messages into TF-IDF features
new_messages_tfidf = vectorizer.transform(new_messages)

# Make predictions
predictions = model.predict(new_messages_tfidf)

# Get probability estimates
probabilities = model.predict_proba(new_messages_tfidf)

print("\nPredictions for new messages:")

for message, prediction, probability in zip(
    new_messages, predictions, probabilities
):
    ham_probability = probability[0]
    spam_probability = probability[1]

    print("\nMessage:", message)
    print("Prediction:", prediction.upper())
    print(f"Ham probability: {ham_probability:.2%}")
    print(f"Spam probability: {spam_probability:.2%}")