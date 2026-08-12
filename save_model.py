import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression


# ==========================================
# 1. LOAD DATASET
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
# 2. PREPARE DATA
# ==========================================

X = data["message"]
y = data["label"]


# ==========================================
# 3. TRAIN / TEST SPLIT
# ==========================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


print("Training messages:", len(X_train))
print("Testing messages:", len(X_test))


# ==========================================
# 4. TF-IDF
# ==========================================

vectorizer = TfidfVectorizer()

X_train_tfidf = vectorizer.fit_transform(X_train)


print("\nTF-IDF training matrix shape:")
print(X_train_tfidf.shape)


# ==========================================
# 5. TRAIN MODEL
# ==========================================

model = LogisticRegression(max_iter=1000)

model.fit(
    X_train_tfidf,
    y_train
)


print("\nModel training completed!")


# ==========================================
# 6. SAVE MODEL
# ==========================================

joblib.dump(
    model,
    "model.pkl"
)

joblib.dump(
    vectorizer,
    "vectorizer.pkl"
)


print("\nModel saved as: model.pkl")
print("Vectorizer saved as: vectorizer.pkl")