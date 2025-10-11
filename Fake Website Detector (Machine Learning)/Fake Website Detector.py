# fake_website_detector.py
# Simple URL-based phishing detector (toy example)

import re
import pandas as pd
from sklearn.feature_extraction import DictVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

def extract_features(url):
    features = {}
    features['length'] = len(url)
    features['has_at'] = int('@' in url)
    features['has_dash'] = int('-' in url)
    features['has_https'] = int(url.startswith('https'))
    features['dots'] = url.count('.')
    features['digits'] = sum(c.isdigit() for c in url)
    features['has_ip'] = int(bool(re.search(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', url)))
    features['suspicious_words'] = int(bool(re.search(r'login|secure|account|bank|verify', url, re.I)))
    return features

# Tiny synthetic dataset (for demo). Replace with larger dataset for real training.
data = [
    ("http://example.com", 0),
    ("https://google.com", 0),
    ("http://192.168.0.1/login", 1),
    ("https://secure-login.com@evil.com", 1),
    ("http://pay-pal.verify-login.com", 1),
    ("https://github.com", 0),
    ("http://bank-secure.verify-account.com", 1),
    ("https://amazon.co.uk", 0),
    ("http://free-gift.example.com", 1),
    ("https://my-university.edu", 0)
]

urls, labels = zip(*data)
X = [extract_features(u) for u in urls]
vec = DictVectorizer(sparse=False)
Xv = vec.fit_transform(X)

X_train, X_test, y_train, y_test, urls_train, urls_test = train_test_split(
    Xv, labels, urls, test_size=0.3, random_state=42
)

clf = LogisticRegression()
clf.fit(X_train, y_train)

y_pred = clf.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred, target_names=["legit","phish"]))

# Interactive prediction
def predict_url(url):
    f = extract_features(url)
    Xf = vec.transform([f])
    p = clf.predict_proba(Xf)[0][1]  # probability of phishing
    label = "PHISHING" if p > 0.5 else "LEGIT"
    print(f"URL: {url}\nPrediction: {label} (phish_prob={p:.2f})\n")

if __name__ == "__main__":
    #
