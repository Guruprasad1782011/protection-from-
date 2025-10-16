import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

# 1. Load dataset (replace with actual path or dataset)
df = pd.read_csv('emails.csv')  # Must have 'text' and 'label' columns

# 2. Preprocess text
def preprocess(text):
    # Add more advanced preprocessing as needed
    text = text.lower()
    text = ''.join([c for c in text if c.isalnum() or c.isspace()])
    return text

df['clean_text'] = df['text'].apply(preprocess)

# 3. Feature extraction using TF-IDF
vectorizer = TfidfVectorizer(stop_words='english', max_features=5000)
X = vectorizer.fit_transform(df['clean_text'])
y = df['label']  # 1 for phishing, 0 for legitimate

# 4. Train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 5. Train model
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# 6. Evaluate
y_pred = clf.predict(X_test)
print(classification_report(y_test, y_pred))

# 7. Predict function for new emails
def predict_email(email_text):
    email_clean = preprocess(email_text)
    email_vec = vectorizer.transform([email_clean])
    prediction = clf.predict(email_vec)
    return 'Phishing' if prediction[0] == 1 else 'Legitimate'

# Example usage
example_email = "Dear user, click this link to update your account now!"
print("Prediction:", predict_email(example_email))