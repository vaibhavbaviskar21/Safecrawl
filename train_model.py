import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib
import re
import tldextract
from urllib.parse import urlparse, unquote

def extract_features(url: str):
    if pd.isna(url) or not isinstance(url, str):
        return None
        
    features = {}
    
    # Basic URL features
    features['url_length'] = len(url)
    features['has_ip'] = 1 if re.match(r'https?://(\d{1,3}\.){3}\d{1,3}', url) else 0
    features['count_dots'] = url.count('.')
    features['count_slashes'] = url.count('/')
    features['count_at'] = url.count('@')
    features['count_www'] = url.count('www')
    features['count_subdomains'] = len(tldextract.extract(url).subdomain.split('.'))
    features['count_percent'] = url.count('%')
    features['count_question_mark'] = url.count('?')
    
    # Enhanced features
    parsed_url = urlparse(url)
    path = parsed_url.path
    features['path_length'] = len(path)
    features['path_depth'] = path.count('/')
    features['has_https'] = 1 if url.startswith('https') else 0
    
    # URL encoding features
    decoded_url = unquote(url)
    features['url_encoded'] = 1 if decoded_url != url else 0
    features['special_chars'] = len(re.findall(r'[^a-zA-Z0-9\-\.]', url))
    
    # Keyword features
    suspicious_keywords = ['login', 'account', 'update', 'free', 'verify', 'secure', 'bank', 'password', 'signin']
    features['contains_keyword'] = sum(1 for word in suspicious_keywords if word in url.lower())
    
    # TLD features
    ext = tldextract.extract(url)
    suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'zip', 'xyz', 'top', 'work', 'site', 'online']
    features['suspicious_tld'] = 1 if ext.suffix in suspicious_tlds else 0
    
    # Domain features
    features['domain_length'] = len(ext.domain)
    features['subdomain_length'] = len(ext.subdomain)
    
    return features

def load_and_prepare_data():
    print("Loading phishing URLs...")
    # Load phishing URLs
    phishing_df = pd.read_csv('data/phishing-urls.csv')
    
    # Create full URLs from components if needed
    if 'Protocol' in phishing_df.columns and 'Domain' in phishing_df.columns and 'Path' in phishing_df.columns:
        phishing_df['url'] = phishing_df.apply(
            lambda row: f"{row['Protocol']}://{row['Domain']}{row['Path']}", 
            axis=1
        )
    
    phishing_df['label'] = 1  # 1 for phishing
    
    print("Creating legitimate URLs dataset...")
    # Create legitimate URLs dataset
    legitimate_urls = [
        "https://www.google.com",
        "https://www.github.com",
        "https://www.microsoft.com",
        "https://www.amazon.com",
        "https://www.facebook.com",
        "https://www.twitter.com",
        "https://www.linkedin.com",
        "https://www.instagram.com",
        "https://www.youtube.com",
        "https://www.netflix.com",
        "https://www.spotify.com",
        "https://www.apple.com",
        "https://www.adobe.com",
        "https://www.dropbox.com",
        "https://www.slack.com",
        "https://www.zoom.us",
        "https://www.trello.com",
        "https://www.notion.so",
        "https://www.figma.com",
        "https://www.discord.com",
        "https://www.reddit.com",
        "https://www.medium.com",
        "https://www.stackoverflow.com",
        "https://www.quora.com",
        "https://www.wikipedia.org",
        "https://www.nytimes.com",
        "https://www.bbc.com",
        "https://www.cnn.com",
        "https://www.bloomberg.com",
        "https://www.reuters.com",
        "https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset/data"
    ]
    
    legitimate_df = pd.DataFrame({'url': legitimate_urls, 'label': 0})  # 0 for legitimate
    
    print("Combining datasets...")
    # Combine datasets
    df = pd.concat([phishing_df, legitimate_df], ignore_index=True)
    
    print("Extracting features...")
    # Extract features
    features = []
    valid_indices = []
    for idx, url in enumerate(df['url']):
        feature_dict = extract_features(url)
        if feature_dict is not None:
            features.append(feature_dict)
            valid_indices.append(idx)
    
    # Filter labels to match valid features
    y = df.loc[valid_indices, 'label']
    
    # Convert features to DataFrame
    feature_df = pd.DataFrame(features)
    X = feature_df
    
    print(f"Final dataset size: {len(X)} URLs")
    print(f"Phishing URLs: {sum(y == 1)}")
    print(f"Legitimate URLs: {sum(y == 0)}")
    
    return X, y, feature_df.columns

def train_model():
    print("Loading and preparing data...")
    X, y, feature_names = load_and_prepare_data()
    
    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("\nTraining model...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
    # Evaluate the model
    y_pred = model.predict(X_test)
    print("\nModel Evaluation:")
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    # Save the model and feature names
    print("\nSaving model and feature names...")
    joblib.dump(model, 'model/phishing_model.pkl')
    joblib.dump(feature_names, 'model/feature_names.pkl')
    
    print("\nModel training completed successfully!")

if __name__ == "__main__":
    train_model() 