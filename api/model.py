import joblib
import re
import tldextract
from urllib.parse import urlparse, unquote
import numpy as np

# Load model and feature names
model = joblib.load('model/phishing_model.pkl')
feature_names = joblib.load('model/feature_names.pkl')

def extract_features(url: str):
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
    
    # Ensure features are in the same order as during training
    feature_values = [features[name] for name in feature_names]
    
    # Debug print
    print("\nExtracted features for URL:", url)
    for name, value in zip(feature_names, feature_values):
        print(f"{name}: {value}")
    
    return feature_values

def predict_url(url: str):
    try:
        features = extract_features(url)
        prediction = model.predict([features])[0]
        proba = model.predict_proba([features])[0]
        
        # Debug print
        print("\nPrediction probabilities:", proba)
        print("Raw prediction:", prediction)
        
        # Map prediction to consistent labels
        label = "phishing" if prediction == 1 else "legitimate"
        confidence = float(max(proba) * 100)  # Convert to float before formatting
        
        return {
            "url": url,
            "prediction": label,
            "confidence": f"{confidence:.2f}%",
            "details": {
                "features": dict(zip(feature_names, features))
            }
        }
    except Exception as e:
        print("\nError during prediction:", str(e))
        return {
            "url": url,
            "prediction": "error",
            "confidence": "0.00%",
            "error": str(e)
        }

    
