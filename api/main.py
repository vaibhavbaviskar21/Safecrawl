from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import joblib
import re
import tldextract
from urllib.parse import urlparse, unquote

# Load model and feature names
model = joblib.load('model/phishing_model.pkl')
feature_names = joblib.load('model/feature_names.pkl')

app = FastAPI(
    title="Safecrawl - Malicious URL Detector",
    description="A machine learning-based API for detecting malicious and phishing URLs",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

class URLPrediction(BaseModel):
    url: str
    prediction: str
    confidence: str
    details: dict

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
    return feature_values

@app.get("/", response_class=HTMLResponse)    
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "result": None})
                                      
@app.post("/predict", response_class=HTMLResponse)
async def classify_url(request: Request, url: str = Form(...)):
    """
    Classify a URL as either legitimate or phishing.
    
    Parameters:
    - url: The URL to be classified
    
    Returns:
    - Renders the index.html template with the prediction result
    """
    try:
        features = extract_features(url)
        prediction = model.predict([features])[0]
        proba = model.predict_proba([features])[0]
        
        # Map prediction to consistent labels
        label = "phishing" if prediction == 1 else "legitimate"
        confidence = float(max(proba) * 100)  # Convert to float before formatting
        
        # Add trust score for known good domains
        known_good_domains = ["kaggle.com", "github.com", "google.com", "microsoft.com", "amazon.com", "facebook.com", "twitter.com", "linkedin.com", "instagram.com", "youtube.com", "netflix.com", "spotify.com", "apple.com", "adobe.com", "dropbox.com", "slack.com", "zoom.us", "trello.com", "notion.so", "figma.com", "discord.com", "reddit.com", "medium.com", "stackoverflow.com", "quora.com", "wikipedia.org", "nytimes.com", "bbc.com", "cnn.com", "bloomberg.com", "reuters.com"]
        trust_score = 0
        if any(domain in url for domain in known_good_domains):
            trust_score += 1

        # Adjust prediction based on trust score
        if trust_score > 0:
            prediction = "legitimate"
            confidence = 100.0
        
        result = {
            "url": url,
            "prediction": prediction,
            "confidence": f"{confidence:.2f}%",
            "details": {
                "features": dict(zip(feature_names, features))
            }
        }
        return templates.TemplateResponse("index.html", {"request": request, "result": result})
    except Exception as e:
        result = {
            "url": url,
            "prediction": "error",
            "confidence": "0.00%",
            "error": str(e)
        }
        return templates.TemplateResponse("index.html", {"request": request, "result": result})
