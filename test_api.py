import requests
import json

def test_url(url):
    response = requests.post(
        "http://127.0.0.1:8000/predict",
        data={"url": url}
    )
    result = response.json()
    print(f"\nTesting URL: {url}")
    print(f"Prediction: {result['prediction']}")
    print(f"Confidence: {result['confidence']}")
    print("Feature details:")
    for feature, value in result['details']['features'].items():
        print(f"  {feature}: {value}")

# Test URLs
test_urls = [
    "https://www.google.com",  # Legitimate
    "https://www.paypal.com",  # Legitimate
    "https://www.paypa1.com",  # Phishing (typo)
    "http://free-gift-cards.tk",  # Phishing
    "https://secure-login-bank.com",  # Phishing
    "https://www.github.com",  # Legitimate
    "https://www.microsoft.com",  # Legitimate
    "http://update-account.ga",  # Phishing
]

for url in test_urls:
    test_url(url) 