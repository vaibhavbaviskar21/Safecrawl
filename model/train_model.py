import pandas as pd 
from sklearn.ensemble import RandomForestClassifier
from sklearn.mode_selection import train_test_split
from sklearn.metrices import classification_report
import joblib
import tldextract
import re 

df = pd.read_csv("/data/dataset_phishing_csv")

def extract_features(url):
    features ={}
    features['url_length']=len(url)
    features['has_ip']=1 if re.match(r'https?://(\d{1,3}\.){3}\d{1,3}',url) else 0
    features['count_dots'] = url.count('.')
    features['count_slashes'] = url.count('/')
    features['count_at']=url.count('@')
    features['count_www']=url.count('www')
    features['count_subdomains'] = len(tldextract.extract(url).subdomain.split('.'))
    features['count_percent']=url.count('%')
    features['count_question_mark']=url.count('?')
    features['contains_keyword']=sum(1 for word in ['login','account','update','free','verify'] if word in url.lower())    

    ext = tldextract.extract(url)
    features['suspicious_tld']=1 if ext.suffix in['tk','ml','ga','cf','zip'] else 0

    return list(features.values)
