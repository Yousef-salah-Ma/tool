import re
import requests
from bs4 import BeautifulSoup
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
import langid
from langdetect import detect
import logging
import csv

logging.basicConfig(level=logging.INFO)

def write_to_csv(data, filename='sensitive_info.csv'):

    try:
        with open(filename, mode='a', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
           
            if file.tell() == 0:
                writer.writerow(["URL", "Sensitive Information"])
            writer.writerows(data)
    except Exception as e:
        logging.error(f"Error writing to CSV: {e}")

def find_sensitive_info(text, url):
   
    patterns = {
        'API Keys': r'(api_key|apikey|api-key)\s*[:=]\s*["\']([a-zA-Z0-9_-]+)["\']',
        'Access Tokens': r'(access_token|accesstoken)\s*[:=]\s*["\']([a-zA-Z0-9_-]+)["\']',
        'Bearer Tokens': r'Bearer\s+([a-zA-Z0-9._-]+)',
        'Client Secrets': r'(client_secret|clientsecret)\s*[:=]\s*["\']([a-zA0-9._-]+)["\']',
        'AWS Keys': r'AKIA[0-9A-Z]{16}',
        'Google API Keys': r'AIza[0-9A-Za-z-_]{35}',
        'Private Keys': r'-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----',
        'SSH Keys': r'-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]+?-----END OPENSSH PRIVATE KEY-----',
        'Email Addresses': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'Database Credentials': r'(db_user|db_pass|database_password|db_password)\s*[:=]\s*["\']([a-zA-Z0-9._-]+)["\']',
        'Hardcoded Passwords': r'(password|passwd|pwd)\s*[:=]\s*["\']([a-zA-Z0-9._-]+)["\']',
        'JWT Tokens': r'eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}',
        'URLs with Credentials': r'https?:\/\/[a-zA-Z0-9._%+-]+:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    }
    
    found = []
    
    for name, pattern in patterns.items():
        matches = re.findall(pattern, text)
        if matches:
            for match in matches:
                found.append([url, f"{name}: {match[0]}" if isinstance(match, tuple) else f"{name}: {match}"])

    if found:
        logging.info(f"\nSensitive information found in {url}:")
        for item in found:
            logging.info(f"  - {item[1]}")
        write_to_csv(found)
    else:
        logging.info(f"\nNo sensitive information found in {url}.")

def detect_language(text):

    langid_lang, _ = langid.classify(text)
    langdetect_lang = detect(text)
    logging.info(f"Detected language by langid: {langid_lang}")
    logging.info(f"Detected language by langdetect: {langdetect_lang}")
    return langid_lang, langdetect_lang

def analyze_with_ml(text):
 
    train_data = [
        ("API key: abc123", 1),
        ("password = mysecret", 1),
        ("This is a normal text with no sensitive data", 0),
        ("Bearer token xyz456", 1),
        ("Visit our site for more info", 0)
    ]
    
    texts, labels = zip(*train_data)
    
    vectorizer = CountVectorizer()
    X_train = vectorizer.fit_transform(texts)
    
    model = MultinomialNB()
    model.fit(X_train, labels)
    
    X_test = vectorizer.transform([text])
    
    prediction = model.predict(X_test)[0]
    
    if prediction == 1:
        logging.info("Machine Learning Model detected sensitive information.")
    else:
        logging.info("Machine Learning Model did not detect sensitive information.")

def analyze_url(url):
    """
    Function to fetch content from a URL and analyze it for sensitive information.
    It handles different content types (HTML, JSON, Plain Text).
    """
    try:
        logging.info(f"Fetching content from: {url}")
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        content_type = response.headers.get('Content-Type', '').lower()

        if 'text/html' in content_type:
            soup = BeautifulSoup(response.text, 'html.parser')
            text = soup.get_text() 
            code = response.text    
        elif 'application/json' in content_type or 'text/plain' in content_type:
            text = response.text
            code = text
        else:
            logging.info(f"Unsupported content type at {url}: {content_type}")
            return

        logging.info(f"Analyzing text content from {url}...")
        find_sensitive_info(text, url)

        analyze_with_ml(text)

        detect_language(text)

        logging.info(f"Analyzing code content from {url}...")
        find_sensitive_info(code, url)

    except Exception as e:
        logging.error(f"Error fetching {url}: {e}")

def analyze_links(file_path):
 
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            urls = file.readlines()
            for url in urls:
                url = url.strip()
                if url:
                    analyze_url(url)
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {e}")

# Example file path where URLs are stored
file_path = 'file_path'

analyze_links(file_path)
