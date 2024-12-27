import re
import requests
from bs4 import BeautifulSoup

def find_sensitive_info(text, url):
    """
    Function to search for sensitive information in the given text.
    It uses predefined regex patterns to find sensitive data like API keys, tokens, passwords, etc.
    """
    patterns = {
        'API Keys': r'(api_key|apikey|api-key)\s*[:=]\s*["\']([a-zA-Z0-9_-]+)["\']',
        'Access Tokens': r'(access_token|accesstoken)\s*[:=]\s*["\']([a-zA-Z0-9_-]+)["\']',
        'Bearer Tokens': r'Bearer\s+([a-zA-Z0-9._-]+)',
        'Client Secrets': r'(client_secret|clientsecret)\s*[:=]\s*["\']([a-zA-Z0-9._-]+)["\']',
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
    
    found = {}
    
    for name, pattern in patterns.items():
        matches = re.findall(pattern, text)
        if matches:
            found[name] = matches

    if found:
        print(f"\nSensitive information found in {url}:")
        for key, values in found.items():
            for value in values:
                print(f"  - {key}: {value}")
    else:
        print(f"\nNo sensitive information found in {url}.")

def analyze_url(url):
    """
    Function to fetch content from a URL and analyze it for sensitive information.
    It handles different content types (HTML, JSON, Plain Text).
    """
    try:
        print(f"Fetching content from: {url}")
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
            print(f"Unsupported content type at {url}: {content_type}")
            return

        print(f"Analyzing text content from {url}...")
        find_sensitive_info(text, url)

        print(f"Analyzing code content from {url}...")
        find_sensitive_info(code, url)

    except Exception as e:
        print(f"Error fetching {url}: {e}")

def analyze_links(file_path):
    """
    Function to read URLs from a file and analyze them.
    Each URL will be passed to the analyze_url function for analysis.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            urls = file.readlines()
            for url in urls:
                url = url.strip()
                if url:
                    analyze_url(url)
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")

file_path = 'file_path'

analyze_links(file_path)
