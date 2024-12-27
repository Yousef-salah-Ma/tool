# tool
Sensitive Information Finder (Web Scraping Tool)
A Python script for identifying sensitive information on websites by scraping their content and searching for common secrets such as API keys, access tokens, database credentials, passwords, and other private data. The script uses regular expressions (regex) to detect sensitive information in HTML, JavaScript, and JSON content.

Key Features:
Scans web pages for common sensitive information like API keys, access tokens, and SSH keys.
Supports multiple content types (HTML, JSON, Plain Text).
Outputs a report of any sensitive information found on the scanned websites.
Designed for use in security assessments and vulnerability detection.
Technologies Used:
Python
Requests (for web scraping)
BeautifulSoup (for HTML parsing)
Regular Expressions (for sensitive data detection)
