import os
import pickle
import base64
import re
from urllib.parse import urlparse
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
import dns.resolver
import dkim

#  Gmail API access scope 
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

#  List of trusted sender domains to reduce false positives
TRUSTED_DOMAINS = [
    "google.com", "microsoft.com", "github.com", "linkedin.com",
    "amazon.com", "apple.com", "facebook.com"
]

def is_trusted_sender(sender_domain):
    return any(sender_domain.lower().endswith(domain) for domain in TRUSTED_DOMAINS)

#  Handles Gmail OAuth authentication
def authenticate_gmail():
    creds = None
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('abc.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)

    service = build('gmail', 'v1', credentials=creds)
    return service

#  Fetches a list of recent emails with subject and sender metadata
def get_email_list(service, max_results=50):
    results = service.users().messages().list(userId='me', maxResults=max_results).execute()
    messages = results.get('messages', [])
    email_summaries = []

    for msg in messages:
        message = service.users().messages().get(
            userId='me', id=msg['id'], format='metadata',
            metadataHeaders=['Subject', 'From']
        ).execute()

        headers = message.get('payload', {}).get('headers', [])
        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), "No Subject")
        sender = next((h['value'] for h in headers if h['name'] == 'From'), "Unknown Sender")

        email_summaries.append({'id': msg['id'], 'subject': subject, 'from': sender})

    return email_summaries

#  Fetches the full raw format of a specific email
def get_email_raw(service, msg_id):
    return service.users().messages().get(userId='me', id=msg_id, format='raw').execute()

#  Extract all URLs from email content using regex
def extract_urls(text):
    url_pattern = r'(https?://[^\s]+)'
    return re.findall(url_pattern, text)

#  Detects phishing-related phrases in the email content
def analyze_content(text):
    suspicious_phrases = [
        "click here", "verify your account", "urgent action required",
        "you have won", "update your info", "account suspended",
        "login immediately", "risk", "confirm password"
    ]
    findings = []
    for phrase in suspicious_phrases:
        if phrase in text.lower():
            findings.append(f"Suspicious phrase detected: '{phrase}'")
    return findings

#  Analyzes the URLs for suspicious patterns
def analyze_urls(urls, sender_domain):
    issues = []
    for url in urls:
        parsed = urlparse(url)
        domain = parsed.hostname or ''

        if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
            issues.append(f"IP address URL detected: {url}")
        elif sender_domain and sender_domain.lower() not in domain.lower():
            issues.append(f"Link domain mismatch: {domain} (sender domain: {sender_domain})")

    return issues

#  Checks for DMARC DNS records
def check_dmarc(domain):
    try:
        txt_records = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
        for txt in txt_records:
            if "v=DMARC1" in str(txt):
                return "DMARC record found"
        return "No valid DMARC record"
    except Exception as e:
        return f"DMARC check failed: {e}"

#  Checks for dangerous keywords in subject/body
def rule_based_check(subject, body):
    keywords = ['win', 'free', 'urgent', 'click', 'verify', 'password', 'bank']
    matches = []
    combined = (subject + ' ' + body).lower()

    for word in keywords:
        if word in combined:
            matches.append(word)

    return matches

#  Final fraud classification based on analysis
def classify_email(dkim_verified, dmarc_status, keywords, suspicious_phrases, url_issues, sender_domain):
    reasons = []
    score = 0

    if is_trusted_sender(sender_domain):
        reasons.append("✅ Sender is from a trusted domain")
        if not dkim_verified:
            reasons.append("⚠ DKIM failed, but trusted domain")
            score += 1
        if "DMARC record found" not in dmarc_status:
            reasons.append("⚠ DMARC missing, but trusted domain")
            score += 1
    else:
        if not dkim_verified:
            reasons.append("❌ DKIM verification failed")
            score += 3
        else:
            reasons.append("✅ DKIM verification passed")

        if "DMARC record found" in dmarc_status:
            reasons.append("✅ Valid DMARC record found")
        else:
            reasons.append("❌ No valid DMARC record")
            score += 2

    if keywords:
        reasons.append(f"⚠ Suspicious keywords found: {', '.join(keywords)}")
        score += len(keywords)

    if suspicious_phrases:
        reasons.append(f"⚠ Suspicious phrases: {', '.join([p.split(': ')[1] for p in suspicious_phrases])}")
        score += len(suspicious_phrases)

    if url_issues:
        reasons.append(f"⚠ URL issues: {', '.join([issue.split(': ')[1] for issue in url_issues])}")
        score += len(url_issues) * 2

    if is_trusted_sender(sender_domain) and score <= 2:
        classification = "Trusted Sender — Safe"
    elif score == 0:
        classification = "Completely Safe"
    elif score <= 2:
        classification = "Likely Safe"
    elif score <= 5:
        classification = "Suspicious (Prank/Spam)"
    elif score <= 8:
        classification = "Potential Spam / Phishing"
    else:
        classification = "Dangerous / Threat"

    return classification, reasons, score
