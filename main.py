import os
import pickle
import base64
import re
import streamlit as st
from urllib.parse import urlparse
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
import dns.resolver
import dkim

# Gmail API scopes
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def authenticate_gmail():
    creds = None
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)
    service = build('gmail', 'v1', credentials=creds)
    return service

def get_email_list(service, max_results=50):
    results = service.users().messages().list(userId='me', maxResults=max_results).execute()
    messages = results.get('messages', [])
    email_summaries = []
    for msg in messages:
        message = service.users().messages().get(userId='me', id=msg['id'], format='metadata', metadataHeaders=['Subject', 'From']).execute()
        headers = message.get('payload', {}).get('headers', [])
        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), "No Subject")
        sender = next((h['value'] for h in headers if h['name'] == 'From'), "Unknown Sender")
        email_summaries.append({'id': msg['id'], 'subject': subject, 'from': sender})
    return email_summaries

def get_email_raw(service, msg_id):
    msg = service.users().messages().get(userId='me', id=msg_id, format='raw').execute()
    return msg

def extract_urls(text):
    url_pattern = r'(https?://[^\s]+)'
    return re.findall(url_pattern, text)

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

def analyze_urls(urls, sender_domain):
    issues = []
    for url in urls:
        parsed = urlparse(url)
        domain = parsed.hostname or ''
        if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
            issues.append(f"IP address URL detected: {url}")
        elif sender_domain and sender_domain not in domain:
            issues.append(f"Link domain mismatch: {domain} (sender domain: {sender_domain})")
    return issues

def check_dmarc(domain):
    try:
        txt_records = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
        for txt in txt_records:
            if "v=DMARC1" in str(txt):
                return "DMARC record found"
        return "No valid DMARC record"
    except Exception as e:
        return f"DMARC check failed: {e}"

def rule_based_check(subject, body):
    keywords = ['win', 'free', 'urgent', 'click', 'verify', 'password', 'bank']
    matches = []
    combined = (subject + ' ' + body).lower()
    for word in keywords:
        if word in combined:
            matches.append(word)
    return matches

def classify_email(dkim_verified, dmarc_status, keywords, suspicious_phrases, url_issues):
    score = 0
    reasons = []

    # DKIM
    if dkim_verified:
        reasons.append("DKIM verification passed")
    else:
        reasons.append("DKIM verification failed")
        score += 3

    # DMARC
    if "DMARC record found" in dmarc_status:
        reasons.append("Valid DMARC record found")
    else:
        reasons.append("No valid DMARC record")
        score += 2

    # Keywords
    if keywords:
        reasons.append(f"Suspicious keywords found: {', '.join(keywords)}")
        score += len(keywords)

    # Suspicious phrases
    if suspicious_phrases:
        reasons.append(f"Suspicious phrases detected: {', '.join([p.split(': ')[1] for p in suspicious_phrases])}")
        score += len(suspicious_phrases)

    # URL issues
    if url_issues:
        reasons.append(f"URL issues detected: {', '.join([issue.split(': ')[1] for issue in url_issues])}")
        score += len(url_issues) * 2  # URLs are higher risk

    # Classification based on score
    if score == 0:
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

# --- Streamlit UI ---
st.set_page_config(page_title="Gmail Fraud Detector", layout="wide")
st.title("🛡️Gmail Fraud Email Detector")

with st.spinner("Authenticating with Gmail..."):
    service = authenticate_gmail()
    emails = get_email_list(service, max_results=50)

if not emails:
    st.warning("No emails found.")
    st.stop()

# Show list of emails for selection
email_display = [f"{email['subject']} — {email['from']}" for email in emails]

selected_indices = st.multiselect(
    "Select emails to analyze",
    options=list(range(len(email_display))),
    format_func=lambda i: email_display[i]
)

if st.button("Run Detailed Analysis on Selected Emails"):
    if not selected_indices:
        st.warning("Please select at least one email to analyze.")
    else:
        for idx in selected_indices:
            email = emails[idx]
            st.markdown(f"---\n### ✉️ Email: {email['subject']}\nFrom: {email['from']}")

            try:
                msg = get_email_raw(service, email['id'])
                raw_data = base64.urlsafe_b64decode(msg['raw'].encode("ASCII"))
            except Exception as e:
                st.error(f"❌ Error decoding raw email: {e}")
                continue

            payload = msg.get('payload', {})
            headers = payload.get('headers', [])
            subject = email['subject']
            from_email = email['from']
            sender_domain = from_email.split('@')[-1] if '@' in from_email else 'unknown'
            snippet = msg.get('snippet', '')

            # Initialize lists to collect findings
            analysis_results = []

            # DKIM check
            dkim_verified = False
            try:
                dkim_verified = dkim.verify(raw_data)
                if dkim_verified:
                    analysis_results.append("✅ DKIM verification passed")
                else:
                    analysis_results.append("❌ DKIM verification failed")
            except Exception as e:
                analysis_results.append(f"❌ DKIM check error: {e}")

            # DMARC check
            dmarc_status = check_dmarc(sender_domain)
            analysis_results.append(f"DMARC status: {dmarc_status}")

            # Rule-based keyword check
            keywords = rule_based_check(subject, snippet)
            if keywords:
                analysis_results.append(f"⚠ Suspicious keywords: {', '.join(keywords)}")

            # Content suspicious phrases
            suspicious_phrases = analyze_content(snippet)
            if suspicious_phrases:
                analysis_results.extend(suspicious_phrases)

            # URL analysis
            urls = extract_urls(snippet)
            url_issues = analyze_urls(urls, sender_domain)
            if url_issues:
                analysis_results.extend(url_issues)

            # Show detailed findings
            for line in analysis_results:
                st.write("🔎", line)

            # Final classification & explanation
            classification, reasons, score = classify_email(dkim_verified, dmarc_status, keywords, suspicious_phrases, url_issues)

            st.markdown(f"### Final Classification: ")
            if classification == "Completely Safe":
                st.success(f"🟢 {classification} (Score: {score})")
            elif classification == "Likely Safe":
                st.info(f"🟡 {classification} (Score: {score})")
            elif classification == "Suspicious (Prank/Spam)":
                st.warning(f"🟠 {classification} (Score: {score})")
            elif classification == "Potential Spam / Phishing":
                st.error(f"🔴 {classification} (Score: {score})")
            else:  # Dangerous / Threat
                st.error(f"🚨 {classification} (Score: {score})")

            with st.expander("View detailed reasons and scoring"):
                for reason in reasons:
                    st.write(f"- {reason}")

        st.success("Detailed analysis complete!")




import streamlit as st
import base64
import dkim  
import re
from backend import (
    authenticate_gmail, get_email_list, get_email_raw,
    extract_urls, analyze_content, analyze_urls,
    check_dmarc, rule_based_check, classify_email
)

st.set_page_config(page_title="Fraud Email Detector", layout="wide")
st.title("🛡️Fraud Email Detector")

def extract_domain(from_email):
    # Extract domain from email string, e.g. "John <john@example.com>"
    match = re.search(r'@([^\s>]+)', from_email)
    return match.group(1).lower() if match else 'unknown'

trusted_domains = {"example.com", "trusted.org", "yourcompany.com"}  # Add your trusted domains here

with st.spinner("Authenticating with Gmail..."):
    service = authenticate_gmail()
    emails = get_email_list(service, max_results=50)

if not emails:
    st.warning("No emails found.")
    st.stop()

email_display = [f"{email['subject']} — {email['from']}" for email in emails]

selected_indices = st.multiselect(
    "Select emails to analyze",
    options=list(range(len(email_display))),
    format_func=lambda i: email_display[i]
)

if st.button("Run Detailed Analysis on Selected Emails"):
    if not selected_indices:
        st.warning("Please select at least one email to analyze.")
    else:
        for idx in selected_indices:
            email = emails[idx]
            st.markdown(f"---\n### ✉️ Email: {email['subject']}\nFrom: {email['from']}")

            try:
                msg = get_email_raw(service, email['id'])
                raw_data = base64.urlsafe_b64decode(msg['raw'].encode("ASCII"))
            except Exception as e:
                st.error(f"❌ Error decoding raw email: {e}")
                continue

            subject = email['subject']
            from_email = email['from']
            sender_domain = extract_domain(from_email)
            snippet = msg.get('snippet', '')

            analysis_results = []

            dkim_verified = False
            try:
                dkim_verified = dkim.verify(raw_data)
                if dkim_verified:
                    analysis_results.append("✅ DKIM verification passed")
                else:
                    analysis_results.append("❌ DKIM verification failed")
            except Exception as e:
                analysis_results.append(f"❌ DKIM check error: {e}")

            dmarc_status = check_dmarc(sender_domain)
            analysis_results.append(f"DMARC status: {dmarc_status}")

            keywords = rule_based_check(subject, snippet)
            if keywords:
                analysis_results.append(f"⚠ Suspicious keywords: {', '.join(keywords)}")

            suspicious_phrases = analyze_content(snippet)
            if suspicious_phrases:
                analysis_results.extend(suspicious_phrases)

            urls = extract_urls(snippet)
            url_issues = analyze_urls(urls, sender_domain)
            if url_issues:
                analysis_results.extend(url_issues)

            for line in analysis_results:
                st.write("🔎", line)

            classification, reasons, _ = classify_email(
                dkim_verified, dmarc_status, keywords, suspicious_phrases, url_issues, sender_domain
            )

            st.markdown(f"### Final Classification: ")
            if sender_domain in trusted_domains:
                st.success(f"💎 Trusted Domain: {sender_domain}")
            elif classification == "Completely Safe":
                st.success(f"🟢 {classification}")
            elif classification == "Likely Safe":
                st.info(f"🟡 {classification}")
            elif classification == "Suspicious (Prank/Spam)":
                st.warning(f"🟠 {classification}")
            elif classification == "Potential Spam / Phishing":
                st.error(f"🔴 {classification}")
            else:
                st.error(f"{classification}")

            with st.expander("View detailed reasons and scoring"):
                for reason in reasons:
                    st.write(f"- {reason}")

        st.success("Detailed analysis complete!")
