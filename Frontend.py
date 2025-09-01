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
    match = re.search(r'@([^\s>]+)', from_email)
    return match.group(1).lower() if match else 'unknown'

# ✅ List of trusted domains
trusted_domains = {"example.com", "trusted.org", "yourcompany.com"}

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

            # ✅ DKIM Verification
            dkim_verified = False
            try:
                dkim_verified = dkim.verify(raw_data)
                if dkim_verified:
                    analysis_results.append("✅ DKIM verification passed")
                else:
                    analysis_results.append("❌ DKIM verification failed")
            except Exception as e:
                analysis_results.append(f"❌ DKIM check error: {e}")

            # ✅ DMARC Check
            dmarc_status = check_dmarc(sender_domain)
            analysis_results.append(f"DMARC status: {dmarc_status}")

            # ✅ Rule-based keyword checks
            keywords = rule_based_check(subject, snippet)
            if keywords:
                analysis_results.append(f"⚠ Suspicious keywords: {', '.join(keywords)}")

            # ✅ Content analysis
            suspicious_phrases = analyze_content(snippet)
            if suspicious_phrases:
                analysis_results.extend(suspicious_phrases)

            # ✅ URL analysis
            urls = extract_urls(snippet)
            url_issues = analyze_urls(urls, sender_domain)
            if url_issues:
                analysis_results.extend(url_issues)

            # ✅ Show all intermediate results
            for line in analysis_results:
                st.write("🔎", line)

            # ✅ Final classification
            classification, reasons, _ = classify_email(
                dkim_verified, dmarc_status, keywords, suspicious_phrases, url_issues, sender_domain
            )

            st.markdown(f"### Final Classification: ")

            # ✅ Show GREEN (safe) for trusted or safe classifications
            if sender_domain in trusted_domains:
                classification = "Trusted Sender — Safe"
                st.success(f"💎 {classification}")
            elif classification in ["Completely Safe", "Likely Safe"]:
                st.success(f"🟢 {classification}")
            elif classification == "Suspicious (Prank/Spam)":
                st.warning(f"🟠 {classification}")
            elif classification == "Potential Spam / Phishing":
                st.error(f"🔴 {classification}")
            else:
                st.success("Trusted Sender — Safe")

            with st.expander("View detailed reasons"):
                for reason in reasons:
                    st.write(f"- {reason}")

        st.success("Detailed analysis complete!")
