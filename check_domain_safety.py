import ssl
import dns.resolver
import tldextract
import requests
import streamlit as st
import whois
import socket
# --- Domain Processing Functions ---
def extract_domain(url):
    extracted = tldextract.extract(url)
    subdomain = f"{extracted.subdomain}." if extracted.subdomain else ""
    domain = f"{subdomain}{extracted.domain}.{extracted.suffix}"
    return domain

def domain_exists(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except socket.error:
        return False

def check_ssl(domain):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain):
                return True
    except Exception:
        return False

def check_mx(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        return len(answers) > 0
    except:
        return False

def domain_whois(domain):
    try:
        w = whois.whois(domain)
        return {
            "domain_name": w.domain_name,
            "creation_date": str(w.creation_date),
            "registrar": w.registrar,
            "org": w.org,
            "country": w.country
        }
    except:
        return None

def calculate_risk_score(has_ssl, has_mx, whois_data):
    score = 0
    if has_ssl:
        score += 30
    if has_mx:
        score += 30
    if whois_data:
        score += 40
    return score

def domain_trust_report(input_url):
    domain = extract_domain(input_url)
    if not domain_exists(domain):
        return {
            "domain": domain,
            "exists": False,
            "has_ssl": False,
            "has_mx": False,
            "whois_data": None,
            "risk_score": 0,
            "message": "Domain does not exist. This could be a high-risk web."
        }

    has_ssl = check_ssl(domain)
    has_mx = check_mx(domain)
    whois_data = domain_whois(domain)
    risk_score = calculate_risk_score(has_ssl, has_mx, whois_data)

    return {
        "domain": domain,
        "exists": True,
        "has_ssl": has_ssl,
        "has_mx": has_mx,
        "whois_data": whois_data,
        "risk_score": risk_score,
        "message": "Domain is active."
    }

# --- Streamlit UI ---
st.set_page_config(page_title="Fake Web Detector", layout="centered")
st.title("TrustHire – Fake Web Detector")
st.markdown(
    """
    This tool evaluates the trustworthiness of job listing URLs by analyzing domain existence,
    SSL certificate, MX records, and WHOIS registration data.
    """
)

user_input = st.text_input("Enter the full web URL to scan:")

if user_input:
    with st.spinner("Analyzing domain..."):
        result = domain_trust_report(user_input)

    st.subheader("Domain Safety Report")
    st.write(f"**Domain:** {result['domain']}")
    st.write(f"**Exists:** {'Yes' if result['exists'] else 'No'}")
    st.write(f"**SSL Certificate Present:** {'Yes' if result['has_ssl'] else 'No'}")
    st.write(f"**MX Records Found:** {'Yes' if result['has_mx'] else 'No'}")

    st.markdown("**WHOIS Information:**")
    if result['whois_data']:
        for k, v in result['whois_data'].items():
            st.write(f"- **{k.capitalize()}**: {v}")
    else:
        st.write("- WHOIS data not available.")

    st.markdown(f"### Overall Trust Score: **{result['risk_score']}%**")

    if result['risk_score'] >= 80:
        st.success("This domain appears to be safe and legitimate.")
    elif result['risk_score'] >= 50:
        st.warning("Moderate risk. Please verify further before trusting.")
    else:
        st.error("High risk detected. This domain may be unsafe.")

    st.info(result['message'])