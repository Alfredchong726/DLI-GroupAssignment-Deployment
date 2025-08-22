# app.py
import re, json, joblib, ipaddress
from urllib.parse import urlparse
import numpy as np
import pandas as pd
import streamlit as st

# ---------- LOAD ----------
@st.cache_resource
def load_assets():
    model = joblib.load("phish_model.joblib")
    feat_names = json.load(open("feature_names.json"))
    return model, feat_names

model, FEATURE_NAMES = load_assets()

# ---------- URL -> BASIC FEATURES (URL-only, safe offline) ----------
SHORTENERS = {
    "bit.ly","goo.gl","t.co","ow.ly","is.gd","buff.ly","tinyurl.com","lnkd.in",
    "rebrand.ly","cutt.ly","t.ly","s.id","v.gd","adf.ly","chilp.it","clck.ru",
    "fb.me","youtu.be"
}

def parse_url(url: str):
    u = url.strip()
    if not re.match(r'^https?://', u, flags=re.I):
        u = "http://" + u
    p = urlparse(u)
    host = (p.hostname or "").lower()
    path = p.path or ""
    return u, host, path

def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False

def subdomain_count(host: str) -> int:
    parts = [s for s in host.split('.') if s]
    if len(parts) <= 2:   # e.g., example.com
        return 0
    return len(parts) - 2 # everything before SLD+TLD

# Fuzzy column matcher (handles weird Mendeley names like "having_IPhaving_IP_Address")
_norm = lambda s: re.sub(r'[^a-z0-9]', '', s.lower())
def find_col(candidates):
    norm_map = {_norm(c): c for c in FEATURE_NAMES}
    for cand in candidates:
        key = _norm(cand)
        if key in norm_map:
            return norm_map[key]
    # fallback: substring contains
    for cand in candidates:
        key = _norm(cand)
        for k, v in norm_map.items():
            if key in k:
                return v
    return None

def url_to_feature_row(url: str) -> pd.DataFrame:
    # start with NaN for every feature
    row = {c: np.nan for c in FEATURE_NAMES}

    raw, host, path = parse_url(url)

    # Compute URL-derivable features
    f_ip   = 1 if is_ip(host) else 0
    f_len  = len(raw)
    f_short= 1 if host in SHORTENERS else 0
    f_at   = 1 if '@' in raw else 0
    # after scheme, any '//' in the remaining path counts as redirect-ish
    rest = raw.split("://", 1)[1] if "://" in raw else raw
    f_dbls = 1 if '//' in rest.replace('//', '', 1) else 0
    f_dash = 1 if '-' in host else 0
    f_subc = subdomain_count(host)

    # Map into your training columns (set only if column exists)
    mapping = {
        "having_ip": (f_ip, ["having_IP_Address","having_IPhaving_IP_Address","havingipaddress","ip_address"]),
        "url_length": (f_len, ["URL_Length","URLURL_Length","urllength"]),
        "shortener": (f_short, ["Shortining_Service","shortening_service","shortiningservice"]),
        "at_symbol": (f_at, ["having_At_Symbol","having_at_symbol"]),
        "double_slash": (f_dbls, ["double_slash_redirecting","double//","double_slash"]),
        "prefix_suffix": (f_dash, ["Prefix_Suffix","prefix_suffix","dash_in_domain"]),
        "subdomain": (f_subc, ["having_Sub_Domain","having_sub_domain","subdomain_count"]),
        # optional: host contains 'https' token
        "https_token": (1 if "https" in host else 0, ["HTTPS_token","https_token"])
    }

    for _, (val, aliases) in mapping.items():
        col = find_col(aliases)
        if col:
            row[col] = val

    # Build 1-row DataFrame in correct training order
    X = pd.DataFrame([row], columns=FEATURE_NAMES)
    return X

# ---------- UI ----------
st.set_page_config(page_title="Phishing URL Detector", page_icon="🛡️", layout="centered")
st.title("🛡️ Phishing URL Detector")
st.caption("Type a URL. We compute URL-only features and use your trained XGBoost model.")

url = st.text_input("Enter URL to scan", placeholder="https://example.com/login")
threshold = st.slider("Decision threshold (phishing if probability ≥ threshold)", 0.10, 0.90, 0.50, 0.01)

if st.button("Scan URL") and url.strip():
    try:
        Xrow = url_to_feature_row(url)
        proba = float(model.predict_proba(Xrow)[:, 1][0])
        pred = int(proba >= threshold)

        st.metric("Phishing probability", f"{proba:.3f}")
        if pred == 1:
            st.error("Prediction: PHISHING")
        else:
            st.success("Prediction: BENIGN")

        # Show which URL-derived features were filled
        filled = Xrow.iloc[0].dropna()
        st.subheader("URL-derived features used")
        st.write(filled.to_frame("value"))
    except Exception as e:
        st.error(str(e))

st.divider()
st.caption("Note: Only URL-string features are computed. Other training features are left as NaN (XGBoost can handle missing).")