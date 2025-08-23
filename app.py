# app.py (fixed: set_page_config is the first Streamlit call)

import os, json, joblib, re
import numpy as np
import pandas as pd
import streamlit as st
from urllib.parse import urlparse

# ---- MUST be the first Streamlit command ----
st.set_page_config(page_title="Phishing URL Detector", page_icon="🛡️", layout="centered")

# ---------- load artifacts ----------
ART_DIR = os.environ.get("ART_DIR", "artifacts")
MODEL_PATH = os.path.join(ART_DIR, "xgb_model.joblib")
COLUMNS_PATH = os.path.join(ART_DIR, "feature_columns.json")
MEDIANS_PATH = os.path.join(ART_DIR, "feature_medians.json")

@st.cache_resource(show_spinner=False)
def load_artifacts():
    model = joblib.load(MODEL_PATH)
    with open(COLUMNS_PATH, "r") as f:
        columns = json.load(f)
    with open(MEDIANS_PATH, "r") as f:
        medians = json.load(f)
    return model, columns, medians

model, FEATURE_COLUMNS, COL_MEDIANS = load_artifacts()

# ---------- URL feature extraction (7 structural features) ----------
SHORTENERS = set("""
bit.ly goo.gl t.co ow.ly is.gd buff.ly tinyurl.com lnkd.in rebrand.ly cutt.ly
t.ly s.id v.gd adf.ly chilp.it clck.ru fb.me youtu.be
""".split())

def _strip_scheme_www(u: str) -> str:
    s = re.sub(r'^\s*https?://', '', u.strip(), flags=re.I)
    s = re.sub(r'^\s*www\.', '', s, flags=re.I)
    return s

def _is_ip(host: str) -> bool:
    return bool(re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', host))

def _subdomain_count(host: str) -> int:
    parts = [p for p in host.split('.') if p]
    return max(0, len(parts) - 2)  # subdomains beyond SLD+TLD

def _has_double_slash_in_path(p: str) -> bool:
    return '//' in p

def _is_shortener(host: str) -> bool:
    return host.lower() in SHORTENERS

def url_struct_features(url: str) -> dict:
    raw = url.strip()
    url_noscheme = _strip_scheme_www(raw)
    parsed = urlparse("http://" + url_noscheme)  # ensure parsable
    host = parsed.hostname or ""
    path = parsed.path or ""
    return {
        "having_IP_Address": 1 if _is_ip(host) else 0,
        "URL_Length": float(len(raw)),
        "Shortining_Service": 1 if _is_shortener(host) else 0,
        "having_At_Symbol": 1 if '@' in raw else 0,
        "double_slash_redirecting": 1 if _has_double_slash_in_path(path) else 0,
        "Prefix_Suffix": 1 if '-' in host else 0,
        "having_Sub_Domain": float(_subdomain_count(host)),
    }

STRUCT_COLS = [
    "having_IP_Address","URL_Length","Shortining_Service","having_At_Symbol",
    "double_slash_redirecting","Prefix_Suffix","having_Sub_Domain"
]

def build_model_input(url: str) -> pd.DataFrame:
    # start with medians so we have every column the model expects
    row = {c: COL_MEDIANS.get(c, 0.0) for c in FEATURE_COLUMNS}
    # override with structural values we can compute from the URL
    s = url_struct_features(url)
    for k, v in s.items():
        if k in row:
            row[k] = float(v)
    return pd.DataFrame([[row[c] for c in FEATURE_COLUMNS]], columns=FEATURE_COLUMNS), s

# ---------- UI ----------
st.title("🛡️ Phishing URL Detector (XGBoost)")
st.markdown(
    "Paste a URL below. The app derives **URL-only structural features** "
    "and fills any remaining features with the training medians you exported."
)

url_input = st.text_input("URL", placeholder="e.g., https://secure-login.example.com/account//verify")

if st.button("Predict", type="primary") and url_input.strip():
    X_one, used_struct = build_model_input(url_input)
    proba = float(model.predict_proba(X_one)[0, 1])
    pred = int(proba >= 0.5)

    st.subheader("Result")
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Prediction", "Phishing" if pred == 1 else "Benign")
    with col2:
        st.metric("Probability (phishing)", f"{proba:.3f}")

    with st.expander("Show derived URL features"):
        st.json(used_struct)

    with st.expander("Model input preview (first 20 columns)"):
        st.dataframe(X_one.iloc[:, :20])

st.caption("Tip: For best fidelity, train on URL-only features or ensure inference fills columns consistently.")
