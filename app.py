# app.py
import io, json, joblib
import pandas as pd
import streamlit as st

st.set_page_config(page_title="Phishing URL Detector", page_icon="🛡️", layout="centered")

@st.cache_resource
def load_assets():
    pipe = joblib.load("phish_model.joblib")
    feats = json.load(open("feature_names.json"))
    return pipe, feats

pipe, FEATURE_NAMES = load_assets()

st.title("🛡️ Phishing URL Detector (XGBoost)")
st.write("Upload a CSV with the **same feature columns** as training (no `CLASS_LABEL`), "
         "or paste one row of JSON to test a single sample.")

tab1, tab2 = st.tabs(["📤 Upload CSV", "✍️ Single row (JSON)"])

with tab1:
    file = st.file_uploader("CSV file", type=["csv"])
    if file:
        df = pd.read_csv(file)
        df = df.drop(columns=[c for c in df.columns if c.lower() in {"class_label","label","target"}], errors="ignore")
        df = df.reindex(columns=FEATURE_NAMES, fill_value=0)
        proba = pipe.predict_proba(df)[:,1]
        pred = (proba >= 0.5).astype(int)
        out = df.copy()
        out["pred"] = pred
        out["prob_phish"] = proba
        st.success(f"Predicted {int(pred.sum())} phishing out of {len(pred)} rows.")
        st.dataframe(out.head(50))
        st.download_button("⬇️ Download predictions CSV", out.to_csv(index=False), "predictions.csv")

with tab2:
    example = "{\n  \"" + "\": 0,\n  \"".join(FEATURE_NAMES[:5]) + "\": 0\n}  // ...complete all features"
    txt = st.text_area("Paste a JSON object with all feature names:", height=180, value=example)
    if st.button("Predict single row"):
        try:
            row = json.loads(txt)
            X = pd.DataFrame([row], columns=FEATURE_NAMES)
            p = float(pipe.predict_proba(X)[:,1][0])
            st.metric("Phishing probability", f"{p:.3f}")
            st.write("Prediction:", int(p >= 0.5))
        except Exception as e:
            st.error(str(e))
