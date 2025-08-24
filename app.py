import streamlit as st
import joblib, json
import numpy as np
import pandas as pd
import re
import logging
import os

# Load model + top-32 features
MODEL_PATH = "models/lightgbm_model.pkl"
FEATURE_PATH = "models/lightgbm_features.json"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

model = joblib.load(MODEL_PATH)
feature_columns = json.load(open(FEATURE_PATH))

st.set_page_config(
    page_title="Phishing URL Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

def extract_features_from_url(url: str) -> dict:
    url = url.strip()
    host = re.sub(r"^https?://", "", url).split('/')[0]
    features = {
        "having_IP_Address": int(bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host))),
        "URL_Length": len(url),
        "Shortining_Service": int(any(s in url for s in ["bit.ly", "tinyurl", "t.co", "is.gd"])),
        "having_At_Symbol": int("@" in url),
        "double_slash_redirecting": int(url.count("//") > 1),
        "Prefix_Suffix": int("-" in host),
        "having_Sub_Domain": host.count("."),
    }
    for feat in feature_columns:
        if feat not in features:
            features[feat] = 0  # pad missing engineered features
    return features

def predict_phishing(url, model, feature_columns):
    """Predict if a URL is phishing or legitimate"""
    try:
        # Extract features from URL
        url_features = extract_features_from_url(url)
        
        # Create DataFrame with the same columns as training data
        feature_df = pd.DataFrame([url_features])
        print(feature_df)
        
        # Ensure all required columns are present
        for col in feature_columns:
            if col not in feature_df.columns:
                feature_df[col] = 0
        
        # Reorder columns to match training data
        feature_df = feature_df.reindex(columns=feature_columns, fill_value=0)
        
        # Make prediction
        prediction = model.predict(feature_df)[0]
        probability = model.predict_proba(feature_df)[0]
        
        return prediction, probability
        
    except Exception as e:
        logger.error(f"Error making prediction: {str(e)}")
        return None, None

def main():
    st.title("🛡️ Phishing URL Detection System")
    st.markdown("### Detect malicious URLs using Machine Learning")

    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("🔍 URL Analysis")
        
        # URL input
        url_input = st.text_input(
            "Enter a URL to check:",
            placeholder="https://example.com",
            help="Enter the complete URL including http:// or https://"
        )
        
        # Analyze button
        if st.button("🔍 Analyze URL", type="primary"):
            if url_input:
                with st.spinner("Analyzing URL..."):
                    prediction, probability = predict_phishing(url_input, model, feature_columns)
                    
                    if prediction is not None:
                        # Display results
                        st.subheader("📋 Analysis Results")
                        
                        col_result1, col_result2 = st.columns(2)
                        
                        with col_result1:
                            if prediction == 1:
                                st.error("⚠️ **PHISHING URL DETECTED**")
                                st.write("This URL appears to be malicious.")
                            else:
                                st.success("✅ **LEGITIMATE URL**")
                                st.write("This URL appears to be safe.")
                        
                        with col_result2:
                            st.write("**Confidence Scores:**")
                            st.write(f"Legitimate: {float(probability[0]):.2%}")
                            st.write(f"Phishing: {float(probability[1]):.2%}")
                        
                        # Confidence bar
                        st.subheader("📊 Confidence Level")
                        confidence = float(probability[1]) if prediction == 1 else float(probability[0])
                        st.progress(confidence)
                        st.write(f"Model Confidence: {confidence:.2%}")
                        
                        # Warning message
                        if prediction == 1:
                            st.warning("⚠️ **Warning**: Do not enter personal information, passwords, or financial details on this website.")
                        
                    else:
                        st.error("❌ Failed to analyze the URL. Please try again.")
            else:
                st.warning("⚠️ Please enter a URL to analyze.")
    
    with col2:
        st.subheader("ℹ️ How it works")
        st.write("""
        This system uses machine learning to analyze URL characteristics and detect phishing attempts:
        
        1. **Feature Extraction**: Analyzes URL structure, length, special characters, and suspicious patterns
        
        2. **ML Prediction**: Uses a trained XGBoost model to classify URLs
        
        3. **Risk Assessment**: Provides confidence scores for the prediction
        """)
        
        st.subheader("🔒 Safety Tips")
        st.write("""
        - Always verify URLs before clicking
        - Look for HTTPS and valid certificates
        - Be cautious of shortened URLs
        - Check for spelling errors in domain names
        - Verify sender authenticity in emails
        """)
    
    # Footer
    st.markdown("---")
    st.markdown("**Disclaimer**: This tool is for educational purposes. Always verify URLs through multiple sources.")

if __name__ == "__main__":
    main()
