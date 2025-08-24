import streamlit as st
import pandas as pd
import numpy as np
import pickle
import joblib
import urllib.parse
import re
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Page configuration
st.set_page_config(
    page_title="Phishing URL Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

@st.cache_resource
def load_model_and_features():
    """Load the trained model and feature information"""
    try:
        # Load the model
        model = joblib.load('phish_model.pkl')
        
        # Load feature columns
        with open('feature_columns.pkl', 'rb') as f:
            feature_columns = pickle.load(f)
        
        # Load model info
        with open('model_info.pkl', 'rb') as f:
            model_info = pickle.load(f)
            
        return model, feature_columns, model_info
    except Exception as e:
        logger.error(f"Error loading model: {str(e)}")
        return None, None, None

def extract_url_features(url):
    """
    Extract features from URL for phishing detection.
    This is a placeholder function - you'll need to implement the same
    feature extraction logic used in your training data.
    """
    features = {}
    
    try:
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc.lower()
        path = parsed_url.path
        query = parsed_url.query
        
        # Basic URL features (implement based on your dataset features)
        features['url_length'] = len(url)
        features['domain_length'] = len(domain)
        features['path_length'] = len(path)
        features['query_length'] = len(query)
        
        # Count specific characters
        features['dots_count'] = url.count('.')
        features['hyphens_count'] = url.count('-')
        features['underscores_count'] = url.count('_')
        features['slashes_count'] = url.count('/')
        features['questionmarks_count'] = url.count('?')
        features['equals_count'] = url.count('=')
        features['amps_count'] = url.count('&')
        
        # Protocol features
        features['is_https'] = 1 if parsed_url.scheme == 'https' else 0
        features['is_http'] = 1 if parsed_url.scheme == 'http' else 0
        
        # Suspicious patterns
        features['has_ip'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', domain) else 0
        features['has_suspicious_words'] = 1 if any(word in url.lower() for word in 
                                                  ['secure', 'account', 'update', 'suspended', 'verify', 'login']) else 0
        
        # Subdomain count
        subdomains = domain.split('.')
        features['subdomain_count'] = len(subdomains) - 2 if len(subdomains) > 2 else 0
        
        # Port usage
        features['has_port'] = 1 if ':' in parsed_url.netloc and parsed_url.port else 0
        
        # Add more features as needed based on your training data
        
    except Exception as e:
        logger.error(f"Error extracting features from URL: {str(e)}")
        # Return default features if extraction fails
        return {f'feature_{i}': 0 for i in range(20)}
    
    return features

def predict_phishing(url, model, feature_columns):
    """Predict if a URL is phishing or legitimate"""
    try:
        # Extract features from URL
        url_features = extract_url_features(url)
        
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
    # Load model and features
    model, feature_columns, model_info = load_model_and_features()
    
    if model is None:
        st.error("❌ Failed to load the model. Please check if model files are available.")
        st.info("Required files: xgboost_phishing_model.pkl, feature_columns.pkl, model_info.pkl")
        return
    
    # Header
    st.title("🛡️ Phishing URL Detection System")
    st.markdown("### Detect malicious URLs using Machine Learning")
    
    # Sidebar with model information
    with st.sidebar:
        st.header("📊 Model Information")
        if model_info:
            st.write(f"**Model Type:** {model_info.get('model_type', 'XGBoost')}")
            st.write(f"**Features:** {len(feature_columns)} features")
            
            if 'metrics' in model_info:
                st.subheader("Model Performance")
                metrics = model_info['metrics']
                st.write(f"**Accuracy:** {metrics.get('Accuracy', 0):.4f}")
                st.write(f"**Precision:** {metrics.get('Precision', 0):.4f}")
                st.write(f"**Recall:** {metrics.get('Recall', 0):.4f}")
                st.write(f"**F1-Score:** {metrics.get('F1', 0):.4f}")
                st.write(f"**ROC AUC:** {metrics.get('ROC_AUC', 0):.4f}")
    
    # Main interface
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