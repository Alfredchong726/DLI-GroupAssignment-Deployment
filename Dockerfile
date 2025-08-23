# Dockerfile
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# System deps (slim image + wheels, keep small)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps
RUN pip install --no-cache-dir \
    streamlit \
    scikit-learn \
    xgboost \
    pandas \
    numpy \
    joblib

# Copy app and artifacts
COPY app.py /app/app.py
COPY artifacts /app/artifacts

# Streamlit on Render must bind to $PORT
EXPOSE 8000
ENV ART_DIR=/app/artifacts

CMD ["bash", "-lc", "streamlit run app.py --server.port=${PORT:-8000} --server.address=0.0.0.0"]
