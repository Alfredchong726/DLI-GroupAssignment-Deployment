# ---- Base Image ----
FROM python:3.10-slim

# ---- Set working dir ----
WORKDIR /app

# ---- Install system dependencies ----
RUN apt-get update && apt-get install -y build-essential

# ---- Copy project ----
COPY . /app

# ---- Install Python dependencies ----
RUN pip install --no-cache-dir -r requirements.txt

# ---- Streamlit port ----
EXPOSE 8080

# ---- Run App ----
CMD ["streamlit", "run", "app.py", "--server.port=8080", "--server.address=0.0.0.0"]
