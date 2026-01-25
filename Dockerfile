# syntax=docker/dockerfile:1
FROM python:3.11-slim

# Avoid prompts from apt
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install system packages required by WeasyPrint
RUN apt-get update && apt-get install -y --no-install-recommends \
    # WeasyPrint deps
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 \
    shared-mime-info \
    fonts-dejavu-core \
    # Build tools (for some wheels)
    build-essential \
    pkg-config \
    libffi-dev \
    # SAML / xmlsec deps
    libxml2 \
    libxml2-dev \
    libxmlsec1 \
    libxmlsec1-dev \
    libxmlsec1-openssl \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first (better caching)
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r /app/requirements.txt

# Copy the rest of the app
COPY . /app

# Streamlit config
ENV STREAMLIT_SERVER_PORT=8501 \
    STREAMLIT_SERVER_HEADLESS=true

EXPOSE 8501

CMD ["python", "-m", "streamlit", "run", "app.py"]
