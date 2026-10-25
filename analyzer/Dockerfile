FROM python:3.11-slim

LABEL maintainer="Ritvik Indupuri <ritvik.indupuri@gmail.com>"
LABEL description="Automated Volatility 3 & Linux Cloud Memory Forensics Worker"

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    curl \
    wget \
    gzip \
    tar \
    binutils \
    libcapstone-dev \
    libyara-dev \
    awscli \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/dfir

# Install Volatility 3 and forensic symbols
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download official Linux and Windows symbol tables for Volatility 3
RUN mkdir -p /root/.local/share/volatility3/symbols \
    && curl -sSL https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip -o /tmp/linux_symbols.zip || true \
    && (unzip -q /tmp/linux_symbols.zip -d /root/.local/share/volatility3/symbols/ 2>/dev/null || true) \
    && rm -f /tmp/linux_symbols.zip

COPY analyze_memory.py /opt/dfir/analyze_memory.py
RUN chmod +x /opt/dfir/analyze_memory.py

ENTRYPOINT ["python", "/opt/dfir/analyze_memory.py"]
