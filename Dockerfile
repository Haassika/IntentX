FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install only the Linux utilities required for safe
# inspection operations demonstrated in Phase 12.
# Docker Desktop/proxied environments may reject Debian's plain-HTTP
# repository endpoints. Preserve APT signature verification while using HTTPS.
RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' \
        /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install --yes --no-install-recommends \
        procps \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Create an unprivileged runtime user.
RUN groupadd --system intentx \
    && useradd \
        --system \
        --gid intentx \
        --create-home \
        --home-dir /home/intentx \
        intentx

# Copy packaging metadata first for Docker layer caching.
COPY pyproject.toml README.md ./

# The source is required because the IntentX package
# itself is installed into the image.
COPY src ./src

RUN python -m pip install --upgrade pip \
    && python -m pip install .

# Runtime configuration and selected trained model.
COPY configs ./configs
COPY models/intent_classifier_v2.joblib \
     ./models/intent_classifier_v2.joblib

# Writable locations required by the application runtime.
RUN mkdir -p /app/runtime /app/logs \
    && chown -R intentx:intentx \
        /app/runtime \
        /app/logs

# IntentX must never run as root.
USER intentx

EXPOSE 8000

CMD ["uvicorn", "intentx.api.app:app", "--host", "0.0.0.0", "--port", "8000"]