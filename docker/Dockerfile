FROM python:3.12-slim

LABEL maintainer="Security Team"
LABEL description="MISP SIEM Integration - Polling Service"

# Create non-root user
RUN groupadd -r mispint && useradd -r -g mispint -d /app mispint

WORKDIR /app

# Install dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY config/ config/
COPY src/ src/

# Create data directory for state DB
RUN mkdir -p /app/data && chown -R mispint:mispint /app

USER mispint

# Health check: verify Python can import the modules
HEALTHCHECK --interval=60s --timeout=10s --retries=3 \
    CMD python -c "import sys; sys.path.insert(0, 'src'); from core.models import IoC; print('OK')"

ENV PYTHONUNBUFFERED=1
ENV CONFIG_PATH=/app/config/settings.yaml

ENTRYPOINT ["python", "-m"]
CMD ["src.main"]
