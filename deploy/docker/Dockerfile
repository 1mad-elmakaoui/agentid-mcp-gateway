# syntax=docker/dockerfile:1
FROM python:3.11-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY agentid ./agentid
COPY policies ./policies
COPY scripts ./scripts
COPY pyproject.toml README.md ./
RUN pip install --no-cache-dir --no-deps -e .

# The gateway runs unprivileged; nothing it does needs root.
RUN useradd --system --create-home --uid 10001 agentid \
    && chown -R agentid:agentid /app
USER agentid

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"

CMD ["uvicorn", "agentid.gateway.main:app", "--host", "0.0.0.0", "--port", "8000"]
