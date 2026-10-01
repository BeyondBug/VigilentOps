FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get upgrade -y --no-install-recommends \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

RUN pip install --no-cache-dir fastapi==0.142.2 uvicorn[standard]==0.54.0 httpx==0.28.1 anyio==4.14.2 \
    && pip uninstall -y setuptools wheel

COPY app.py .

RUN useradd -m appuser && chown -R appuser /app
USER appuser

CMD ["python", "app.py"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8002/_proxy_health', timeout=3)"
