FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir fastapi==0.142.2 uvicorn[standard]==0.54.0 httpx==0.28.1 anyio==4.14.2

COPY app.py .

RUN useradd -m appuser && chown -R appuser /app
USER appuser

CMD ["python", "app.py"]
