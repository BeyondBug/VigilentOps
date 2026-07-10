FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir fastapi==0.111.0 uvicorn[standard]==0.29.0 httpx==0.27.0

COPY app.py .

CMD ["python", "app.py"]
