# Build context: agent-poc/  (docker build -f demo/Dockerfile .)
FROM python:3.12-slim
RUN pip install --no-cache-dir fastapi==0.115.6 uvicorn==0.34.0 requests==2.32.3 httpx==0.28.1 \
    cryptography==43.0.3 rfc8785==0.1.4 dcap-qvl==0.7.1
WORKDIR /app
COPY verifier/gateway_attestation.py verifier/verify.py verifier/inspect_answer.py verifier/
COPY agent/e2ee.py agent/
COPY demo/app.py demo/
COPY demo/static demo/static
WORKDIR /app/demo
ENV PYTHONUNBUFFERED=1
EXPOSE 8080
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
