FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi==0.115.6 uvicorn==0.34.0 httpx==0.28.1 cryptography==43.0.3 rfc8785==0.1.4
COPY app.py tee.py e2ee.py ./
COPY static ./static
EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
