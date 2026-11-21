FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir cryptography==43.0.3 requests==2.32.3
COPY server.py tee_crypto.py ./
EXPOSE 8000
CMD ["python", "server.py"]
