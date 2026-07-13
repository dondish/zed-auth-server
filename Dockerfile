FROM python:3.12-slim

WORKDIR /app

# Install Python deps first for better layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# The server package (app assembly, routers, stores, blobstore, …).
COPY server/ ./server/

# Certs and persistent state are provided at runtime via volumes.
#   /certs — server.crt / server.key (generate with `python -m scripts.gen_certs`)
#   /data  — state.json (users + tokens)
EXPOSE 8443 8080 8787

ENTRYPOINT ["python", "-m", "server"]
CMD ["--host", "0.0.0.0", "--port", "8443", "--internal-port", "8787", \
     "--cert-dir", "/certs", "--data-dir", "/data"]
