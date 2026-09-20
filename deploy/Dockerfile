# Production image for the issuer + verifier Flask services.
# Build from the repo root:  docker build -f deploy/Dockerfile .
FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ ./shared/
COPY issuer/ ./issuer/
COPY verifier/ ./verifier/
RUN rm -f ./issuer/*.db ./verifier/*.db
ENV APP=issuer PORT=5001
EXPOSE 5001 5002
# APP=issuer|verifier selects the gunicorn target; ADMIN_TOKEN is mandatory.
CMD ["sh", "-c", ": \"${ADMIN_TOKEN:?set ADMIN_TOKEN}\" && if [ \"$APP\" = verifier ]; then exec gunicorn verifier.app:app --bind 0.0.0.0:${PORT:-5002} --workers 1; else exec gunicorn issuer.app:app --bind 0.0.0.0:${PORT:-5001} --workers 1; fi"]
