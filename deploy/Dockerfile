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
COPY holder/ ./holder/
COPY scripts/ ./scripts/
COPY deploy/entrypoint.sh ./entrypoint.sh
RUN chmod +x ./entrypoint.sh && rm -f ./issuer/*.db ./verifier/*.db
ENV APP=issuer PORT=5001
EXPOSE 5001 5002
ENTRYPOINT ["./entrypoint.sh"]
