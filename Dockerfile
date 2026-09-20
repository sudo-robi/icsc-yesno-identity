FROM python:3.11-slim

WORKDIR /srv/yn
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn
COPY shared/ shared/
COPY issuer/ issuer/
COPY verifier/ verifier/
COPY holder/ holder/
COPY scripts/ scripts/

# APP=issuer|verifier selects the service. Single worker: nonce registry +
# SQLite live in-process. Persistent data belongs on a mounted volume (/data
# with ISSUER_DB/VERIFIER_DB/TRUSTBUNDLE_PATH/OTP_SECRETS_PATH/ISSUER_KEYDIR
# pointed at it). ADMIN_TOKEN *must* be provided (services refuse to start
# without it outside debug).
ENV APP=issuer \
    PORT=5000
EXPOSE 5000
CMD ["sh", "-c", "gunicorn ${APP}.app:app --bind 0.0.0.0:${PORT} --workers 1"]
