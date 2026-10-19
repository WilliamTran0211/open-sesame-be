ARG PYTHON_IMAGE=python:3.13-alpine

FROM ${PYTHON_IMAGE} AS builder

RUN apk add --no-cache \
    build-base \
    libffi-dev \
    openssl-dev

WORKDIR /build

COPY requirements.txt .
RUN pip install \
    --prefix=/install \
    --no-cache-dir \
    -r requirements.txt

COPY app ./app
RUN python -m compileall -q app

FROM ${PYTHON_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000

RUN apk add --no-cache \
    libffi \
    openssl \
    && addgroup -S app \
    && adduser -S -G app app \
    && mkdir -p /app/logs \
    && chown app:app /app/logs

WORKDIR /app

COPY --from=builder /install /usr/local
COPY --from=builder --chown=app:app /build/app ./app
COPY --chown=app:app alembic.ini ./alembic.ini
COPY --chown=app:app alembic ./alembic

EXPOSE 8000
USER app

CMD ["sh", "-c", "exec gunicorn --bind 0.0.0.0:${PORT:-8000} --workers 1 --worker-class uvicorn.workers.UvicornWorker --timeout 60 app.main:app"]
