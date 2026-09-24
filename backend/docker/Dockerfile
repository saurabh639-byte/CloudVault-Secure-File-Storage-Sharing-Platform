FROM python:3.12-slim

WORKDIR /app

# System deps for mysqlclient/bcrypt build + healthcheck curl
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential default-libmysqlclient-dev pkg-config curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY alembic ./alembic
COPY alembic.ini .
COPY docker/gunicorn_conf.py ./docker/gunicorn_conf.py
COPY docker/entrypoint.sh ./docker/entrypoint.sh
RUN chmod +x ./docker/entrypoint.sh

RUN mkdir -p /data/storage
VOLUME ["/data/storage"]

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Runs `alembic upgrade head` then starts Gunicorn with Uvicorn workers
# (see docker/entrypoint.sh, docker/gunicorn_conf.py). Celery containers in
# docker-compose.yml override this CMD with their own celery command, so
# migrations only run once (from the backend container), not once per
# worker replica.
CMD ["/app/docker/entrypoint.sh"]

