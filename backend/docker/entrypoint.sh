#!/bin/sh
set -e

echo "Waiting for database migrations..."

attempt=0

until alembic upgrade head; do
    attempt=$((attempt + 1))

    if [ "$attempt" -ge 10 ]; then
        echo "alembic upgrade head failed after 10 attempts, giving up."
        exit 1
    fi

    echo "Migration attempt $attempt failed, retrying in 3s..."
    sleep 3
done

echo "Starting CloudVault backend..."

exec gunicorn app.main:app -c docker/gunicorn_conf.py
