FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml alembic.ini ./
COPY migrations ./migrations
COPY src ./src

RUN pip install --no-cache-dir .

COPY tests ./tests
COPY README.md jt808_fixtures.json ./

RUN addgroup --system app && adduser --system --ingroup app app
USER app

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import socket; s=socket.create_connection(('127.0.0.1', 8881), 2); s.close()"

CMD ["python", "-m", "fleet_tracker.ingestion.server"]
