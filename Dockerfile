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

CMD ["python", "-m", "fleet_tracker.ingestion.server"]
