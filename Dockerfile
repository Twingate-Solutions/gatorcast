FROM python:3.12-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Install dependencies first for better layer caching.
COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install --no-cache-dir .

# Run as an unprivileged, non-root system user. Pre-create the data volume mount
# point and hand both /data and /app to the runtime user so config.data_dir.mkdir
# (and the SQLite WAL / .cast writes under /data) succeed without root.
RUN groupadd --system --gid 10001 gatorcast \
    && useradd --system --uid 10001 --gid gatorcast --home-dir /app --no-create-home gatorcast \
    && mkdir -p /data \
    && chown -R gatorcast:gatorcast /data /app
USER gatorcast

EXPOSE 8080 6514
VOLUME ["/data"]

CMD ["python", "-m", "gatorcast.main"]
