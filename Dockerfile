# syntax=docker/dockerfile:1

# ---- build stage: produce a wheel ----------------------------------------------------
FROM python:3.12-slim AS build
WORKDIR /src
RUN pip install --no-cache-dir build
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m build --wheel --outdir /dist

# ---- runtime stage: minimal, non-root ------------------------------------------------
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AGENTWARDEN_DB_PATH=/data/agentwarden.db
RUN useradd --create-home --uid 10001 warden \
 && mkdir -p /data /keys \
 && chown warden:warden /data /keys
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl
USER warden
WORKDIR /home/warden
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"
# Binding to all interfaces is intended inside the container; publish the port deliberately.
CMD ["agentwarden", "serve", "--host", "0.0.0.0", "--port", "8000"]
