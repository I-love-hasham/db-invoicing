# ---- build: install pinned dependencies into a virtualenv, scan them ----
FROM python:3.13-slim AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY requirements.txt requirements-audit.txt /tmp/
RUN python -m venv /venv \
 && /venv/bin/pip install -r /tmp/requirements.txt
# pip-audit runs in its own throwaway venv; its report is shown on the Security Status page.
RUN python -m venv /auditvenv \
 && /auditvenv/bin/pip install -r /tmp/requirements-audit.txt \
 && mkdir -p /security \
 && (/auditvenv/bin/pip-audit -r /tmp/requirements.txt -f json -o /security/pip-audit.json --progress-spinner off || true) \
 && date -u +%Y-%m-%dT%H:%M:%SZ > /security/scanned_at

# ---- runtime ----
FROM python:3.13-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends tzdata \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app \
 && mkdir /data && chown app:app /data && chmod 700 /data
COPY --from=build /venv /venv
COPY --from=build /security /app/security
WORKDIR /app
# Code is owned by root and read-only to the app user.
COPY app ./app
COPY wsgi.py gunicorn.conf.py VERSION ./
ARG BUILD_DATE=unknown
ENV PATH=/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_DIR=/data \
    SECURITY_DIR=/app/security \
    BUILD_DATE=${BUILD_DATE}
USER app
EXPOSE 8080
HEALTHCHECK --interval=60s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3).status == 200 else 1)"]
CMD ["gunicorn", "-c", "gunicorn.conf.py", "wsgi:app"]
