FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY requirements-server.txt ./
RUN pip install --no-cache-dir -r requirements-server.txt \
    && groupadd --gid 10001 analyser \
    && useradd --uid 10001 --gid analyser --no-create-home --shell /usr/sbin/nologin analyser \
    && mkdir -p /data \
    && chown analyser:analyser /data
COPY app.py production.py bundle.py import_issues.py container_entrypoint.py container_backup.py appsettings.json ./
COPY static/ ./static/
COPY VERSION version_stamp.py ./
RUN python version_stamp.py /app /app/static/index.html
USER 10001:10001
EXPOSE 8766
HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=4 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8766/api/known-issues', timeout=3).close()"
ENTRYPOINT ["python", "container_entrypoint.py"]
CMD ["python", "production.py", "--config", "/data/appsettings.json", "--host", "0.0.0.0", "--port", "8766"]
