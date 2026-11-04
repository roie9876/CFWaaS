FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PORT=8000
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --create-home faas
COPY --chown=faas:faas service/*.py ./service/
COPY --chown=faas:faas service/templates ./service/templates
COPY --chown=faas:faas service/static ./service/static
COPY --chown=faas:faas startup-api.sh startup-worker.sh startup-management.sh ./
USER faas
EXPOSE 8000
CMD ["sh", "startup-api.sh"]
