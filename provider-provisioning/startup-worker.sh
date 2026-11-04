#!/bin/sh
set -eu
exec python -m uvicorn service.worker_app:app --host 0.0.0.0 --port "${PORT:-8000}" --workers 1 --no-access-log --timeout-graceful-shutdown 180
