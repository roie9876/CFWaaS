#!/bin/sh
set -eu
exec python -m uvicorn service.provider_setup_app:app --host 0.0.0.0 --port "${PORT:-8000}" --workers 1 --no-access-log
