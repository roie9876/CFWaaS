#!/bin/bash
set -euo pipefail
cloud-init status --wait
python3 - <<'PY'
import json
import pathlib
import time
import urllib.request

deadline = time.monotonic() + 300
while not any(p.resolve().name == "mana" for p in pathlib.Path("/sys/class/net").glob("*/device/driver")):
    if time.monotonic() >= deadline:
        raise SystemExit("MANA hardware/driver was not verified; Accelerated Networking alone is insufficient")
    time.sleep(5)
print("FAAS_MANA_VERIFIED")
for attempt in range(30):
    try:
        with urllib.request.urlopen("http://__REMOTE_IP__:8080/peering-proof", timeout=5) as response:
            evidence = json.load(response)
        if evidence.get("sourceIp") != "__SOURCE_IP__":
            raise SystemExit("East-west source address was translated")
        with urllib.request.urlopen("https://www.microsoft.com/", timeout=15) as response:
            if response.status != 200:
                raise SystemExit("Internet egress verification failed")
        print("FAAS_ORIGINAL_SOURCE_AND_EGRESS_VERIFIED")
        break
    except (OSError, ValueError):
        if attempt == 29:
            raise
        time.sleep(5)
PY
