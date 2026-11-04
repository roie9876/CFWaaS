"""Shared guest-result framing and HTTP probes; no deployment entrypoint."""

import json
import re

SERVER = r'''import json
import socket
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        record = {
            "time": datetime.now(timezone.utc).isoformat(),
            "hostname": socket.gethostname(),
            "client_ip": self.client_address[0],
            "path": self.path,
        }
        body = json.dumps(record).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        print(json.dumps(record), flush=True)

    def log_message(self, format, *args):
        pass

ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
'''


def extract_guest_result(output):
    messages = "\n".join(item.get("message", "") for item in output.get("value", []))
    match = re.search(r"FAAS_RESULT_BEGIN\s*\n(.*?)\nFAAS_RESULT_END", messages, re.S)
    if not match:
        raise RuntimeError("Guest command did not return a complete FAAS_RESULT payload: " + messages[-1500:])
    result = json.loads(match.group(1))
    if not isinstance(result, list) or not result or not all(
        isinstance(item, dict) and isinstance(item.get("ok"), bool) for item in result
    ):
        raise RuntimeError("Guest result shape is invalid")
    return result


def require_marker(output, marker):
    messages = "\n".join(item.get("message", "") for item in output.get("value", []))
    if marker not in messages:
        raise RuntimeError("Guest command did not confirm " + marker + ": " + messages[-1500:])


def result_script(python_source):
    return ["python3 - <<'FAAS_PYTHON'", python_source, "FAAS_PYTHON"]


def request_script(targets):
    source = r'''
import http.client
import json
import socket
targets = TARGETS
results = []
for target in targets:
    item = {"test": target["test"], "host": target["host"], "port": target["port"]}
    connection = http.client.HTTPConnection(target["host"], target["port"], timeout=6)
    try:
        connection.request("GET", target["path"], headers={"Connection": "close"})
        response = connection.getresponse()
        body = response.read().decode()
        item.update({"ok": response.status == 200, "status": response.status, "body": json.loads(body)})
    except (OSError, http.client.HTTPException, json.JSONDecodeError) as error:
        item.update({"ok": False, "errorType": type(error).__name__, "error": str(error),
                     "errno": getattr(error, "errno", None)})
    finally:
        connection.close()
    results.append(item)
print("FAAS_RESULT_BEGIN")
print(json.dumps(results))
print("FAAS_RESULT_END")
'''
    return result_script(source.replace("TARGETS", repr(targets)))
