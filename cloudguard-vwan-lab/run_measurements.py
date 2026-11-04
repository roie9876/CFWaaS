"""Bounded guest HTTP measurements with explicit result framing and error types."""

import json


def script(tests):
    return """python3 - <<'FAAS_PY'
import json
import socket
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
tests = json.loads(TEST_INPUT)
results = []
for test in tests:
    result = {"name": test["name"], "ok": False}
    try:
        with urlopen(Request(test["url"], headers={"Connection": "close"}), timeout=5) as response:
            content = response.read(8192)
            result["ok"] = response.status == 200
            if test["hostname"]:
                result["body"] = json.loads(content)
    except HTTPError as error:
        result.update(errorKind="http", status=error.code)
    except URLError as error:
        reason = error.reason
        result.update(errorKind="timeout" if isinstance(reason, (TimeoutError, socket.timeout)) else "transport",
                      error=str(reason))
    except (TimeoutError, socket.timeout) as error:
        result.update(errorKind="timeout", error=str(error))
    results.append(result)
print("FAAS_RESULT_BEGIN")
print(json.dumps(results))
print("FAAS_RESULT_END")
FAAS_PY
""".replace("TEST_INPUT", repr(json.dumps(tests)))


def extract_results(output):
    messages = "\n".join(item.get("message", "") for item in output.get("value", []))
    begin, end = "FAAS_RESULT_BEGIN", "FAAS_RESULT_END"
    if messages.count(begin) != 1 or messages.count(end) != 1:
        raise RuntimeError("Guest command did not return one framed measurement set")
    result = json.loads(messages.split(begin, 1)[1].split(end, 1)[0])
    if not isinstance(result, list) or not result or any(
        not isinstance(item, dict) or not isinstance(item.get("ok"), bool)
        or not isinstance(item.get("name"), str) for item in result
    ):
        raise RuntimeError("Invalid guest measurement output shape")
    return result
