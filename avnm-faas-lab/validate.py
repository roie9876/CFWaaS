#!/usr/bin/env python3
"""Local-only regression tests, Bicep compilation and offline IaC scan."""

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SCANNER = ROOT.parent / "cloudguard-vwan-lab/.venv-tools/bin/checkov"


def run(arguments, env=None):
    print("+ " + " ".join(map(str, arguments)), flush=True)
    result = subprocess.run(arguments, cwd=ROOT, env=env)
    print("Exit status:", result.returncode, flush=True)
    if result.returncode:
        raise RuntimeError("Local validation command failed")


def main():
    run([sys.executable, "-B", "-m", "unittest", "discover", "-s", str(ROOT), "-p", "test_*.py", "-v"])
    with tempfile.TemporaryDirectory(prefix="avnm-lab-build-") as temporary:
        for name in ("main", "customer", "compute"):
            run(["az", "bicep", "build", "--file", str(ROOT / "infra" / (name + ".bicep")),
                 "--outfile", str(Path(temporary) / (name + ".json"))])
        scanner = SCANNER if SCANNER.is_file() else shutil.which("checkov")
        if scanner is None:
            raise RuntimeError("Checkov is missing. Install cloudguard-vwan-lab/requirements-dev.txt in an isolated environment.")
        environment = os.environ.copy()
        environment.pop("BC_API_KEY", None)
        environment.pop("BRIDGECREW_API_KEY", None)
        run([str(scanner), "--directory", temporary, "--config-file", str(ROOT / ".checkov.yml")], environment)
    print("PASS: local tests, Bicep and offline security scan. No Azure deployment.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError) as error:
        print("ERROR:", error, file=sys.stderr)
        sys.exit(1)
