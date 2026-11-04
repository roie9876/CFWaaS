#!/usr/bin/env python3
"""Local-only syntax, unit tests, and offline IaC scanning. No Azure deployment."""

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ENTRYPOINTS = ("main", "customer", "management", "cloudguard", "routing-intent")


def run(arguments, env=None):
    print("+ " + " ".join(map(str, arguments)), flush=True)
    result = subprocess.run(arguments, cwd=ROOT, env=env)
    print("Exit status: " + str(result.returncode), flush=True)
    if result.returncode:
        raise RuntimeError("Local validation failed")


def main():
    run([sys.executable, "-B", "-m", "unittest", "discover", "-s", str(ROOT), "-p", "test_*.py", "-v"])
    with tempfile.TemporaryDirectory(prefix="cgvwan-compiled-") as temporary:
        for name in ENTRYPOINTS:
            run(["az", "bicep", "build", "--file", str(ROOT / "infra" / (name + ".bicep")),
                 "--outfile", str(Path(temporary) / (name + ".json"))])
        run(["az", "bicep", "build-params", "--file", str(ROOT / "infra/main.bicepparam"),
             "--outfile", str(Path(temporary) / "main.parameters.json")])
        scanner = ROOT / ".venv-tools/bin/checkov"
        if not scanner.is_file():
            executable = shutil.which("checkov")
            if executable is None:
                raise RuntimeError("Checkov is missing. Install requirements-dev.txt in an isolated environment first.")
            scanner = Path(executable)
        environment = os.environ.copy()
        for name in ("BC_API_KEY", "BRIDGECREW_API_KEY", "PRISMA_API_URL"):
            environment.pop(name, None)
        run([str(scanner), "--directory", temporary, "--config-file", str(ROOT / ".checkov.yml")], environment)
    print("Local validation passed. No Azure or Check Point deployment was performed.")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError) as error:
        print("ERROR: " + str(error), file=sys.stderr)
        sys.exit(1)
