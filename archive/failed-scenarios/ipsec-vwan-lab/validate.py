#!/usr/bin/env python3
"""Focused tests, local compilation and offline IaC security scanning."""

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def run(arguments, environment=None):
    print("+", " ".join(map(str, arguments)), flush=True)
    result = subprocess.run(arguments, cwd=ROOT, env=environment)
    print("Exit status:", result.returncode, flush=True)
    if result.returncode:
        raise RuntimeError("Local validation failed")


def main():
    run([sys.executable, "-B", "-m", "unittest", "discover", "-s", str(ROOT), "-p", "test_*.py", "-v"])
    with tempfile.TemporaryDirectory(prefix="ipsec-lab-compiled-") as directory:
        for name in ("main", "networks", "compute", "bgp-gateway"):
            run(["az", "bicep", "build", "--file", str(ROOT / "infra" / (name + ".bicep")),
                 "--outfile", str(Path(directory) / (name + ".json"))])
        run(["az", "bicep", "build-params", "--file", str(ROOT / "infra/main.bicepparam"),
             "--outfile", str(Path(directory) / "main.parameters.json")])
        scanner = ROOT.parents[2] / "cloudguard-vwan-lab/.venv-tools/bin/checkov"
        if not scanner.is_file():
            found = shutil.which("checkov")
            if found is None:
                raise RuntimeError("Checkov missing; install the existing development requirements in an isolated environment")
            scanner = Path(found)
        environment = os.environ.copy()
        for key in ("BC_API_KEY", "BRIDGECREW_API_KEY", "PRISMA_API_URL"):
            environment.pop(key, None)
        run([str(scanner), "--directory", directory, "--config-file", str(ROOT / ".checkov.yml")], environment)
    print("PASS: tests, four Bicep entrypoints, parameter file and offline scan. No deployment.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError) as error:
        print("ERROR:", error, file=sys.stderr)
        sys.exit(1)
