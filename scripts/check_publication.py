#!/usr/bin/env python3
"""Offline publication checks; findings never include matched content."""

import argparse
import ipaddress
import json
import re
import subprocess
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = "publication-manifest.json"
MAX_BYTES = 2_000_000
PUBLIC_GUIDS = {
    "b24988ac-6180-42a0-ab88-20f7382dd24c",  # Azure Contributor.
    "4d97b98b-1d4f-4787-a291-c67834d212e7",  # Azure Network Contributor.
    "9980e02c-c2be-4d73-94e8-173b1dc7cf3c",  # Azure Virtual Machine Contributor.
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",  # Azure Owner.
    "acdd72a7-3385-48ef-bd42-f606fba81ae7",  # Azure Reader.
    "797f4846-ba00-4fd7-ba43-dac1f8f63013",  # Public ARM application audience.
    "0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3",  # Storage Table Data Contributor.
    "4633458b-17de-408a-b874-0445c86b69e6",  # Key Vault Secrets User.
    "b86a8fe4-44ce-4948-aee5-eccb2c155cd7",  # Key Vault Secrets Officer.
    "f1a07417-d97a-45cb-824c-7a7467783830",  # Managed Identity Operator.
    "f25e0fa2-a7c8-4377-a976-54943a77a395",  # Key Vault Contributor.
    "17d1049b-9a84-46fb-8f53-869881c3d3ab",  # Storage Account Contributor.
    "b12aa53e-6015-4669-85d0-8515ebb3ae7f",  # Private DNS Zone Contributor.
    "5d977122-f97e-4b4d-a52f-6b43003ddb4d",  # Azure Container Instances Contributor.
    "ba92f5b4-2d11-453d-a403-e96b0029c9fe",  # Storage Blob Data Contributor.
    "76199698-9eea-4c19-bc75-cec21354c6b6",  # Storage Table Data Reader.
    "de139f84-1756-47ae-9be6-808fbbe84772",  # Website Contributor.
    "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1",  # Storage Blob Data Reader.
    "00000003-0000-0000-c000-000000000000",  # Microsoft Graph application ID.
    "18a4783c-866b-4cc7-a460-3d5e5662c884",  # Graph Application.ReadWrite.OwnedBy.
    "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30",  # Graph Application.Read.All.
    "06b708a9-e830-4db3-a914-8e69da51d44f",  # Graph AppRoleAssignment.ReadWrite.All.
    "db58b8e5-c6ad-4a2a-8342-4190687cbf4a",  # Storage Blob Delegator.
    "e1fe6dd8-ba31-4d61-89e7-88639da4683d",  # Graph User.Read delegated scope.
    "bdfbf15f-ee85-4955-8675-146e8e5296b5",  # Graph Application.ReadWrite.All delegated scope.
    "c79f8feb-a9db-4090-85f9-90d820caa0eb",  # Graph Application.Read.All delegated scope.
    "84bccea3-f856-4a8a-967b-dbe0a3d53a64",  # Graph AppRoleAssignment.ReadWrite.All delegated scope.
}
PUBLIC_ADDRESSES = {
    "0.0.0.0", "1.0.0.0", "1.1.1.0", "1.1.1.1", "8.8.8.8", "9.9.9.9",
    "168.63.129.16", "169.254.169.254",
    "100.64.0.0", "192.0.0.0", "198.18.0.0", "224.0.0.0", "240.0.0.0",
    "192.88.99.0",  # Deprecated IANA 6to4 relay prefix, rejected by public-admin validation.
    "255.255.254.0", "255.255.255.0", "255.255.255.255",  # Standard dotted IPv4 netmasks.
}
PUBLIC_EMAILS = {"noreply@github.com", "owners@odata.bind"}  # Graph property, not an email.
PRIVATE_NETWORKS = tuple(map(ipaddress.ip_network, (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
    "169.254.0.0/16", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
)))
FORBIDDEN_PARTS = {
    ".git", ".azure", ".local", "results", "node_modules", "__pycache__",
    "venv", ".execution-lock", ".secrets.json", "ssh-access", "compiled",
}
FORBIDDEN_SUFFIXES = {
    ".pem", ".key", ".pfx", ".p12", ".cer", ".crt", ".pub", ".jsonl", ".log",
    ".pcap", ".pcapng", ".zip", ".tar", ".gz", ".png", ".jpg", ".jpeg",
}
CHECKPOINT_SSH_PATH = str(PurePosixPath("/home") / "notused" / ".ssh" / "authorized_keys")
CHECKPOINT_SSH_PATH_FILES = {
    "provider-provisioning/service/checkpoint_plan.py",
    "provider-provisioning/tests/test_checkpoint_modules.py",
}
GUID = re.compile(r"\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b")
ENCODED_SUBSCRIPTION_GUID = re.compile(
    r"(?i)%2Fsubscriptions%2F(?P<guid>[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})"
)
ADDRESS = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
EMAIL = re.compile(r"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
RUN_ID = re.compile(r"\b20\d{6}-\d{6}-[0-9a-f]{6}\b")
PATTERNS = (
    ("private-key material", re.compile(r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----")),
    ("certificate material", re.compile("-----BEGIN " + "CERTIFICATE-----")),
    ("JWT-shaped token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,})\b")),
    ("connection-string key", re.compile(r"(?i)(?:AccountKey|SharedAccessKey)\s*=\s*[A-Za-z0-9+/]{20,}={0,2}")),
    ("SAS signature", re.compile(r"(?i)[?&]sig=[A-Za-z0-9%+/=_-]{20,}")),
    ("SSH public identity", re.compile(r"\b(?:ssh-ed25519|ssh-rsa) [A-Za-z0-9+/]{32,}={0,3}")),
    ("workstation home path", re.compile(r"(?:/(?:Users|home)/[A-Za-z0-9_.-]+/|[A-Za-z]:\\Users\\[A-Za-z0-9_.-]+\\)")),
    ("tenant domain", re.compile(r"\b[A-Za-z0-9][A-Za-z0-9.-]*\.onmicrosoft\.com\b", re.I)),
    ("embedded binary data", re.compile(r"data:[A-Za-z0-9/+.-]+;base64,", re.I)),
    ("literal credential", re.compile(
        r"""(?i)["']?(?:client_secret|adminpassword|password|api_key|access_token|refresh_token)["']?\s*[:=]\s*["'][A-Za-z0-9/+_=.-]{16,}["']"""
    )),
)


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    category: str


def git(root, *arguments):
    result = subprocess.run(
        ["git", "--no-pager", *arguments], cwd=root, capture_output=True,
    )
    if result.returncode:
        raise RuntimeError("Git inspection failed; run inside an initialized repository")
    return result.stdout


def valid_path(path):
    item = PurePosixPath(path)
    return (
        isinstance(path, str) and path == item.as_posix() and not item.is_absolute()
        and ".." not in item.parts and "\\" not in path and bool(item.parts)
    )


def manifest_paths(data):
    document = json.loads(data)
    paths = document.get("files")
    if document.get("schemaVersion") != 1 or not isinstance(paths, list):
        raise ValueError("Publication manifest requires schemaVersion 1 and a files array")
    if any(not isinstance(path, str) or not valid_path(path) for path in paths):
        raise ValueError("Publication manifest has an invalid relative path")
    if len(paths) != len(set(paths)) or MANIFEST not in paths:
        raise ValueError("Publication manifest has duplicates or omits itself")
    return set(paths)


def path_findings(path, allowed):
    item = PurePosixPath(path)
    findings = []
    if not valid_path(path) or path not in allowed:
        findings.append(Finding(path, 0, "path outside publication allowlist"))
    if (
        any(part in FORBIDDEN_PARTS or part.startswith(".venv") for part in item.parts)
        or item.suffix.lower() in FORBIDDEN_SUFFIXES
        or item.name in {"config.json", "REPORT.md", ".DS_Store"}
        or item.name.startswith((".env", "id_rsa", "id_ed25519", "known_hosts"))
        or ".local." in item.name
    ):
        findings.append(Finding(path, 0, "private/runtime path"))
    return findings


def scan_content(path, data):
    if len(data) > MAX_BYTES:
        return [Finding(path, 0, "oversized unreviewed file")]
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return [Finding(path, 0, "binary/non-UTF-8 file")]
    findings = []
    for number, line in enumerate(text.splitlines(), 1):
        for category, pattern in PATTERNS:
            matches = list(pattern.finditer(line))
            if category == "workstation home path":
                def permitted(match):
                    if match.group() == "/home/labuser/":
                        return True
                    suffix = line[match.start():]
                    remainder = suffix[len(CHECKPOINT_SSH_PATH):]
                    return (path in CHECKPOINT_SSH_PATH_FILES
                            and suffix.startswith(CHECKPOINT_SSH_PATH)
                            and (not remainder or remainder[0] in "\"' \t,)}]"))
                matches = [match for match in matches if not permitted(match)]
            if matches:
                findings.append(Finding(path, number, category))
        identity_matches = [(match.group(), match.span()) for match in GUID.finditer(line)]
        identity_matches.extend(
            (match.group("guid"), match.span("guid"))
            for match in ENCODED_SUBSCRIPTION_GUID.finditer(line)
            if match.span("guid") not in {span for _, span in identity_matches}
        )
        for raw, span in identity_matches:
            value = raw.lower()
            if value not in PUBLIC_GUIDS and uuid.UUID(value).int > 255:
                findings.append(Finding(path, number, "non-public identity UUID"))
        for match in EMAIL.finditer(line):
            email = match.group().lower()
            domain = email.rsplit("@", 1)[1]
            if not (
                email in PUBLIC_EMAILS or domain == "users.noreply.github.com" or domain.endswith(".example")
                or domain in {"example.com", "example.invalid", "example.test"}
            ):
                findings.append(Finding(path, number, "account email"))
        for match in ADDRESS.finditer(line):
            try:
                address = ipaddress.ip_address(match.group())
            except ValueError:
                continue
            if str(address) not in PUBLIC_ADDRESSES and not any(address in network for network in PRIVATE_NETWORKS):
                findings.append(Finding(path, number, "non-example public IPv4 address"))
        for match in RUN_ID.finditer(line):
            if match.group() != "20000101-000000-000000":
                findings.append(Finding(path, number, "operational run identifier"))
    return findings


def worktree_findings(root):
    allowed = manifest_paths((root / MANIFEST).read_bytes())
    findings = []
    for path in sorted(allowed):
        findings.extend(path_findings(path, allowed))
        target = root / path
        if target.is_symlink() or root.resolve() not in target.resolve().parents:
            findings.append(Finding(path, 0, "symlink/outside-root content"))
        elif not target.is_file():
            findings.append(Finding(path, 0, "missing publication file"))
        else:
            findings.extend(scan_content(path, target.read_bytes()))
    return findings, len(allowed)


def index_entries(root):
    entries = []
    for record in git(root, "ls-files", "--stage", "-z").split(b"\0"):
        if not record:
            continue
        metadata, path = record.split(b"\t", 1)
        mode, blob, stage = metadata.decode().split()
        if stage != "0":
            raise RuntimeError("Resolve index conflicts before publication validation")
        entries.append((mode, blob, path.decode()))
    return entries


def entries_findings(root, entries, allowed):
    findings = []
    for mode, blob, path in entries:
        findings.extend(path_findings(path, allowed))
        if mode not in {"100644", "100755"}:
            findings.append(Finding(path, 0, "symlink/submodule/non-regular entry"))
        else:
            findings.extend(scan_content(path, git(root, "cat-file", "blob", blob)))
    return findings


def staged_findings(root):
    entries = index_entries(root)
    manifests = [blob for _, blob, path in entries if path == MANIFEST]
    if len(manifests) != 1:
        raise RuntimeError("Stage the publication manifest with the reviewed source files first")
    allowed = manifest_paths(git(root, "cat-file", "blob", manifests[0]))
    findings = entries_findings(root, entries, allowed)
    present = {path for _, _, path in entries}
    for path in sorted(allowed - present):
        findings.append(Finding(path, 0, "manifest file missing from index"))
    return findings, len(entries)


def push_revisions(data):
    revisions = set()
    for line in data.splitlines():
        fields = line.split()
        if len(fields) != 4:
            raise ValueError("Invalid pre-push ref update")
        _, local_oid, _, remote_oid = fields
        if any(not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", oid) for oid in (local_oid, remote_oid)):
            raise ValueError("Invalid pre-push object identifier")
        if set(local_oid) != {"0"}:
            revisions.add(local_oid)
    return sorted(revisions)


def history_findings(root, revisions=None):
    findings = []
    if revisions is None:
        selection = ["--branches", "--tags", "--remotes", "--ignore-missing", "HEAD"]
    elif revisions:
        if any(not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", oid) for oid in revisions):
            raise ValueError("History selection requires full object identifiers")
        selection = list(revisions)
    else:
        return findings, 0
    commits = git(root, "rev-list", *selection, "--").decode().splitlines()
    seen = set()
    for commit in commits:
        entries = []
        for record in git(root, "ls-tree", "-r", "-z", commit).split(b"\0"):
            if record:
                metadata, path = record.split(b"\t", 1)
                mode, kind, blob = metadata.decode().split()
                entries.append((mode, blob, path.decode()))
        manifests = [blob for _, blob, path in entries if path == MANIFEST]
        if len(manifests) != 1:
            findings.append(Finding("<history>", 0, "commit lacks publication manifest"))
            continue
        allowed = manifest_paths(git(root, "cat-file", "blob", manifests[0]))
        pending = []
        for entry in entries:
            mode, blob, path = entry
            findings.extend(path_findings(path, allowed))
            if entry not in seen:
                pending.append(entry)
                seen.add(entry)
        findings.extend(entries_findings(root, pending, allowed))
        metadata = git(root, "show", "-s", "--format=%an%n%ae%n%cn%n%ce%n%B", commit)
        findings.extend(scan_content("<commit metadata>", metadata))
    return findings, len(commits)


def safe_label(path):
    path = GUID.sub("<id>", path)
    path = EMAIL.sub("<email>", path)
    path = ADDRESS.sub("<ip>", path)
    return RUN_ID.sub("<run>", path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--worktree", action="store_true", help="Inspect only explicit publication files")
    mode.add_argument("--staged", action="store_true", help="Inspect actual Git index blobs")
    parser.add_argument("--history", action="store_true",
                        help="Inspect branch/tag/remote history and HEAD, excluding unrelated local tool refs")
    parser.add_argument("--pre-push", action="store_true",
                        help="With --history, inspect exactly the outgoing ref tips supplied by Git on stdin")
    args = parser.parse_args()
    if args.pre_push and not args.history:
        parser.error("--pre-push requires --history")
    findings, files = staged_findings(ROOT) if args.staged else worktree_findings(ROOT)
    commits = 0
    if args.history:
        revisions = push_revisions(sys.stdin.read()) if args.pre_push else None
        historical, commits = history_findings(ROOT, revisions)
        findings.extend(historical)
    for finding in sorted(set(findings), key=lambda item: (item.path, item.line, item.category)):
        print(f"BLOCK: {safe_label(finding.path)}:{finding.line}: {finding.category}", file=sys.stderr)
    if findings:
        print("Publication blocked. Matched content was not printed.", file=sys.stderr)
        return 1
    print(f"PASS: {files} publication files; {commits} historical commits inspected. No cloud/network calls.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        print("ERROR: publication validation could not complete:", type(error).__name__, file=sys.stderr)
        sys.exit(1)
