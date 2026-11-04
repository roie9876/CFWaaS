"""Guest configuration for the two isolated Ubuntu firewall simulators."""

import ipaddress
import json

from guest_tools import SERVER


def bootstrap(node, own_prefixes, other_prefixes):
    lines = [
        "#!/bin/bash", "set -euo pipefail",
        "exec > >(tee -a /var/log/avnm-faas-bootstrap.log) 2>&1",
        "mkdir -p /opt/faas",
        "cat > /opt/faas/server.py <<'AVNM_SERVER'", SERVER, "AVNM_SERVER",
        "cat > /etc/systemd/system/faas-http.service <<'AVNM_UNIT'",
        "[Unit]", "Description=AVNM isolated test endpoint", "After=network.target",
        "[Service]", "ExecStart=/usr/bin/python3 /opt/faas/server.py",
        "User=nobody", "NoNewPrivileges=true", "PrivateTmp=true", "ProtectSystem=strict",
        "Restart=on-failure", "StandardOutput=journal",
        "[Install]", "WantedBy=multi-user.target", "AVNM_UNIT",
    ]
    if node["firewall"]:
        lines += firewall_rules(own_prefixes, other_prefixes)
    lines += [
        "systemctl daemon-reload", "systemctl enable --now faas-http.service",
        "printf 'AVNM_BOOTSTRAP_OK\\n'",
    ]
    return "\n".join(lines) + "\n"


def firewall_rules(own_prefixes, other_prefixes):
    for prefix in own_prefixes + other_prefixes:
        if ipaddress.ip_network(prefix).version != 4:
            raise ValueError("IPv4 prefixes are required")
    lines = [
        "if ! command -v iptables >/dev/null 2>&1; then",
        "  echo 'Installing the missing lab forwarding dependency: iptables'",
        "  apt-get update", "  DEBIAN_FRONTEND=noninteractive apt-get install -y iptables",
        "fi",
        "printf 'net.ipv4.ip_forward=1\\nnet.ipv4.conf.all.rp_filter=0\\nnet.ipv4.conf.default.rp_filter=0\\n' > /etc/sysctl.d/90-avnm-faas.conf",
        "sysctl --system",
        "for setting in /proc/sys/net/ipv4/conf/*/rp_filter; do printf 0 > \"$setting\"; done",
    ]
    for chain in ("AF_FORWARD", "AF_OWN", "AF_ISOLATE"):
        lines += [
            f"if iptables -w -nL {chain} >/dev/null 2>&1; then",
            f"  iptables -w -F {chain}",
            "else",
            f"  iptables -w -N {chain}",
            "fi",
        ]
    lines += [
        "iptables -w -A AF_OWN -j ACCEPT",
        "iptables -w -A AF_ISOLATE -j DROP",
        "if ! iptables -w -C FORWARD -j AF_FORWARD >/dev/null 2>&1; then iptables -w -I FORWARD 1 -j AF_FORWARD; fi",
        "iptables -w -A AF_FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
    ]
    for source in own_prefixes:
        for destination in own_prefixes:
            lines += [
                f"iptables -w -A AF_FORWARD -s {source} -d {destination} -p tcp --dport 8080 -j AF_OWN",
                f"iptables -w -A AF_FORWARD -s {source} -d {destination} -p icmp -j AF_OWN",
            ]
        for destination in other_prefixes:
            lines.append(f"iptables -w -A AF_FORWARD -s {source} -d {destination} -j AF_ISOLATE")
        for destination in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"):
            lines.append(f"iptables -w -A AF_FORWARD -s {source} -d {destination} -j DROP")
        for ports, protocol in (("80,443", "tcp"), ("53", "udp")):
            lines.append(
                f"iptables -w -A AF_FORWARD -s {source} -p {protocol} -m multiport --dports {ports} -j ACCEPT"
            )
    lines += [
        "iptables -w -A AF_FORWARD -j DROP",
        "if iptables -w -t nat -nL AF_NAT >/dev/null 2>&1; then iptables -w -t nat -F AF_NAT; else iptables -w -t nat -N AF_NAT; fi",
        "if ! iptables -w -t nat -C POSTROUTING -j AF_NAT >/dev/null 2>&1; then iptables -w -t nat -A POSTROUTING -j AF_NAT; fi",
    ]
    for destination in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"):
        lines.append(f"iptables -w -t nat -A AF_NAT -d {destination} -j RETURN")
    for source in own_prefixes:
        lines.append(f"iptables -w -t nat -A AF_NAT -s {source} -j MASQUERADE")
    return lines


def metrics_script():
    return ["python3 - <<'AVNM_METRICS'", r'''
import json
import re
import subprocess
rules = subprocess.run(["iptables-save", "-c", "-t", "filter"], check=True,
                       capture_output=True, text=True).stdout
def packets(chain, target):
    pattern = r"^\[(\d+):\d+\] -A " + chain + r" -j " + target + r"$"
    matches = re.findall(pattern, rules, re.M)
    if len(matches) != 1:
        raise RuntimeError("Expected one counter rule in " + chain)
    return int(matches[0])
print("FAAS_RESULT_BEGIN")
print(json.dumps([{"ok": True, "kind": "firewall-counters",
                  "ownAccepted": packets("AF_OWN", "ACCEPT"),
                  "crossDropped": packets("AF_ISOLATE", "DROP")}]))
print("FAAS_RESULT_END")
''', "AVNM_METRICS"]


def targets_for(source, workloads, run_id, phase):
    return [{
        "test": source["name"] + "-to-" + destination["name"],
        "host": destination["privateIp"], "port": 8080,
        "path": f"/avnm/{run_id}/{phase}/{source['name']}/{destination['name']}",
    } for destination in workloads if destination["name"] != source["name"]]


def block_script(enabled):
    source = r'''
import subprocess
rule = ["-p", "tcp", "--dport", "8080", "-m", "comment",
        "--comment", "avnm-faas-negative-control", "-j", "DROP"]
check = subprocess.run(["iptables", "-w", "-C", "FORWARD"] + rule, capture_output=True, text=True)
if check.returncode not in (0, 1):
    raise RuntimeError("Cannot inspect the negative-control rule: " + check.stderr)
enabled = ENABLED
if enabled and check.returncode == 1:
    subprocess.run(["iptables", "-w", "-I", "FORWARD", "1"] + rule, check=True)
elif not enabled and check.returncode == 0:
    subprocess.run(["iptables", "-w", "-D", "FORWARD"] + rule, check=True)
print("AVNM_NEGATIVE_CONTROL_ON" if enabled else "AVNM_NEGATIVE_CONTROL_OFF")
'''
    return ["python3 - <<'AVNM_BLOCK'", source.replace("ENABLED", repr(enabled)), "AVNM_BLOCK"]


def evaluate(source, targets, measured, workloads, blocked_groups):
    expected = {target["test"] for target in targets}
    if len(measured) != len(targets) or {row.get("test") for row in measured} != expected:
        raise RuntimeError("Every directed traffic test must be reported exactly once")
    results = []
    destinations = {row["name"]: row for row in workloads}
    for item in measured:
        if not isinstance(item.get("ok"), bool):
            raise RuntimeError("Guest test ok must be a Boolean")
        name = item["test"].split("-to-", 1)[1]
        destination = destinations[name]
        same_group = source["group"] == destination["group"]
        allowed = same_group and source["group"] not in blocked_groups
        body = item.get("body")
        if allowed:
            passed = item["ok"] and isinstance(body, dict) and (
                body.get("hostname") == "vm-" + destination["name"]
                and body.get("client_ip") == source["privateIp"]
            )
        else:
            passed = item["ok"] is False and item.get("errorType") in {"TimeoutError", "timeout"}
        results.append({
            **item, "source": source["name"], "destination": name, "sameGroup": same_group,
            "expectedAllowed": allowed, "passed": bool(passed),
        })
    return results
