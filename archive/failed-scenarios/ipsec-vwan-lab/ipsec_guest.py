"""Owned simulator bootstrap and bounded private traffic probes."""

import ipaddress
import json

from guest_tools import SERVER, result_script


def bootstrap(firewall):
    lines = ["#!/bin/bash", "set -euo pipefail", "exec > >(tee -a /var/log/ipsec-lab-bootstrap.log) 2>&1"]
    if firewall:
        lines += [
            "apt-get update",
            "DEBIAN_FRONTEND=noninteractive apt-get install -y strongswan-swanctl charon-systemd tcpdump",
        ]
    else:
        lines += [
            "mkdir -p /opt/ipsec-lab",
            "cat > /opt/ipsec-lab/server.py <<'IPSEC_SERVER'", SERVER, "IPSEC_SERVER",
            "cat > /etc/systemd/system/ipsec-lab-http.service <<'IPSEC_UNIT'",
            "[Unit]", "Description=Private IPsec lab endpoint", "After=network.target",
            "[Service]", "ExecStart=/usr/bin/python3 /opt/ipsec-lab/server.py",
            "User=nobody", "NoNewPrivileges=true", "PrivateTmp=true", "ProtectSystem=strict",
            "Restart=on-failure", "[Install]", "WantedBy=multi-user.target", "IPSEC_UNIT",
            "systemctl daemon-reload", "systemctl enable --now ipsec-lab-http.service",
        ]
    return "\n".join(lines + ["printf 'IPSEC_BOOTSTRAP_OK\\n'"]) + "\n"


def tunnel_script(private_ip, public_ip, peers, prefixes, static_routes=True, allow_within_prefix=False):
    if len(peers) != 2 or len(set(peers)) != 2:
        raise ValueError("Both distinct active-active gateway endpoints are required")
    for address in [private_ip, public_ip, *peers]:
        ipaddress.IPv4Address(address)
    for prefix in prefixes:
        if not ipaddress.ip_network(prefix).is_private:
            raise ValueError("Only private customer prefixes may be routed into the lab tunnel")
    values = {"private": private_ip, "public": public_ip, "peers": peers, "prefixes": prefixes,
              "staticRoutes": static_routes, "allowWithinPrefix": allow_within_prefix}
    source = r'''
import json
import os
import re
import subprocess
import sys
from pathlib import Path
settings = SETTINGS
key = sys.argv[1]
if not re.fullmatch("[0-9a-f]{64}", key):
    raise ValueError("Invalid protected per-run VPN key")
def run(*args):
    subprocess.run(list(args), check=True, capture_output=True, text=True)
underlay = json.loads(subprocess.check_output(["ip", "-j", "route", "get", settings["peers"][0]]))[0]["dev"]
if underlay.startswith("xfrm"):
    raise RuntimeError("VPN underlay is incorrectly routed into its own tunnel")
connections = []
for index, peer in enumerate(settings["peers"]):
    name, interface, identifier = "azure-" + str(index), "xfrm" + str(index), 42 + index
    exists = subprocess.run(["ip", "link", "show", interface], capture_output=True)
    if exists.returncode:
        run("ip", "link", "add", interface, "type", "xfrm", "dev", underlay, "if_id", str(identifier))
    else:
        record = json.loads(subprocess.check_output(["ip", "-j", "-d", "link", "show", interface]))[0]
        if record["linkinfo"]["info_kind"] != "xfrm":
            raise RuntimeError("Refusing to reuse an unrelated network interface")
    run("ip", "link", "set", interface, "mtu", "1400", "up")
    connections.append("""
    NAME {
      version = 2
      local_addrs = PRIVATE
      remote_addrs = PEER
      proposals = aes256-sha256-modp2048
      encap = yes
      dpd_delay = 20s
      local { auth = psk
              id = PUBLIC }
      remote { auth = psk
               id = PEER }
      children {
        net {
          local_ts = 0.0.0.0/0
          remote_ts = 0.0.0.0/0
          if_id_in = IDENTIFIER
          if_id_out = IDENTIFIER
          esp_proposals = aes256-sha256-modp2048
          start_action = start
          dpd_action = restart
          rekey_time = 3000s
          life_time = 3600s
        }
      }
    }
""".replace("NAME", name).replace("PRIVATE", settings["private"])
       .replace("PUBLIC", settings["public"]).replace("PEER", peer).replace("IDENTIFIER", str(identifier)))
text = "connections {\n" + "\n".join(connections) + "\n}\n"
text += 'secrets { ike-lab { id = ' + settings["public"] + '\nsecret = "' + key + '"\n} }\n'
path = Path("/etc/swanctl/conf.d/ipsec-lab.conf")
path.parent.mkdir(parents=True, exist_ok=True)
descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(descriptor, "w") as stream:
    stream.write(text)
run("chmod", "600", str(path))
Path("/etc/strongswan.d/ipsec-lab.conf").write_text(
    "charon { plugins { kernel-netlink {\ninstall_routes = no\ninstall_routes_xfrmi = no\n} } }\n"
)
for name in ("net.ipv4.ip_forward", "net.ipv4.conf.all.rp_filter", "net.ipv4.conf.default.rp_filter"):
    run("sysctl", "-w", name + ("=1" if name.endswith("ip_forward") else "=0"))
for path in Path("/proc/sys/net/ipv4/conf").glob("*/rp_filter"):
    path.write_text("0\n")
for chain in ("IV_FORWARD", "IV_NEGATIVE", "IV_COUNT"):
    result = subprocess.run(["iptables", "-w", "-nL", chain], capture_output=True)
    run("iptables", "-w", "-F" if result.returncode == 0 else "-N", chain)
run("iptables", "-w", "-A", "IV_COUNT", "-j", "RETURN")
run("iptables", "-w", "-A", "IV_FORWARD", "-j", "IV_NEGATIVE")
run("iptables", "-w", "-A", "IV_FORWARD", "-i", "xfrm+", "-o", "xfrm+", "-p", "tcp",
    "--dport", "8080", "--syn", "-j", "IV_COUNT")
run("iptables", "-w", "-A", "IV_FORWARD", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
for source in settings["prefixes"]:
    for destination in settings["prefixes"]:
        if source == destination and not settings["allowWithinPrefix"]:
            continue
        for protocol in ("tcp", "icmp"):
            rule = ["iptables", "-w", "-A", "IV_FORWARD", "-i", "xfrm+", "-o", "xfrm+",
                    "-s", source, "-d", destination, "-p", protocol]
            if protocol == "tcp":
                rule += ["--dport", "8080"]
            run(*(rule + ["-j", "ACCEPT"]))
run("iptables", "-w", "-A", "IV_FORWARD", "-j", "DROP")
check = subprocess.run(["iptables", "-w", "-C", "FORWARD", "-j", "IV_FORWARD"], capture_output=True)
if check.returncode not in (0, 1):
    raise RuntimeError("Cannot inspect firewall forwarding hook")
if check.returncode == 1:
    run("iptables", "-w", "-I", "FORWARD", "1", "-j", "IV_FORWARD")
if settings["staticRoutes"]:
    for prefix in settings["prefixes"]:
        run("ip", "route", "replace", prefix, "dev", "xfrm0")
run("systemctl", "enable", "strongswan")
run("systemctl", "restart", "strongswan")
run("swanctl", "--load-all")
print("IPSEC_CONFIGURED")
'''
    return ["set -eu", "python3 - \"$1\" <<'IPSEC_CONFIG'", source.replace("SETTINGS", repr(values)), "IPSEC_CONFIG"]


def metrics_script():
    return result_script(r'''
import json
import re
import subprocess
sas = subprocess.check_output(["swanctl", "--list-sas"], text=True)
counter = subprocess.check_output(["iptables", "-w", "-nvxL", "IV_COUNT"], text=True)
rows = [line.split() for line in counter.splitlines() if "RETURN" in line]
if len(rows) != 1:
    raise RuntimeError("Missing or ambiguous forwarding SYN counter")
ready = all(
    re.search(r"azure-" + str(index) + r":[^\n]*\bESTABLISHED\b(?:(?!\nazure-\d+:).)*\bINSTALLED\b", sas, re.S)
    for index in (0, 1)
)
counters = {}
current = None
for line in sas.splitlines():
    peer = re.match(r"azure-(\d+):", line)
    if peer:
        current = peer.group(1)
        counters[current] = {}
    traffic = re.search(r"\b(in|out)\s+[0-9a-f]+(?:\s+\([^)]*\))?,\s+(\d+)\s+bytes,\s+(\d+)\s+packets", line)
    if current is not None and traffic:
        direction, size, packets = traffic.groups()
        counters[current][direction + "Bytes"] = int(size)
        counters[current][direction + "Packets"] = int(packets)
complete = set(counters) == {"0", "1"} and all(
    all(key in row for key in ("inBytes", "inPackets", "outBytes", "outPackets"))
    for row in counters.values()
)
result = [{"ok": bool(ready and complete), "sas": sas, "synCount": int(rows[0][0]), "tunnelCounters": counters}]
print("FAAS_RESULT_BEGIN")
print(json.dumps(result))
print("FAAS_RESULT_END")
''')


def block_script(enabled):
    return result_script(r'''
import json
import subprocess
subprocess.run(["iptables", "-w", "-F", "IV_NEGATIVE"], check=True)
if ENABLED:
    subprocess.run(["iptables", "-w", "-A", "IV_NEGATIVE", "-p", "tcp", "--dport", "8080", "-j", "DROP"], check=True)
print("FAAS_RESULT_BEGIN")
print(json.dumps([{"ok": True, "blocked": ENABLED}]))
print("FAAS_RESULT_END")
'''.replace("ENABLED", repr(enabled)))


def prefer_tunnel_script(index, prefixes):
    if index not in (0, 1):
        raise ValueError("Only the two actual managed gateway tunnels may be selected")
    return result_script(r'''
import json
import subprocess
for prefix in PREFIXES:
    subprocess.run(["ip", "route", "replace", prefix, "dev", "INTERFACE"], check=True)
print("FAAS_RESULT_BEGIN")
print(json.dumps([{"ok": True, "preferredTunnel": INDEX}]))
print("FAAS_RESULT_END")
'''.replace("PREFIXES", repr(prefixes)).replace("INTERFACE", "xfrm" + str(index)).replace("INDEX", str(index)))


def ping_script(destination):
    ipaddress.IPv4Address(destination)
    return result_script(r'''
import json
import re
import subprocess
result = subprocess.run(["ping", "-c", "3", "-W", "2", "-t", "8", "DESTINATION"], capture_output=True, text=True)
passed = result.returncode == 0 and bool(re.search(r"3 packets transmitted,\s*3 received,\s*0% packet loss", result.stdout))
print("FAAS_RESULT_BEGIN")
print(json.dumps([{"ok": passed, "exitCode": result.returncode, "output": result.stdout + result.stderr}]))
print("FAAS_RESULT_END")
'''.replace("DESTINATION", destination))
