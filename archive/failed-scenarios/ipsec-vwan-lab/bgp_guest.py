"""Default-only BGP, dynamic customer routing and fail-closed probe scripts."""

import ipaddress
import json

from guest_tools import result_script


def configure_script(settings, private_ip, peers):
    for address in [private_ip, settings["providerBgpIp"], *[row["azureBgpIp"] for row in peers]]:
        ipaddress.IPv4Address(address)
    if len(peers) != 2 or settings["advertiseToCustomer"] != ["0.0.0.0/0"]:
        raise ValueError("Expected two BGP peers and a default-only export")
    values = {
        "settings": {key: settings[key] for key in (
            "providerAsn", "azureAsn", "providerBgpIp", "acceptedCustomerAggregates",
        )},
        "privateIp": private_ip, "peers": peers,
    }
    return ["set -eu", "apt-get update", "DEBIAN_FRONTEND=noninteractive apt-get install -y frr",
            *result_script(r'''
import json
import os
import re
import subprocess
from pathlib import Path
values = VALUES
settings, peers = values["settings"], values["peers"]
def run(*args):
    subprocess.run(list(args), check=True, capture_output=True, text=True)
if settings["providerBgpIp"] != values["privateIp"]:
    raise RuntimeError("BGP source must be the simulator's existing private interface address")
for index, peer in enumerate(peers):
    run("ip", "route", "replace", peer["azureBgpIp"] + "/32", "dev", "xfrm" + str(index))
for prefix in settings["acceptedCustomerAggregates"]:
    run("ip", "route", "replace", "blackhole", prefix, "metric", "42760")
guard = ["iptables", "-w", "-C", "IV_FORWARD", "-i", "xfrm+", "!", "-o", "xfrm+", "-j", "DROP"]
exists = subprocess.run(guard, capture_output=True)
if exists.returncode not in (0, 1):
    raise RuntimeError("Cannot inspect the fail-closed tunnel-interface guard")
if exists.returncode:
    run("iptables", "-w", "-I", "IV_FORWARD", "1", "-i", "xfrm+", "!", "-o", "xfrm+", "-j", "DROP")
lines = [
    "frr defaults traditional",
    "hostname ipsec-lab",
    "service integrated-vtysh-config",
    "ip prefix-list DEFAULT-ONLY seq 10 permit 0.0.0.0/0",
]
for index, prefix in enumerate(settings["acceptedCustomerAggregates"], 1):
    lines.append("ip prefix-list CUSTOMER-ROUTES seq " + str(index * 10) + " permit " + prefix + " le 32")
lines += ["route-map DEFAULT-ONLY permit 10", " match ip address prefix-list DEFAULT-ONLY",
          "router bgp " + str(settings["providerAsn"]), " bgp router-id " + values["privateIp"]]
for peer in peers:
    neighbor = " neighbor " + peer["azureBgpIp"]
    lines += [neighbor + " remote-as " + str(settings["azureAsn"]),
              neighbor + " update-source " + settings["providerBgpIp"],
              neighbor + " ebgp-multihop 2", neighbor + " timers 10 30"]
lines += [" address-family ipv4 unicast", "  maximum-paths 2"]
for peer in peers:
    neighbor = "  neighbor " + peer["azureBgpIp"]
    lines += [neighbor + " activate", neighbor + " default-originate",
              neighbor + " route-map DEFAULT-ONLY out", neighbor + " prefix-list CUSTOMER-ROUTES in"]
lines += [" exit-address-family", "!"]
path = Path("/etc/frr/frr.conf")
path.write_text("\n".join(lines) + "\n")
run("chown", "frr:frr", str(path))
run("chmod", "640", str(path))
path = Path("/etc/frr/daemons")
text = path.read_text()
for daemon in ("zebra", "bgpd"):
    if re.search(r"^" + daemon + "=", text, re.M):
        text = re.sub(r"^" + daemon + "=.*$", daemon + "=yes", text, flags=re.M)
    else:
        text += "\n" + daemon + "=yes\n"
path.write_text(text)
run("systemctl", "enable", "frr")
run("systemctl", "restart", "frr")
print("FAAS_RESULT_BEGIN")
print(json.dumps([{"ok": True, "export": ["0.0.0.0/0"], "perVnetRoutesConfigured": False}]))
print("FAAS_RESULT_END")
'''.replace("VALUES", repr(values)))]


def metrics_script(peers):
    return result_script(r'''
import hashlib
import json
import subprocess
from pathlib import Path
peers = PEERS
def query(command):
    return json.loads(subprocess.check_output(["vtysh", "-c", command], text=True))
summary = query("show bgp ipv4 unicast summary json")
family = summary.get("ipv4Unicast", summary)
if not isinstance(family.get("peers"), dict):
    raise RuntimeError("Unsupported or missing FRR peer-summary response")
routes = query("show bgp ipv4 unicast json")
if not isinstance(routes.get("routes"), dict):
    raise RuntimeError("Unsupported or missing FRR IPv4 routing table")
neighbors = {}
for peer in peers:
    address = peer["azureBgpIp"]
    row = family["peers"].get(address)
    if not isinstance(row, dict):
        raise RuntimeError("Configured Azure BGP neighbor is missing")
    if row.get("state") != "Established":
        neighbors[address] = {
            "state": row.get("state"), "remoteAs": row.get("remoteAs"),
            "receivedPrefixes": row.get("pfxRcd"), "advertised": [],
            "advertisementStatus": "neighbor-not-established",
        }
        continue
    advertised = query("show bgp ipv4 unicast neighbors " + address + " advertised-routes json")
    prefixes = advertised.get("advertisedRoutes")
    if not isinstance(prefixes, dict):
        raise RuntimeError("Unsupported or missing FRR advertised-route response")
    exported = set(prefixes)
    if advertised.get("bgpOriginatingDefaultNetwork") == "0.0.0.0/0":
        exported.add("0.0.0.0/0")
    neighbors[address] = {
        "state": row.get("state"), "remoteAs": row.get("remoteAs"),
        "receivedPrefixes": row.get("pfxRcd"), "advertised": sorted(exported),
    }
digests = {}
for name in ("/etc/frr/frr.conf", "/etc/swanctl/conf.d/ipsec-lab.conf"):
    digests[name] = hashlib.sha256(Path(name).read_bytes()).hexdigest()
rules = subprocess.check_output(["iptables-save", "-t", "filter"], text=True)
digests["firewallRules"] = hashlib.sha256(
    "\n".join(line for line in rules.splitlines() if line.startswith("-A ")).encode()
).hexdigest()
ready = all(row["state"] == "Established" and row["advertised"] == ["0.0.0.0/0"] for row in neighbors.values())
print("FAAS_RESULT_BEGIN")
print(json.dumps([{"ok": ready, "neighbors": neighbors, "learnedPrefixes": sorted(routes["routes"]),
                  "configurationDigests": digests}]))
print("FAAS_RESULT_END")
'''.replace("PEERS", repr(peers)))


def default_script(peers, advertise):
    return result_script(r'''
import json
import subprocess
commands = ["vtysh", "-c", "configure terminal", "-c", "router bgp 65010", "-c", "address-family ipv4 unicast"]
for peer in PEERS:
    commands += ["-c", ("neighbor " if ADVERTISE else "no neighbor ") + peer["azureBgpIp"] + " default-originate"]
subprocess.run(commands, check=True, capture_output=True, text=True)
print("FAAS_RESULT_BEGIN")
print(json.dumps([{"ok": True, "defaultAdvertised": ADVERTISE}]))
print("FAAS_RESULT_END")
'''.replace("PEERS", repr(peers)).replace("ADVERTISE", repr(advertise)))


def tunnel_control_script(enabled):
    source = r'''
import json
import subprocess
subprocess.run(["systemctl", "ACTION", "strongswan"], check=True, capture_output=True, text=True)
if ENABLED:
    subprocess.run(["swanctl", "--load-all"], check=True, capture_output=True, text=True)
print("FAAS_RESULT_BEGIN")
print(json.dumps([{"ok": True, "ipsecEnabled": ENABLED}]))
print("FAAS_RESULT_END")
'''
    return result_script(source.replace("ACTION", "start" if enabled else "stop").replace("ENABLED", repr(enabled)))


def local_health_script():
    return result_script(r'''
import json
import urllib.request
with urllib.request.urlopen("http://127.0.0.1:8080/health", timeout=5) as response:
    body = json.load(response)
print("FAAS_RESULT_BEGIN")
print(json.dumps([{"ok": response.status == 200, "hostname": body["hostname"]}]))
print("FAAS_RESULT_END")
''')
