#!/usr/bin/env python3
"""East-west performance test between two customer workload VMs.

Runs entirely through `az vm run-command`, so no SSH or inbound access is needed. It measures:
  * TCP throughput (iperf3) for several parallel-stream counts, in both directions;
  * ICMP round-trip latency percentiles (p50/p90/p99/p99.9/max), idle and under iperf3 load.

See docs/ew-performance-test-plan.md for the test plan and how to read the results.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import datetime
import json
import pathlib
import subprocess
import sys
import time

IPERF_PORT = 5201

# Executed on the workload VMs (Ubuntu, as root via run-command). Prints one "RESULT <json>" line per measurement.
AGENT = r'''
import json, math, os, re, subprocess, sys, time
mode, args = sys.argv[1], json.loads(sys.argv[2])

def emit(**kw):
    print("RESULT " + json.dumps(kw), flush=True)

def sh(cmd, timeout=None):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)

def percentiles(values, total):
    values = sorted(values)
    def pick(p):
        if not values:
            return None
        return round(values[min(len(values) - 1, max(0, math.ceil(p / 100 * len(values)) - 1))], 3)
    return {"sent": total, "received": len(values),
            "loss_pct": round(100 * (total - len(values)) / total, 3) if total else None,
            "min": pick(0.0001), "p50": pick(50), "p90": pick(90), "p99": pick(99), "p99.9": pick(99.9),
            "max": round(values[-1], 3) if values else None,
            "avg": round(sum(values) / len(values), 3) if values else None}

def ping(peer, count, interval, size):
    out = sh(f"ping -n -c {count} -i {interval} -s {size} -W 1 {peer}", timeout=count * interval + 120).stdout
    rtts = [float(x) for x in re.findall(r"time=([0-9.]+) ms", out)]
    return percentiles(rtts, count)

ECHO_SERVER = """
import os, socket, sys, threading
def serve(conn):
    with conn:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        while True:
            data = conn.recv(256)
            if not data:
                return
            conn.sendall(data)
listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("0.0.0.0", int(sys.argv[1])))
listener.listen(512)
while True:
    conn, _ = listener.accept()
    threading.Thread(target=serve, args=(conn,), daemon=True).start()
"""

def tcp_rtt(peer, port, count, interval, persistent, payload=b"x" * 32):
    import socket
    rtts, sock, start = [], None, time.perf_counter()
    def connect():
        conn = socket.create_connection((peer, port), timeout=1)
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return conn
    def exchange(conn):
        conn.sendall(payload)
        received = 0
        while received < len(payload):
            chunk = conn.recv(len(payload) - received)
            if not chunk:
                raise OSError("closed")
            received += len(chunk)
    for index in range(count):
        delay = start + index * interval - time.perf_counter()
        if delay > 0:
            time.sleep(delay)
        began = time.perf_counter()
        try:
            if persistent:
                sock = sock or connect()
                exchange(sock)
            else:
                with connect() as conn:
                    exchange(conn)
            rtts.append((time.perf_counter() - began) * 1000)
        except OSError:
            if sock:
                sock.close()
            sock = None
    if sock:
        sock.close()
    return percentiles(rtts, count)

if mode == "prepare":
    if sh("command -v iperf3").returncode != 0:
        sh("DEBIAN_FRONTEND=noninteractive apt-get -qq update && "
           "DEBIAN_FRONTEND=noninteractive apt-get -qq install -y iperf3", timeout=600)
    sh("pkill -x iperf3; sleep 1")
    started = sh(f"iperf3 -s -D -p {args['port']}").returncode == 0
    echo = None
    if args.get("tcp_port"):
        with open("/tmp/ew_tcp_echo.py", "w") as handle:
            handle.write(ECHO_SERVER)
        sh("pkill -f '[e]w_tcp_echo.py'; sleep 1")
        sh(f"setsid nohup python3 /tmp/ew_tcp_echo.py {args['tcp_port']} >/dev/null 2>&1 < /dev/null &")
        time.sleep(1)
        echo = sh(f"timeout 3 bash -c '</dev/tcp/127.0.0.1/{args['tcp_port']}'").returncode == 0
    mtu = sh("cat /sys/class/net/eth0/mtu").stdout.strip()
    emit(test="prepare", iperf3=sh("iperf3 --version | head -1").stdout.strip(), server_started=started, mtu=mtu,
         kernel=sh("uname -r").stdout.strip(), cpus=os.cpu_count(), tcp_echo_started=echo)

elif mode == "preflight":
    peer = args["peer"]
    tcp = sh(f"timeout 5 bash -c '</dev/tcp/{peer}/{args['port']}'").returncode == 0
    emit(test="preflight", peer=peer, tcp_port_open=tcp, icmp=ping(peer, 5, 0.2, 56))

elif mode == "throughput":
    peer, duration = args["peer"], args["duration"]
    for streams in args["streams"]:
        for reverse in (False, True):
            cmd = f"iperf3 -c {peer} -p {args['port']} -P {streams} -t {duration} -O 3 -J"
            cmd += " -R" if reverse else ""
            cmd += f" -M {args['mss']}" if args.get("mss") else ""
            proc = sh(cmd, timeout=duration + 60)
            try:
                data = json.loads(proc.stdout)
                end = data["end"]
                emit(test="throughput", streams=streams, direction="reverse" if reverse else "forward",
                     sent_gbps=round(end["sum_sent"]["bits_per_second"] / 1e9, 3),
                     received_gbps=round(end["sum_received"]["bits_per_second"] / 1e9, 3),
                     retransmits=end["sum_sent"].get("retransmits"),
                     cpu_local=round(end["cpu_utilization_percent"]["host_total"], 1),
                     cpu_remote=round(end["cpu_utilization_percent"]["remote_total"], 1),
                     error=data.get("error"))
            except Exception as exc:
                emit(test="throughput", streams=streams, direction="reverse" if reverse else "forward",
                     error=f"{type(exc).__name__}: {proc.stderr.strip()[:200] or proc.stdout.strip()[:200]}")
            time.sleep(3)

elif mode == "latency":
    peer, count, interval, size = args["peer"], args["count"], args["interval"], args["size"]
    if not args.get("skip_ping"):
        emit(test="latency", method="icmp", load="idle", size=size, **ping(peer, count, interval, size))
    if args.get("load_streams"):
        seconds = int(count * interval) + 15
        load = subprocess.Popen(f"iperf3 -c {peer} -p {args['port']} -P {args['load_streams']} -t {seconds} -J",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        time.sleep(5)
        result = ping(peer, count, interval, size)
        out, _ = load.communicate(timeout=seconds + 60)
        try:
            gbps = round(json.loads(out)["end"]["sum_received"]["bits_per_second"] / 1e9, 3)
        except Exception:
            gbps = None
        emit(test="latency", load=f"iperf3 -P {args['load_streams']}", load_gbps=gbps, size=size, **result)

elif mode == "tcp-latency":
    peer, port, count, interval = args["peer"], args["tcp_port"], args["count"], args["interval"]
    persistent = args["method"] == "tcp-open"
    emit(test="latency", method=args["method"], load="idle", size=32,
         **tcp_rtt(peer, port, count, interval, persistent))
'''


TRANSIENT = ("Failed to resolve", "Connection aborted", "Connection reset", "Max retries exceeded",
             "Temporary failure in name resolution", "timed out")


def az(*arguments: str, timeout: int = 7200, attempts: int = 3) -> str:
    for attempt in range(1, attempts + 1):
        proc = subprocess.run(["az", *arguments, "--only-show-errors"], capture_output=True, text=True,
                              timeout=timeout)
        if proc.returncode == 0:
            return proc.stdout
        if attempt < attempts and any(text in proc.stderr for text in TRANSIENT):
            log(f"  transient az error, retrying ({attempt}/{attempts - 1}): {proc.stderr.strip()[:120]}")
            time.sleep(30)
            continue
        raise RuntimeError(f"az {' '.join(arguments[:3])} failed: {proc.stderr.strip()[:500]}")
    raise AssertionError("unreachable")


def run_agent(ctx: argparse.Namespace, vm: str, mode: str, args: dict) -> list[dict]:
    encoded = base64.b64encode(AGENT.encode()).decode()
    script = f"echo {encoded} | base64 -d > /tmp/ew_perf_agent.py && python3 /tmp/ew_perf_agent.py {mode} '{json.dumps(args)}'"
    message = az("vm", "run-command", "invoke", "--subscription", ctx.subscription, "-g", ctx.resource_group,
                 "-n", vm, "--command-id", "RunShellScript", "--scripts", script,
                 "--query", "value[0].message", "-o", "tsv")
    results = [json.loads(line[7:]) for line in message.splitlines() if line.startswith("RESULT ")]
    if not results:
        raise RuntimeError(f"{vm} {mode}: no results. Output:\n{message[-1500:]}")
    for item in results:
        item["vm"] = vm
    return results


def vm_details(ctx: argparse.Namespace, vm: str) -> dict:
    data = json.loads(az("vm", "show", "-d", "--subscription", ctx.subscription, "-g", ctx.resource_group,
                         "-n", vm, "--query", "{ip:privateIps,size:hardwareProfile.vmSize,power:powerState}",
                         "-o", "json"))
    return {"name": vm, "ip": data["ip"].split(",")[0], "size": data["size"], "power": data["power"]}


def log(text: str) -> None:
    print(f"[{datetime.datetime.now():%H:%M:%S}] {text}", flush=True)


def report(meta: dict, results: list[dict]) -> str:
    lines = [f"# East-west performance results ({meta['started']})", "",
             f"- Client: `{meta['client']['name']}` {meta['client']['ip']} ({meta['client']['size']})",
             f"- Server: `{meta['server']['name']}` {meta['server']['ip']} ({meta['server']['size']})",
             f"- iperf3 duration per test: {meta['duration']} s; ping samples: {meta['ping_count']} "
             f"at {meta['ping_interval']} s, {meta['ping_size']} B payload", ""]
    lines += ["## TCP throughput (iperf3)", "",
              "| Streams | Direction | Received Gbps | Retransmits | CPU client % | CPU server % | Error |",
              "|---|---|---|---|---|---|---|"]
    tput = [r for r in results if r["test"] == "throughput"]
    for r in tput:
        lines.append(f"| {r['streams']} | {r['direction']} | {r.get('received_gbps', '')} | "
                     f"{r.get('retransmits', '')} | {r.get('cpu_local', '')} | {r.get('cpu_remote', '')} | "
                     f"{r.get('error') or ''} |")
    best = max((r for r in tput if r.get("received_gbps")), key=lambda r: r["received_gbps"], default=None)
    if best:
        lines += ["", f"**Max E-W throughput: {best['received_gbps']} Gbps** "
                      f"({best['streams']} streams, {best['direction']})."]
    lines += ["", "## Round-trip latency (ms)", "",
              "| Source | Method | Load | Sent | Loss % | min | p50 | p90 | p99 | **p99.9** | max | Load Gbps |",
              "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in (r for r in results if r["test"] == "latency"):
        lines.append(f"| {r['vm']} | {METHODS[r.get('method', 'icmp')]} | {r['load']} | {r['sent']} | "
                     f"{r['loss_pct']} | {r['min']} | {r['p50']} | "
                     f"{r['p90']} | {r['p99']} | **{r['p99.9']}** | {r['max']} | {r.get('load_gbps', '')} |")
    return "\n".join(lines) + "\n"


METHODS = {"icmp": "ICMP echo", "tcp-open": "TCP, open connection", "tcp-new": "TCP, new connection"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--subscription", required=True)
    parser.add_argument("--resource-group", required=True, help="Customer resource group holding both workload VMs")
    parser.add_argument("--client-vm", default="vm-customer-workload-0")
    parser.add_argument("--server-vm", default="vm-customer-workload-1")
    parser.add_argument("--duration", type=int, default=30, help="Seconds per iperf3 run")
    parser.add_argument("--streams", default="1,4,8,16,32", help="Comma-separated parallel stream counts")
    parser.add_argument("--mss", type=int, help="Optional TCP MSS for iperf3 (-M)")
    parser.add_argument("--ping-count", type=int, default=20000, help=">=10000 needed for a meaningful p99.9")
    parser.add_argument("--ping-interval", type=float, default=0.01)
    parser.add_argument("--ping-size", type=int, default=56)
    parser.add_argument("--load-streams", type=int, default=8, help="iperf3 streams during loaded ping; 0 skips")
    parser.add_argument("--tcp-latency", action="store_true",
                        help="Also measure TCP request/response latency on an open connection and per new connection")
    parser.add_argument("--tcp-port", type=int, default=5202, help="Port for the TCP echo server")
    parser.add_argument("--skip-ping", action="store_true", help="Skip the idle ICMP latency run")
    parser.add_argument("--skip-throughput", action="store_true")
    parser.add_argument("--skip-latency", action="store_true")
    parser.add_argument("--out", default="ew-perf-results", help="Output directory (JSON + Markdown)")
    ctx = parser.parse_args()
    streams = [int(item) for item in ctx.streams.split(",") if item.strip()]

    client, server = vm_details(ctx, ctx.client_vm), vm_details(ctx, ctx.server_vm)
    for vm in (client, server):
        if vm["power"] != "VM running":
            log(f"{vm['name']} is '{vm['power']}'; start it first.")
            return 2
    meta = {"started": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "client": client, "server": server, "duration": ctx.duration, "ping_count": ctx.ping_count,
            "ping_interval": ctx.ping_interval, "ping_size": ctx.ping_size}
    results: list[dict] = []

    log("Preparing both VMs (iperf3 install + server start)")
    with concurrent.futures.ThreadPoolExecutor(2) as pool:
        for batch in pool.map(lambda vm: run_agent(ctx, vm["name"], "prepare", {
                "port": IPERF_PORT, "tcp_port": ctx.tcp_port if ctx.tcp_latency else None}), (client, server)):
            results += batch
            log(f"  {batch[0]['vm']}: {batch[0]}")
    if not all(r.get("server_started") for r in results if r["test"] == "prepare"):
        log("iperf3 server failed to start; aborting.")
        return 1
    if ctx.tcp_latency and not all(r.get("tcp_echo_started") for r in results if r["test"] == "prepare"):
        log("TCP echo server failed to start; aborting.")
        return 1

    log("Preflight: TCP/5201 and ICMP in both directions")
    with concurrent.futures.ThreadPoolExecutor(2) as pool:
        checks = list(pool.map(lambda pair: run_agent(ctx, pair[0]["name"], "preflight",
                                                      {"peer": pair[1]["ip"], "port": IPERF_PORT}),
                               ((client, server), (server, client))))
    for batch in checks:
        results += batch
        r = batch[0]
        log(f"  {r['vm']} -> {r['peer']}: tcp/{IPERF_PORT}={r['tcp_port_open']} "
            f"icmp loss={r['icmp']['loss_pct']}% p50={r['icmp']['p50']} ms")
    if not all(b[0]["tcp_port_open"] for b in checks):
        log("TCP east-west is blocked (check firewall policy and workload NSG); aborting before load tests.")
        return 1

    if not ctx.skip_throughput:
        log(f"Throughput sweep: streams={streams}, {ctx.duration}s each, forward + reverse")
        batch = run_agent(ctx, client["name"], "throughput", {"peer": server["ip"], "port": IPERF_PORT,
                                                              "duration": ctx.duration, "streams": streams,
                                                              "mss": ctx.mss})
        for r in batch:
            log(f"  P={r['streams']:>2} {r['direction']:<7} {r.get('received_gbps')} Gbps "
                f"retr={r.get('retransmits')} {r.get('error') or ''}")
        results += batch
        save(meta, results, ctx.out)

    if not ctx.skip_latency and not (ctx.skip_ping and not ctx.load_streams):
        log(f"Latency: {ctx.ping_count} pings at {ctx.ping_interval}s, idle then under {ctx.load_streams}-stream load")
        batch = run_agent(ctx, client["name"], "latency", {
            "peer": server["ip"], "port": IPERF_PORT, "count": ctx.ping_count, "interval": ctx.ping_interval,
            "size": ctx.ping_size, "load_streams": ctx.load_streams, "skip_ping": ctx.skip_ping})
        for r in batch:
            log(f"  {r['load']}: loss={r['loss_pct']}% p50={r['p50']} p99={r['p99']} p99.9={r['p99.9']} "
                f"max={r['max']} ms")
        results += batch
        save(meta, results, ctx.out)

    if not ctx.skip_latency and ctx.tcp_latency:
        for method in ("tcp-open", "tcp-new"):
            log(f"Latency: {ctx.ping_count} {METHODS[method]} requests at {ctx.ping_interval}s")
            batch = run_agent(ctx, client["name"], "tcp-latency", {
                "peer": server["ip"], "tcp_port": ctx.tcp_port, "count": ctx.ping_count,
                "interval": ctx.ping_interval, "method": method})
            for r in batch:
                log(f"  {METHODS[method]}: loss={r['loss_pct']}% p50={r['p50']} p99={r['p99']} "
                    f"p99.9={r['p99.9']} max={r['max']} ms")
            results += batch
            save(meta, results, ctx.out)

    path = save(meta, results, ctx.out)
    print("\n" + report(meta, results))
    log(f"Saved {path}.json and .md")
    return 0


def save(meta: dict, results: list[dict], directory: str) -> pathlib.Path:
    """Write JSON and Markdown after every step so a later failure keeps completed measurements."""
    out = pathlib.Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    path = out / ("ew-perf-" + meta["started"].replace(":", "").replace("-", ""))
    path.with_suffix(".json").write_text(json.dumps({"meta": meta, "results": results}, indent=2))
    path.with_suffix(".md").write_text(report(meta, results))
    return path


if __name__ == "__main__":
    sys.exit(main())
