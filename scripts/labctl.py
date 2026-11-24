#!/usr/bin/env python3
"""labctl — run the Phase 2 tests against the running GNS3 project and save results.

Run on the GNS3 server (carlos). Results (JSON/CSV/Markdown/pcap) go to ../results/.
  labctl.py status                   routing/BFD/BGP/services health
  labctl.py access [secure|open]     zone access-control matrix (unauthorized access test)
  labctl.py mtls                     device identity: valid / rogue / no certificate
  labctl.py breach                   plaintext MQTT vs mutual TLS on the wire (pcaps for Wireshark)
  labctl.py failover                 cut ring link C1-C2, measure convergence (OSPF+BFD)
  labctl.py scale                    add devices step by step, measure throughput/latency/loss + S1 reduction
  labctl.py qos                      latency of safety (EF) vs best effort under congestion, QoS off/on
  labctl.py ddos                     SYN flood from a compromised sensor and from the Internet, guard off/on
  labctl.py add-cluster              S2: plug a new cluster C6 into the ring without touching other routers
  labctl.py all                      everything above, in order
"""
import csv, datetime, json, os, re, subprocess, sys, time
sys.path.insert(0, os.path.dirname(__file__))
from gns3api import req

SIM = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(SIM, "results")
os.makedirs(RES, exist_ok=True)

# Not on the GNS3 server (e.g. on the Mac)? Run this same command on the server over SSH, then copy results/ back.
SERVER = os.environ.get("GNS3_SERVER", "carlos@100.99.194.92")
REMOTE_SIM = os.environ.get("REMOTE_SIM", "/home/carlos/projects/IoT_Applications/simulation")
if not os.path.isdir("/mnt/storage/gns3/projects") and os.environ.get("LABCTL_LOCAL") != "1":
    import shlex
    args = " ".join(shlex.quote(a) for a in sys.argv[1:])
    print(f"[labctl] running on {SERVER} over SSH ...", flush=True)
    rc = subprocess.call(["ssh", "-t", SERVER, f"cd {REMOTE_SIM}/scripts && python3 labctl.py {args}"])
    print("[labctl] copying results/ back to", RES, flush=True)
    subprocess.call(["rsync", "-a", f"{SERVER}:{REMOTE_SIM}/results/", RES + "/"])
    sys.exit(rc)

PID = open(os.path.join(SIM, ".project_id")).read().strip()
TLS = ["--cafile", "/etc/lab/pki/ca.crt", "--cert", "/etc/lab/pki/client.crt", "--key", "/etc/lab/pki/client.key", "--insecure"]
BROKER, CLOUD = "10.2.200.10", "10.100.1.10"


def cname(node):
    return f"GNS3.{node}.{PID}"


def x(node, *cmd, timeout=60, check=False):
    """Run a command in a node; return (rc, stdout)."""
    try:
        r = subprocess.run(["docker", "exec", cname(node), *cmd], capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired:
        return 124, "timeout"


def bg(node, *cmd):
    return subprocess.Popen(["docker", "exec", cname(node), *cmd], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def save(name, data, md=None):
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M")
    with open(os.path.join(RES, f"{name}.json"), "w") as f:
        json.dump({"test": name, "time": stamp, "data": data}, f, indent=1)
    if md:
        with open(os.path.join(RES, f"{name}.md"), "w") as f:
            f.write(md + "\n")
    print(f"\nsaved results/{name}.json" + (f" and results/{name}.md" if md else ""))


def table(rows, headers):
    w = [max(len(str(h)), *(len(str(r[i])) for r in rows)) for i, h in enumerate(headers)]
    line = lambda r: "| " + " | ".join(str(c).ljust(w[i]) for i, c in enumerate(r)) + " |"
    return "\n".join([line(headers), "|" + "|".join("-" * (n + 2) for n in w) + "|"] + [line(r) for r in rows])


def nodes():
    return {n["name"]: n for n in req("GET", f"/projects/{PID}/nodes")}


def link_between(a, b):
    ns = nodes()
    ia, ib = ns[a]["node_id"], ns[b]["node_id"]
    for l in req("GET", f"/projects/{PID}/links"):
        ids = {e["node_id"] for e in l["nodes"]}
        if ids == {ia, ib}:
            return l["link_id"]
    raise SystemExit(f"no link {a}-{b}")


# ------------------------------------------------------------------ status
def status():
    print("== OSPF neighbors (FOG-C1)"); print(x("FOG-C1", "vtysh", "-c", "show ip ospf neighbor")[1])
    print("== BFD peers (FOG-C1)"); print(x("FOG-C1", "vtysh", "-c", "show bfd peers brief")[1])
    print("== BGP (DC-A)"); print(x("DC-A", "vtysh", "-c", "show bgp summary")[1].split("Neighbor")[-1])
    print("== default route (FOG-C4)"); print(x("FOG-C4", "vtysh", "-c", "show ip route 0.0.0.0/0")[1])
    print("== firewall / QoS (FW-C2)"); print(x("FW-C2", "fw-mode", "status")[1].splitlines()[0]); print(x("FW-C2", "tc", "qdisc", "show", "dev", "eth0")[1].splitlines()[0])
    print("== fog bridge (BROKER-C2)"); print(x("BROKER-C2", "sh", "-c", "grep -iE 'bridge' /var/log/mosquitto.log | tail -1")[1])
    print("== aggregator"); print(x("BROKER-C2", "sh", "-c", "tail -1 /var/log/fog-aggregator.log 2>/dev/null || echo 'no data yet'")[1])


# ------------------------------------------------------------------ access matrix (unauthorized access)
ACCESS = [  # (description, source, command, expected in SECURE mode)
    ("Safety ctrl -> fog broker 8883 (mTLS)", "SIGNAL-CTRL", ["mosquitto_pub", "-h", BROKER, "-p", "8883", *TLS, "-t", "city/c2/raw/safety/1", "-m", "{}"], True),
    ("RSU -> signal controller CoAP 5683 (preemption)", "RSU", ["sh", "-c", "coap-client -m get -B 3 coap://10.2.10.10/ | grep -q libcoap"], True),
    ("Transit -> fog broker 8883 (mTLS)", "TRANSIT-GW", ["mosquitto_pub", "-h", BROKER, "-p", "8883", *TLS, "-t", "city/c2/raw/transit/1", "-m", "{}"], True),
    ("Transit -> fog broker 1883 (plaintext)", "TRANSIT-GW", ["mosquitto_pub", "-h", BROKER, "-p", "1883", "-t", "x", "-m", "{}"], False),
    ("EV charger -> payment processor 443 (TLS)", "EV-CHARGER", ["curl", "-sk", "--max-time", "5", f"https://{CLOUD}/"], True),
    ("EV charger -> fog broker 8883", "EV-CHARGER", ["mosquitto_pub", "-h", BROKER, "-p", "8883", *TLS, "-t", "x", "-m", "{}"], False),
    ("EV charger -> signal controller", "EV-CHARGER", ["ping", "-c1", "-W2", "10.2.10.10"], False),
    ("LoRa sensors -> fog broker 8883 (mTLS)", "LORA-GW", ["mosquitto_pub", "-h", BROKER, "-p", "8883", *TLS, "-t", "city/c2/raw/parking/1", "-m", "{}"], True),
    ("LoRa sensors -> signal controller CoAP", "LORA-GW", ["sh", "-c", "coap-client -m get -B 3 coap://10.2.10.10/ | grep -q libcoap"], False),
    ("LoRa sensors -> Internet (botnet egress)", "LORA-GW", ["ping", "-c1", "-W2", "198.18.0.10"], False),
    ("Public Wi-Fi -> Internet", "PUBLIC-WIFI", ["ping", "-c1", "-W2", "198.18.0.10"], True),
    ("Public Wi-Fi -> signal controller CoAP", "PUBLIC-WIFI", ["sh", "-c", "coap-client -m get -B 3 coap://10.2.10.10/ | grep -q libcoap"], False),
    ("Public Wi-Fi -> fog broker 8883", "PUBLIC-WIFI", ["mosquitto_pub", "-h", BROKER, "-p", "8883", *TLS, "-t", "x", "-m", "{}"], False),
    ("Public Wi-Fi -> payment zone (EV charger)", "PUBLIC-WIFI", ["ping", "-c1", "-W2", "10.2.40.10"], False),
    ("Mgmt jump host -> signal controller", "MGMT-JUMP", ["ping", "-c1", "-W2", "10.2.10.10"], True),
    ("Internet attacker -> cloud front door 8883", "ATTACKER", ["nc", "-z", "-w3", CLOUD, "8883"], True),
    ("Internet attacker -> signal controller", "ATTACKER", ["ping", "-c1", "-W2", "10.2.10.10"], False),
    ("Internet attacker -> fog broker", "ATTACKER", ["nc", "-z", "-w3", BROKER, "8883"], False),
]


def access(mode="secure"):
    x("FW-C2", "fw-mode", mode)
    rows, data, ok_all = [], [], True
    for desc, src, cmd, exp in ACCESS:
        rc, _ = x(src, *cmd, timeout=12)
        got = rc == 0
        exp_mode = exp if mode == "secure" else None
        ok = (got == exp) if mode == "secure" else True
        ok_all &= ok
        rows.append((desc, src, "ALLOWED" if got else "blocked", ("ALLOWED" if exp else "blocked") if mode == "secure" else "-", "PASS" if ok else "FAIL") if mode == "secure"
                    else (desc, src, "ALLOWED" if got else "blocked"))
        data.append({"flow": desc, "source": src, "result": "allowed" if got else "blocked", "expected": exp_mode})
    hdr = ("Flow", "Source", "Result", "Expected (design)", "Check") if mode == "secure" else ("Flow", "Source", "Result")
    md = f"### Access-control matrix — firewall {mode.upper()} mode\n\n" + table(rows, hdr)
    print(md)
    counters = x("FW-C2", "sh", "-c", "nft list ruleset | grep -E 'counter packets [1-9]'")[1]
    if mode == "secure":
        md += "\n\nFirewall counters (packets that matched each rule):\n```\n" + counters + "\n```"
    if mode == "open":
        x("FW-C2", "fw-mode", "secure")
        print("(firewall returned to SECURE mode)")
    save(f"access_{mode}", data, md)
    return ok_all


# ------------------------------------------------------------------ device identity
def mtls():
    tests = [("Valid device certificate (lab CA)", "EDGE-C4", ["mosquitto_pub", "-h", CLOUD, "-p", "8883", *TLS, "-t", "city/c4/raw/env/1", "-m", "{}"], True),
             ("Rogue certificate (untrusted CA)", "ATTACKER", ["mosquitto_pub", "-h", CLOUD, "-p", "8883", *TLS, "-t", "city/c4/raw/env/1", "-m", "{}"], False),
             ("No client certificate", "INET-USER", ["mosquitto_pub", "-h", CLOUD, "-p", "8883", "--cafile", "/etc/lab/pki/ca.crt", "--insecure", "-t", "x", "-m", "{}"], False),
             ("Plaintext (no TLS) to 8883", "INET-USER", ["mosquitto_pub", "-h", CLOUD, "-p", "8883", "-t", "x", "-m", "{}"], False)]
    rows, data = [], []
    for desc, src, cmd, exp in tests:
        rc, out = x(src, *cmd, timeout=12)
        got = rc == 0
        rows.append((desc, src, "accepted" if got else "rejected", "PASS" if got == exp else "FAIL", out.splitlines()[-1][:60] if out else ""))
        data.append({"case": desc, "accepted": got, "expected": exp, "msg": out[-200:]})
    md = "### Device identity — mutual TLS at the cloud broker\n\n" + table(rows, ("Case", "From", "Result", "Check", "Client message"))
    md += "\n\nBroker log:\n```\n" + x("CLOUD-A", "tail", "-8", "/var/log/mosquitto.log")[1] + "\n```"
    print(md); save("mtls", data, md)


# ------------------------------------------------------------------ data breach: plaintext vs TLS
def breach():
    pcaps = {}
    x("FW-C2", "fw-mode", "open")                      # allow 1883 for the demonstration
    for label, port, extra in (("plaintext_1883", "1883", []), ("mtls_8883", "8883", TLS)):
        f = f"/tmp/{label}.pcap"
        cap = bg("FW-C2", "timeout", "8", "tcpdump", "-i", "eth2", "-w", f, "-U", f"tcp port {port}")
        time.sleep(1.5)
        payload = '{"id":"EV-CHARGER-7","card_token":"4111-XXXX-XXXX-1111","kwh":12.5,"lat":33.95,"lon":-84.55}'
        x("TRANSIT-GW", "mosquitto_pub", "-h", BROKER, "-p", port, *extra, "-t", "city/c2/raw/payment/7", "-m", payload, timeout=10)
        cap.wait(timeout=15)
        dst = os.path.join(RES, f"breach_{label}.pcap")
        subprocess.run(["docker", "cp", f"{cname('FW-C2')}:{f}", dst], check=False)
        rc, txt = x("FW-C2", "sh", "-c", f"tcpdump -r {f} -A 2>/dev/null | grep -c card_token")
        pcaps[label] = {"file": f"results/breach_{label}.pcap", "payload_visible": txt.strip() not in ("", "0")}
    x("FW-C2", "fw-mode", "secure")
    rows = [(k, v["file"], "YES — readable" if v["payload_visible"] else "no — encrypted") for k, v in pcaps.items()]
    md = "### Data-breach test — what an on-path attacker sees\n\n" + table(rows, ("Transport", "Capture", "Payment data visible?"))
    md += "\n\nOpen both pcaps in Wireshark: filter `mqtt` on the plaintext capture shows the payload; `tls` on the mTLS capture shows only Application Data."
    print(md); save("breach", pcaps, md)


# ------------------------------------------------------------------ failover (S6)
def failover():
    # continuous probe from the C1 edge to the C2 broker path (crosses C1-C2) every 20 ms
    probe = bg("EDGE-C1", "ping", "-D", "-i", "0.02", "-w", "14", "10.254.0.34")
    time.sleep(4)
    before = x("FOG-C1", "vtysh", "-c", "show ip route 10.254.0.32/30")[1]
    via_before = [f"{ip} ({dev})" for ip, dev in re.findall(r"\* ([\d.]+), via ([\w.]+)", before)]
    t_cut = time.time()
    # silent fiber cut: both ends drop everything (no carrier loss), so BFD must detect it
    for n in ("FOG-C1", "FOG-C2"):
        x(n, "tc", "qdisc", "add", "dev", "eth0", "root", "netem", "loss", "100%")
    time.sleep(5)
    after = x("FOG-C1", "vtysh", "-c", "show ip route 10.254.0.32/30")[1]
    for n in ("FOG-C1", "FOG-C2"):
        x(n, "tc", "qdisc", "del", "dev", "eth0", "root")
    out, _ = probe.communicate(timeout=30)
    seqs = [int(m) for m in re.findall(r"bytes from .*?icmp_seq=(\d+)", out)]
    lost = sorted(set(range(min(seqs), max(seqs) + 1)) - set(seqs)) if seqs else []
    # longest burst of consecutive losses = outage
    burst, best = 1, 0
    for i in range(1, len(lost)):
        burst = burst + 1 if lost[i] == lost[i - 1] + 1 else 1
        best = max(best, burst)
    best = max(best, 1 if lost else 0)
    conv_ms = best * 20
    via = [f"{ip} ({dev})" for ip, dev in re.findall(r"\* ([\d.]+), via ([\w.]+)", after)]
    data = {"path_before": via_before, "probe_interval_ms": 20, "lost_packets": len(lost), "outage_ms": conv_ms, "new_path_via": via}
    md = ("### Failover — ring link C1–C2 cut (OSPF + BFD)\n\n" + table(
        [("Probe", "EDGE-C1 → FW-C2 (path over C1–C2) every 20 ms"), ("Packets lost", len(lost)),
         ("Measured outage / convergence", f"~{conv_ms} ms"), ("Path before cut (FOG-C1)", ", ".join(via_before) or "-"), ("Path after cut (FOG-C1)", ", ".join(via) or "-"),
         ("Design target", "no single link failure isolates a cluster (S6)")], ("Metric", "Value")))
    print(md); save("failover", data, md)


# ------------------------------------------------------------------ scalability (S1, S2)
def scale(steps=((100, 5), (500, 5), (2000, 10), (5000, 20), (10000, 40)), interval=1.0, duration=30):
    rows, data = [], []
    for devices, gws in steps:
        sink = bg("BROKER-C2", "latency-sink", "--broker", BROKER, "--tls", "--topic", "city/c2/raw/#", "--duration", str(duration + 6), "--label", str(devices))
        cloud = bg("CLOUD-A", "latency-sink", "--broker", CLOUD, "--tls", "--topic", "city/c2/summary/#", "--duration", str(duration + 6), "--label", f"cloud-{devices}")
        time.sleep(2)
        _, simout = x("LORA-GW", "sensor-sim", "--broker", BROKER, "--tls", "--gateways", str(gws), "--devices", str(devices),
                      "--interval", str(interval), "--duration", str(duration), "--cls", "parking", timeout=duration + 60)
        s = json.loads(sink.communicate(timeout=duration + 60)[0].strip().splitlines()[-1])
        c = json.loads(cloud.communicate(timeout=duration + 60)[0].strip().splitlines()[-1])
        sim = json.loads(simout.strip().splitlines()[-1])
        cpu = x("BROKER-C2", "sh", "-c", "top -bn1 | grep -E 'mqtt-broker' | head -1 | awk '{print $7}'")[1]
        red = 100 * (1 - c["received"] / s["received"]) if s["received"] else 0
        rows.append((devices, gws, sim["target_msgs_per_s"], s["msgs_per_s"], s["loss_pct"], s["lat_ms_p50"], s["lat_ms_p95"], s["lat_ms_p99"], c["received"], f"{red:.2f}%"))
        data.append({"devices": devices, "gateways": gws, "sim": sim, "fog": s, "cloud": c, "broker_cpu": cpu, "upstream_reduction_pct": round(red, 2)})
        print(rows[-1])
        time.sleep(3)
    md = ("### Scalability — devices added step by step (fog broker C2, mutual TLS, 1 msg/s per device)\n\n" + table(
        rows, ("Devices", "Gateways", "Target msg/s", "Fog msg/s", "Loss %", "p50 ms", "p95 ms", "p99 ms", "Cloud msgs (summaries)", "Upstream reduction")))
    md += "\n\nS1: the fog aggregator forwards one summary per class every 10 s, so cloud traffic stays flat while device count grows."
    with open(os.path.join(RES, "scale.csv"), "w", newline="") as f:
        w = csv.writer(f); w.writerow(["devices", "gateways", "target", "fog_rate", "loss_pct", "p50", "p95", "p99", "cloud_msgs", "reduction"])
        for r in rows: w.writerow(r)
    print(md); save("scale", data, md)


# ------------------------------------------------------------------ QoS (S5)
def qos():
    x("FW-C2", "nft", "insert", "rule", "inet", "fw", "forward", "iifname", "eth1.50", "ip", "daddr", CLOUD, "tcp", "dport", "5201", "accept", "comment", "\"qos-test-traffic\"")
    rows, data = [], []
    for mode in ("off", "on"):
        x("FW-C2", "qos", mode)
        flood = bg("LORA-GW", "iperf3", "-c", CLOUD, "-t", "25", "-P", "4", "-b", "4M")        # bulk sensor upload saturates the 10 Mbit/s uplink
        time.sleep(5)
        res = {}
        for host, cls in (("SIGNAL-CTRL", "EF (safety)"), ("TRANSIT-GW", "AF31 (transit)"), ("PUBLIC-WIFI", "CS1 (public)")):
            dst = CLOUD if host != "PUBLIC-WIFI" else CLOUD
            p = bg(host, "ping", "-i", "0.2", "-c", "50", "-q", dst)
            res[cls] = p
        for cls, p in res.items():
            out = p.communicate(timeout=40)[0]
            m = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)", out); loss = re.search(r"(\d+)% packet loss", out)
            avg, mx = (float(m.group(2)), float(m.group(3))) if m else (None, None)
            rows.append((f"QoS {mode.upper()}", cls, avg, mx, f"{loss.group(1)}%" if loss else "?"))
            data.append({"qos": mode, "class": cls, "avg_ms": avg, "max_ms": mx, "loss": loss.group(1) if loss else None})
        flood.wait(timeout=90)
    x("FW-C2", "qos", "on")
    x("FW-C2", "sh", "-c", "h=$(nft -a list chain inet fw forward | grep qos-test-traffic | sed 's/.*handle //'); [ -n \"$h\" ] && nft delete rule inet fw forward handle $h")
    md = ("### QoS — latency to the cloud while bulk sensor traffic saturates the 10 Mbit/s fog uplink\n\n" + table(rows, ("Mode", "Traffic class", "Avg RTT ms", "Max RTT ms", "Loss")))
    md += "\n\nDSCP is set at the fog firewall (trust boundary): EF for VLAN 10/20, AF31 transit, AF21 payment, CS1 sensors/public."
    print(md); save("qos", data, md)


# ------------------------------------------------------------------ DDoS (C7)
def _legit_latency(seconds=12):
    sink = bg("BROKER-C2", "latency-sink", "--broker", BROKER, "--tls", "--topic", "city/c2/raw/transit/#", "--duration", str(seconds + 4))
    time.sleep(1.5)
    _, so = x("TRANSIT-GW", "sensor-sim", "--broker", BROKER, "--tls", "--devices", "50", "--interval", "1", "--duration", str(seconds), "--cls", "transit", timeout=seconds + 40)
    s = json.loads(sink.communicate(timeout=seconds + 40)[0].strip().splitlines()[-1])
    sim = json.loads(so.strip().splitlines()[-1])
    return sim, s


def ddos():
    """Three protection levels: none -> firewall/front-door guard -> + edge port policing (cabinet switch)."""
    levels = [("1 none", "off", "off"), ("2 firewall + front-door guard", "on", "off"), ("3 guard + edge port policing", "on", "on")]
    rows, data = [], []
    for label, guard, police in levels:
        x("FW-C2", "ddos-guard", guard); x("DC-A", "ddos-guard", guard); x("CABINET-SW", "port-police", police)
        for n, ch in (("FW-C2", "inet fw ddos"), ("DC-A", "inet frontdoor ddos")):
            x(n, "sh", "-c", f"nft reset counters table {ch.rsplit(' ', 1)[0]} >/dev/null 2>&1")
        base_sim, base = _legit_latency()
        # compromised sensor gateway floods the fog broker with SYNs (spoofing is impossible: egress anti-spoofing)
        a1 = bg("LORA-GW", "timeout", "22", "nping", "--tcp", "-p", "8883", "--flags", "syn", "--rate", "3000", "-c", "0", "-H", "-N", BROKER)
        # Internet botnet floods the cloud front door
        a2 = bg("ATTACKER", "timeout", "22", "nping", "--tcp", "-p", "8883", "--flags", "syn", "--rate", "3000", "-c", "0", "-H", "-N", CLOUD)
        time.sleep(3)
        att_sim, att = _legit_latency()
        conn_ok = x("EDGE-C4", "mosquitto_pub", "-h", CLOUD, "-p", "8883", *TLS, "-t", "city/c4/raw/env/1", "-m", "{}", timeout=15)[0] == 0
        a1.wait(timeout=40); a2.wait(timeout=40)
        fw = sum(int(n) for n in re.findall(r"counter packets (\d+)", x("FW-C2", "nft", "list", "chain", "inet", "fw", "ddos")[1]))
        fd = sum(int(n) for n in re.findall(r"counter packets (\d+)", x("DC-A", "nft", "list", "chain", "inet", "frontdoor", "ddos")[1]))
        sw = sum(int(n) for n in re.findall(r"dropped (\d+)", x("CABINET-SW", "port-police", "status")[1]))
        rows.append((label, base["lat_ms_p95"], att["lat_ms_p50"], att["lat_ms_p95"], att["lat_ms_p99"], att["loss_pct"], "yes" if conn_ok else "NO", sw, fw, fd))
        data.append({"level": label, "baseline": base, "under_attack": att, "cloud_connect_ok": conn_ok,
                     "dropped_edge_switch": sw, "dropped_fw_c2": fw, "dropped_dc_a": fd})
        print(rows[-1])
        time.sleep(5)
    x("FW-C2", "ddos-guard", "on"); x("DC-A", "ddos-guard", "on"); x("CABINET-SW", "port-police", "on")
    md = ("### DDoS — 3 000 SYN/s from a compromised sensor gateway (→ fog broker) + 3 000 SYN/s from an Internet botnet (→ cloud front door)\n\n"
          "Legitimate traffic: 50 transit devices publishing over mutual TLS to the fog broker (one-way latency).\n\n" + table(
        rows, ("Protection level", "Legit p95 ms (no attack)", "Legit p50 ms (attack)", "Legit p95 ms (attack)", "Legit p99 ms (attack)",
               "Legit loss %", "Cloud connect OK", "SYNs dropped at cabinet switch", "SYNs dropped at FW-C2", "SYNs dropped at DC-A")))
    md += ("\n\nControls (Table 2, C7): per-port SYN policing at the cabinet switch (edge), per-source SYN limit + global SYN cap + per-source "
           "connection limit at the fog firewall, front-door SYN limits at DC-A, SYN cookies, egress anti-spoofing, no Internet egress for sensors.")
    print(md); save("ddos", data, md)


# ------------------------------------------------------------------ S2: add a cluster
C6_FRR = """frr defaults traditional
hostname FOG-C6
service integrated-vtysh-config
bfd
 profile fast
  transmit-interval 150
  receive-interval 150
  detect-multiplier 3
 exit
exit
interface lo
 ip address 10.255.0.6/32
exit
interface eth0
 description to FOG-C4 (reserved port eth2)
 ip address 10.254.0.38/30
 ip ospf area 0
 ip ospf network point-to-point
 ip ospf hello-interval 1
 ip ospf dead-interval 4
 ip ospf bfd
 ip ospf bfd profile fast
exit
interface eth1
 description to FOG-C2 (reserved port eth3)
 ip address 10.254.0.42/30
 ip ospf area 0
 ip ospf network point-to-point
 ip ospf hello-interval 1
 ip ospf dead-interval 4
 ip ospf bfd
 ip ospf bfd profile fast
exit
interface eth3
 description edge LAN cluster C6 (new city: e.g. Kennesaw)
 ip address 10.6.50.1/24
exit
router ospf
 ospf router-id 10.255.0.6
 redistribute connected
 passive-interface default
 no passive-interface eth0
 no passive-interface eth1
exit
end
"""


def add_cluster():
    tpl = {t["name"]: t["template_id"] for t in req("GET", "/templates")}
    ns = nodes()
    if "FOG-C6" in ns:
        print("FOG-C6 already exists")
    else:
        r = req("POST", f"/projects/{PID}/templates/{tpl['IoT Lab Router']}", {"x": -240, "y": 380})
        req("PUT", f"/projects/{PID}/nodes/{r['node_id']}", {"name": "FOG-C6"})
        h = req("POST", f"/projects/{PID}/templates/{tpl['IoT Lab Host']}", {"x": -240, "y": 520})
        req("PUT", f"/projects/{PID}/nodes/{h['node_id']}", {"name": "EDGE-C6"})
        base = f"/mnt/storage/gns3/projects/{PID}/project-files/docker"
        for nid, files in ((r["node_id"], {"etc/frr/frr.conf": C6_FRR, "etc/lab/startup.sh": "#!/bin/bash\n:\n"}),
                           (h["node_id"], {"etc/lab/startup.sh": "#!/bin/bash\nip addr add 10.6.50.10/24 dev eth0\nip route add default via 10.6.50.1\n"})):
            for rel, content in files.items():
                p = os.path.join(base, nid, rel); os.makedirs(os.path.dirname(p), exist_ok=True)
                open(p, "w").write(content); os.chmod(p, 0o755)
        ns = nodes()
        L = lambda a, ai, b, bi: req("POST", f"/projects/{PID}/links", {"nodes": [{"node_id": ns[a]["node_id"], "adapter_number": ai, "port_number": 0},
                                                                                  {"node_id": ns[b]["node_id"], "adapter_number": bi, "port_number": 0}]})
        L("FOG-C6", 0, "FOG-C4", 2); L("FOG-C6", 1, "FOG-C2", 3); L("FOG-C6", 3, "EDGE-C6", 0)
        t0 = time.time()
        req("POST", f"/projects/{PID}/nodes/{ns['FOG-C6']['node_id']}/start", {}); req("POST", f"/projects/{PID}/nodes/{ns['EDGE-C6']['node_id']}/start", {})
    t0 = time.time(); learned = None
    while time.time() - t0 < 60:
        if "10.6.50.0/24" in x("FOG-C1", "vtysh", "-c", "show ip route 10.6.50.0/24")[1]:
            learned = round(time.time() - t0, 1); break
        time.sleep(1)
    rc, out = x("EDGE-C6", "ping", "-c3", "-W2", "10.100.1.10")
    data = {"new_prefix": "10.6.50.0/24", "learned_by_FOG-C1_after_s": learned, "edge_c6_to_cloud_ok": rc == 0, "changes_on_existing_routers": 0}
    md = ("### Scalability S2 — adding cluster C6 without redesign\n\n" + table(
        [("New fog router", "FOG-C6, dual-homed to FOG-C4 (eth2) and FOG-C2 (eth3), ports pre-provisioned"),
         ("Config changes on existing routers", "0"), ("Route 10.6.50.0/24 learned by FOG-C1", f"after {learned} s" if learned else "not learned"),
         ("EDGE-C6 → cloud reachability", "OK" if rc == 0 else "FAIL")], ("Item", "Result")))
    print(md); save("add_cluster", data, md)


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    arg = sys.argv[2] if len(sys.argv) > 2 else None
    fn = {"status": status, "access": lambda: access(arg or "secure"), "mtls": mtls, "breach": breach, "failover": failover,
          "scale": scale, "qos": qos, "ddos": ddos, "add-cluster": add_cluster}
    if cmd == "all":
        for name in ("status", "access", "mtls", "breach", "failover", "scale", "qos", "ddos"):
            print(f"\n######## {name}")
            fn[name]()
        access("open")
    elif cmd in fn:
        fn[cmd]()
    else:
        print(__doc__)
