# IoT Smart City — Phase 2 Simulation (GNS3)

Simulation of the Phase 1 design (*Design and Simulation of a Scalable and Secure Network Architecture for IoT Applications*, metro-Atlanta transportation): five fog clusters on a ring, two data centers, two ISPs, and the Marietta/Smyrna cluster (C2) built in detail with its VLAN zones, fog firewall, MQTT brokers and security controls. Everything runs in **GNS3 on the home server (carlos)** and is opened from the **Mac** through the GNS3 web UI; packets are analyzed with **Wireshark on the Mac**.

- GNS3 web UI: **http://100.99.194.92:3080** → project **"IoT Smart City - Phase 2"** (Tailscale must be on)
- Project folder on the server: `~/projects/IoT_Applications/simulation/`
- Test results (tables, JSON, CSV, pcaps): `simulation/results/`

---

## 1. What is in the topology

```
                     INET-USER   ATTACKER (botnet)
                           \       /
                          INTERNET-SW
                               |
                 ISP-1 (AS64501) ── ISP-2 (AS64502)          eBGP, both DCs announce the cloud prefix (anycast front door)
                   |                    |
 CLOUD-A ── DC-A (AS65000)          DC-B (AS65000)
  broker     |  front-door FW,      /        \
  API 443    |  DDoS guard         /          \
          FOG-C1 ─────────────── FOG-C5        |
          /   \                     \          |
     FOG-C2    EDGE-C1          FOG-C3 ────────┘          Ring C1–C2–C4–C3–C5–C1: OSPFv2 + OSPFv3, BFD (150 ms × 3)
       |   \                     /    \
     FW-C2  FOG-C4 ─────────────┘     EDGE-C3
       |  \      \
       |   BROKER-C2 (fog MQTT broker, mTLS, aggregator, bridge → CLOUD-A)
   CABINET-SW (802.1Q)        EDGE-C4      (FOG-C6 + EDGE-C6 are added by the S2 test)
   ├─ VLAN 10 SIGNAL-CTRL  (CoAP server = preemption endpoint)
   ├─ VLAN 20 RSU
   ├─ VLAN 30 TRANSIT-GW
   ├─ VLAN 40 EV-CHARGER   (payment, TLS 443 to the processor only)
   ├─ VLAN 50 LORA-GW      (parking/environment sensors)
   ├─ VLAN 90 PUBLIC-WIFI  (Internet only; also the insider attacker)
   └─ VLAN 99 MGMT-JUMP
```

### Addressing (from Phase 1, Table 3)

| Item | IPv4 | IPv6 |
|---|---|---|
| Cluster C*n* | `10.n.0.0/16` | `2001:db8:n::/48` |
| C2 zones, site 0x02A | VLAN 10 `10.2.10.0/24`, 20 `10.2.20.0/24`, 30 `10.2.30.0/24`, 40 `10.2.40.0/24`, 50 `10.2.50.0/24`, 90 `10.2.90.0/24`, 99 `10.2.99.0/24` (gateway `.1` on FW-C2, host `.10`) | `2001:db8:2:Z02a::/64` (Z = zone code, e.g. safety `2001:db8:2:102a::/64`) |
| Fog services C2 (broker) | `10.2.200.10` | `2001:db8:2:e000::10` |
| Ring / DC links | `10.254.0.0/24` (/30 each) | link-local (OSPFv3) |
| Router loopbacks | `10.255.0.x/32` | `2001:db8:ffff::x/128` |
| Cloud services DC-A | `10.100.1.10` | `2001:db8:a:1::10` |
| Edge LANs C1/C3/C4/C5 | `10.n.50.0/24` | `2001:db8:n:502a::/64` |
| ISP links / Internet | `203.0.113.0/30`, `198.51.100.0/30`, `192.0.2.0/30`, Internet `198.18.0.0/24` | — |

### How the design maps to the simulation

| Phase 1 requirement | Implemented as | Test |
|---|---|---|
| S1 hierarchical filtering | `fog-aggregator` on BROKER-C2 publishes one summary per class every 10 s; the MQTT bridge forwards only `city/c2/summary/#` to the cloud | `scale` (upstream reduction) |
| S2 growth without redesign | Free, pre-configured ring ports on FOG-C4/FOG-C2; new cluster C6 joins OSPF with 0 changes elsewhere | `add-cluster` |
| S5 QoS | DSCP set at FW-C2 (EF safety/V2X, AF31 transit, AF21 payment, CS1 sensors/public); HTB strict priority for EF on the 10 Mbit/s uplink | `qos` |
| S6 no single point of failure | Ring + dual-homed DC-B, OSPF hello 1 s / dead 4 s, BFD 150 ms × 3 | `failover` |
| C1 device identity | X.509 certificates, mutual TLS on both brokers (`require_certificate true`) | `mtls` |
| C3 encryption in transit | MQTT over TLS (8883); bridge fog→cloud over mTLS; payment over TLS 443 | `breach` |
| C5 segmentation | VLANs per zone + default-deny zone matrix on FW-C2 (`fw-mode secure`) | `access` |
| C6 firewalls | FW-C2 zone firewall, DC-A front door (only 443/8883 from the Internet) | `access` |
| C7 DDoS resilience | per-port SYN policing at the cabinet switch (edge), per-source SYN limit, global SYN cap, per-source connection limit, SYN cookies, egress anti-spoofing, no Internet for sensors | `ddos` |

**Simplifications (say so in the report):** MPLS L3VPN/VRFs are replaced by VLANs + a stateful zone firewall (VRF-lite equivalent); LoRaWAN, C-V2X PC5 and 5G radios are represented by their IP-side gateways; the fog LoRaWAN network server is represented by the MQTT broker; one data center hosts the cloud services (DC-B is the second path/anycast entry); link speeds are not emulated except the fog uplink shaped to 10 Mbit/s for the QoS test.

---

## 2. Run it from your Mac — step by step

### 2.1 One-time setup on the Mac

1. **Tailscale** on and connected (the lab only listens on `100.99.194.92`).
2. **Wireshark**: `brew install --cask wireshark` (or download from wireshark.org). Open it once so macOS installs ChmodBPF.
3. **SSH key to carlos** (for live captures and running tests). Test: `ssh carlos@100.99.194.92 hostname` → `carlos`.
4. **Get the project files** (scripts, results, README) on the Mac:
   ```bash
   mkdir -p ~/IoT_Applications && rsync -av carlos@100.99.194.92:/home/carlos/projects/IoT_Applications/simulation ~/IoT_Applications/
   ```
   Re-run the same command later to pull new results (pcaps, tables).
5. Python packages: **none needed** — see `requirements.txt` (only `paho-mqtt`, optional, to run the sensor tools on the Mac itself).
6. Optional: **GNS3 desktop app 3.0.6** (same version as the server) from gns3.com if you prefer it over the web UI (it can launch Wireshark from a link with one click).

### 2.2 Open the project in the GNS3 web UI

1. Browser → **http://100.99.194.92:3080** → user `admin`, password: `ssh carlos@100.99.194.92 cat ~/services/gns3/.admin-password` (save it in Vaultwarden).
2. **Projects → "IoT Smart City - Phase 2" → Open.**
3. Click **▶ Start all** (green play button). Wait ~40 s (OSPF/BGP converge, brokers start).
4. Double-click any device to open its **console** (a shell). Useful commands:
   - routers: `vtysh -c "show ip ospf neighbor"`, `vtysh -c "show ip route"`, `vtysh -c "show bfd peers"`, `vtysh -c "show bgp summary"`
   - FW-C2: `fw-mode status | secure | open`, `qos status | on | off`, `ddos-guard status | on | off`, `nft list ruleset`
   - CABINET-SW: `port-police status | on | off`, `bridge vlan show`
   - DC-A: `ddos-guard status | on | off`, `nft list ruleset`
   - hosts: `cat /etc/lab/ROLE`, `sensor-sim --help`, `latency-sink --help`, `mosquitto_sub`, `coap-client`, `nping`, `nmap`
5. When done: **■ Stop all** (the project stays saved on the server).

### 2.3 Run the tests (from the Mac terminal)

Every test prints a table and saves `results/<test>.md` / `.json` (and `.pcap`/`.csv` where relevant):

```bash
S="ssh carlos@100.99.194.92"
L="cd ~/projects/IoT_Applications/simulation/scripts && python3 labctl.py"

$S "$L status"           # routing / BFD / BGP / firewall / bridge health
$S "$L access secure"    # zone access-control matrix, designed firewall (18 flows, PASS/FAIL vs Table 3)
$S "$L access open"      # same flows with a flat network (baseline for comparison)
$S "$L mtls"             # valid vs rogue vs no certificate
$S "$L breach"           # plaintext MQTT vs mutual TLS on the wire -> results/breach_*.pcap
$S "$L failover"         # cut ring link C1–C2, measure convergence
$S "$L scale"            # 100 → 10 000 devices: throughput, loss, latency, upstream reduction (~5 min)
$S "$L qos"              # EF vs best effort latency under congestion, QoS off vs on (~2 min)
$S "$L ddos"             # SYN floods, guard off vs on (~2 min)
$S "$L add-cluster"      # S2: add cluster C6 (already done once — it reports the result again)

rsync -av carlos@100.99.194.92:/home/carlos/projects/IoT_Applications/simulation/results ~/IoT_Applications/simulation/   # copy results to the Mac
```

### 2.4 Capture packets in Wireshark on the Mac

**Option A — live, recommended (any interface of any node):**
```bash
cd ~/IoT_Applications/simulation/scripts
./mac-capture.sh FW-C2 eth1                                   # trunk: all VLANs
./mac-capture.sh FW-C2 eth1 "" ~/Desktop/trunk.pcapng         # same + save a copy
./mac-capture.sh FOG-C1 eth0 "ospf or udp port 3784"          # OSPF + BFD on the C1–C2 ring link
```
Wireshark opens and shows packets live. Then trigger traffic (run a test from 2.3 in another terminal, or type commands in a node console).

**Option B — GNS3 desktop app:** right-click a link → **Start capture** → Wireshark opens automatically.

**Option C — web UI only:** right-click a link → **Start capture**, generate traffic, **Stop capture**, then copy the file:
```bash
rsync -av "carlos@100.99.194.92:/mnt/storage/gns3/projects/$(ssh carlos@100.99.194.92 cat ~/projects/IoT_Applications/simulation/.project_id)/project-files/captures/" ~/Desktop/captures/
```

**Ready-made pcaps:** `results/breach_plaintext_1883.pcap` and `results/breach_mtls_8883.pcap` (from `labctl.py breach`).

### 2.5 Where to capture

| Link (node:interface) | What crosses it |
|---|---|
| `FOG-C1:eth0` (C1–C2 ring) | OSPF, OSPFv3, BFD, failover traffic |
| `DC-A:eth2` (DC-A–ISP-1) | eBGP, Internet attacks on the front door |
| `DC-B:eth2` (DC-B–ISP-2) | eBGP with AS-path prepending (backup path) |
| `FW-C2:eth1` (trunk) | 802.1Q tags of every zone, CoAP preemption, blocked flows, SYN flood from sensors |
| `FW-C2:eth0` (fog uplink) | DSCP markings, MQTT bridge fog→cloud (summaries only), QoS test |
| `FW-C2:eth2` (fog services) | MQTT/TLS to the fog broker, plaintext 1883 in the breach test |

---

## 3. Wireshark guide for the report (filters, what to expand, what it answers)

"Row" = the packet number of the first match in **your** capture (it changes every capture — write down yours). Save each screenshot with the image name to drop it straight into the LaTeX report (`\includegraphics{images/<image>.png}`).

| Image | Capture (where / when) | Filter | Click / expand | Report section | Expected answer |
|---|---|---|---|---|---|
| `p2_ospf_hello` | `FOG-C1:eth0`, any time | `ospf.msg == 1` | OSPF Header > Area ID; OSPF Hello Packet > Hello Interval, Router Dead Interval, Active Neighbor | S6, routing config | Area 0.0.0.0, Hello 1 s, Dead 4 s, neighbor 10.255.0.2 |
| `p2_bfd` | `FOG-C1:eth0` | `bfd` | BFD Control message > Desired Min TX Interval, Required Min RX Interval, Detect Time Multiplier, Session State | S6 fast detection | 150 000 µs, 150 000 µs, ×3 (≈450 ms detection), State Up |
| `p2_failover_gap` | `FOG-C1:eth1` while `labctl.py failover` runs | `icmp && ip.src == 10.1.50.10` | Statistics > I/O Graph (interval 100 ms) | S6 results | traffic appears on the C5 side ~1.3 s after the cut (matches results/failover.md) |
| `p2_bgp_update` | `DC-A:eth2` while restarting DC-A's BGP (`vtysh -c "clear bgp *"`) | `bgp.type == 2` | BGP UPDATE > Path attributes > AS_PATH; NLRI | Cloud/ISP design | DC-A announces 10.100.1.0/24 with AS_PATH 65000; ISP-1 sends 0.0.0.0/0 and 198.18.0.0/24 |
| `p2_bgp_prepend` | `DC-B:eth2`, same | `bgp.type == 2` | AS_PATH | Dual ISP, backup path | AS_PATH 65000 65000 65000 (prepend → DC-B is the backup entry) |
| `p2_vlan_tags` | `FW-C2:eth1` | `vlan` | 802.1Q Virtual LAN > ID; Statistics > Protocol Hierarchy | C5 segmentation | VLAN IDs 10, 20, 30, 40, 50, 90, 99 on one trunk |
| `p2_coap_preemption` | `FW-C2:eth1`, run on RSU: `coap-client -m get coap://10.2.10.10/` | `coap` | CoAP > Code (GET / 2.05 Content), 802.1Q ID | Preemption path (V2X→safety) | request in VLAN 20, response from VLAN 10 — allowed flow |
| `p2_blocked_flow` | `FW-C2:eth1`, run on PUBLIC-WIFI: `coap-client -m get -B 3 coap://10.2.10.10/` | `coap && ip.src == 10.2.90.10` | count requests vs `coap.code == 69` responses | Unauthorized access | requests retransmitted, **no response** — dropped by the zone firewall (default deny) |
| `p2_dscp_ef` | `FW-C2:eth0`, ping from SIGNAL-CTRL to 10.100.1.10 | `ip.dsfield.dscp == 46` | IP > Differentiated Services Field | S5 QoS | DSCP 46 = EF (Expedited Forwarding) |
| `p2_dscp_classes` | `FW-C2:eth0`, pings from TRANSIT-GW / LORA-GW | `ip.dsfield.dscp == 26 \|\| ip.dsfield.dscp == 8` | DS Field | S5 QoS | AF31 (26) transit, CS1 (8) sensors/public |
| `p2_qos_rtt` | `FW-C2:eth0` while `labctl.py qos` runs | `icmp.type == 0` | Statistics > I/O Graph, Y = `icmp.resptime` AVG, two graphs filtered by `ip.dsfield.dscp == 46` and `== 8` | S5 results | EF RTT stays low with QoS on; best effort rises (matches results/qos.md) |
| `p2_mqtt_plaintext` | open `results/breach_plaintext_1883.pcap` | `mqtt.msgtype == 3` | MQ Telemetry Transport > Topic, Message | C3 data breach | topic `city/c2/raw/payment/7`, **card token and GPS visible in clear text** |
| `p2_tls_clienthello` | open `results/breach_mtls_8883.pcap` | `tls.handshake.type == 1` | TLS > Client Hello > Version, supported_versions, Cipher Suites | C1/C3 | TLS 1.3 offered |
| `p2_tls_encrypted` | `results/breach_mtls_8883.pcap` | `tls.record.content_type == 23` | TLS > Application Data | C3 encryption | only encrypted Application Data — **no topic, no card data** (in TLS 1.3 even the client certificate is encrypted) |
| `p2_mtls_reject` | `DC-A:eth1` (cloud LAN), run `labctl.py mtls` | `tls.alert_message \|\| tcp.flags.reset == 1` | TLS > Alert > Description | C1 identity | rogue/no-cert client: handshake fails, connection closed |
| `p2_bridge_summary` | `FW-C2:eth0` during `labctl.py scale` | `ip.dst == 10.100.1.10 && tcp.port == 8883` | Statistics > Conversations > TCP (bytes) — compare with `FW-C2:eth2` conversations to 10.2.200.10 | S1 filtering | uplink to cloud carries a tiny fraction of the bytes the fog broker receives |
| `p2_synflood` | `FW-C2:eth1` (trunk) — on CABINET-SW run `port-police off`, on FW-C2 `ddos-guard off`, then on LORA-GW: `nping --tcp -p 8883 --flags syn --rate 3000 -c 0 -H 10.2.200.10` (Ctrl+C to stop) | `tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.dst == 10.2.200.10` | Statistics > I/O Graph (packets/s) | C7 DDoS | ~3 000 SYN/s from 10.2.50.10 crossing the trunk |
| `p2_synflood_after_guard` | `FW-C2:eth2` (broker side), same flood, with `ddos-guard on` | same filter | I/O Graph | C7 DDoS | only ~20 SYN/s reach the broker (firewall per-source limit) |
| `p2_synflood_edge` | `FW-C2:eth1` again, same flood, with `port-police on` on CABINET-SW | same filter | I/O Graph + on CABINET-SW: `port-police status` | C7 DDoS (edge) | the trunk carries only ~130 SYN/s; the switch reports millions of dropped packets |
| `p2_antispoof` | `FW-C2:eth1`, on LORA-GW: `nping --tcp -p 8883 -S 10.9.9.9 -c 5 10.2.200.10` | `ip.src == 10.9.9.9` | — then same filter on `FW-C2:eth2` | C7 egress filtering | spoofed packets seen on the trunk, **never** on the broker side |

Tips: right-click a field → **Apply as Column** to show DSCP / VLAN ID / AS_PATH in the packet list; **File > Export Specified Packets** to save only the frames you screenshot.

---

## 4. Results (latest run — see `results/` for full tables)

| Test | Key result |
|---|---|
| Access control (C2, C5, C6) | **18/18 flows match Table 3** in secure mode; with a flat network 14/18 flows get through — 6 flows that the design forbids become possible |
| Device identity (C1) | valid certificate accepted; rogue CA, no certificate and plaintext rejected |
| Data breach (C3) | plaintext MQTT exposes the payment token on the wire; mutual TLS shows only encrypted records |
| Failover (S6) | 1320 ms outage after a silent ring-link cut, traffic rerouted via C5 |
| Scalability (S1) | 100 → 10 000 devices: 0 % loss, p99 ≤ 36.44 ms; cloud receives only summaries (≥ 99.87 % less upstream traffic) |
| Scalability (S2) | new cluster C6 learned by the ring in 6.4 s with 0 changes to existing routers |
| QoS (S5) | congested uplink: EF safety traffic ≈ 0.3 ms with QoS on vs ≈ 354 ms with QoS off |
| DDoS (C7) | legit p95 during attack: no protection ≈ 2 962 ms → firewall guard ≈ 492 ms → + edge port policing ≈ 1.6 ms, 0 % loss |


Flows that a flat network would allow but the design blocks:
- Transit -> fog broker 1883 (plaintext)
- EV charger -> fog broker 8883
- EV charger -> signal controller
- LoRa sensors -> signal controller CoAP
- Public Wi-Fi -> signal controller CoAP
- Public Wi-Fi -> payment zone (EV charger)

#### Access-control matrix — firewall SECURE mode

| Flow                                            | Source      | Result  | Expected (design) | Check |
|-------------------------------------------------|-------------|---------|-------------------|-------|
| Safety ctrl -> fog broker 8883 (mTLS)           | SIGNAL-CTRL | ALLOWED | ALLOWED           | PASS  |
| RSU -> signal controller CoAP 5683 (preemption) | RSU         | ALLOWED | ALLOWED           | PASS  |
| Transit -> fog broker 8883 (mTLS)               | TRANSIT-GW  | ALLOWED | ALLOWED           | PASS  |
| Transit -> fog broker 1883 (plaintext)          | TRANSIT-GW  | blocked | blocked           | PASS  |
| EV charger -> payment processor 443 (TLS)       | EV-CHARGER  | ALLOWED | ALLOWED           | PASS  |
| EV charger -> fog broker 8883                   | EV-CHARGER  | blocked | blocked           | PASS  |
| EV charger -> signal controller                 | EV-CHARGER  | blocked | blocked           | PASS  |
| LoRa sensors -> fog broker 8883 (mTLS)          | LORA-GW     | ALLOWED | ALLOWED           | PASS  |
| LoRa sensors -> signal controller CoAP          | LORA-GW     | blocked | blocked           | PASS  |
| LoRa sensors -> Internet (botnet egress)        | LORA-GW     | blocked | blocked           | PASS  |
| Public Wi-Fi -> Internet                        | PUBLIC-WIFI | ALLOWED | ALLOWED           | PASS  |
| Public Wi-Fi -> signal controller CoAP          | PUBLIC-WIFI | blocked | blocked           | PASS  |
| Public Wi-Fi -> fog broker 8883                 | PUBLIC-WIFI | blocked | blocked           | PASS  |
| Public Wi-Fi -> payment zone (EV charger)       | PUBLIC-WIFI | blocked | blocked           | PASS  |
| Mgmt jump host -> signal controller             | MGMT-JUMP   | ALLOWED | ALLOWED           | PASS  |
| Internet attacker -> cloud front door 8883      | ATTACKER    | ALLOWED | ALLOWED           | PASS  |
| Internet attacker -> signal controller          | ATTACKER    | blocked | blocked           | PASS  |
| Internet attacker -> fog broker                 | ATTACKER    | blocked | blocked           | PASS  |

Firewall counters (packets that matched each rule):
```
iifname "eth1.10" ip daddr 10.2.200.10 tcp dport 8883 counter packets 1 bytes 60 accept comment "safety->broker"
		iifname "eth1.20" oifname "eth1.10" udp dport 5683 counter packets 1 bytes 39 accept comment "rsu->controller preemption"
		iifname "eth1.30" ip daddr 10.2.200.10 tcp dport 8883 counter packets 1 bytes 60 accept comment "transit->broker"
		iifname "eth1.40" ip daddr 10.100.1.10 tcp dport 443 counter packets 1 bytes 60 accept comment "payment->processor TLS"
		iifname "eth1.50" ip daddr 10.2.200.10 tcp dport 8883 counter packets 1 bytes 60 accept comment "sensors->broker"
		iifname "eth1.90" ip daddr != 10.0.0.0/8 counter packets 1 bytes 84 accept comment "public->internet"
		iifname "eth1.99" counter packets 1 bytes 84 accept comment "mgmt->all"
		counter packets 35 bytes 2088 comment "forward-default-deny"
```

#### Device identity — mutual TLS at the cloud broker

| Case                              | From      | Result   | Check | Client message                  |
|-----------------------------------|-----------|----------|-------|---------------------------------|
| Valid device certificate (lab CA) | EDGE-C4   | accepted | PASS  |                                 |
| Rogue certificate (untrusted CA)  | ATTACKER  | rejected | PASS  | Error: The connection was lost. |
| No client certificate             | INET-USER | rejected | PASS  | Error: The connection was lost. |
| Plaintext (no TLS) to 8883        | INET-USER | rejected | PASS  | Error: Protocol error           |

Broker log:
```
1795466223: OpenSSL Error[0]: error:0A000086:SSL routines::certificate verify failed
1795466223: Client <unknown> disconnected: Protocol error.
1795466223: New connection from 198.18.0.10:48816 on port 8883.
1795466223: OpenSSL Error[0]: error:0A0000C7:SSL routines::peer did not return a certificate
1795466223: Client <unknown> disconnected: Protocol error.
1795466224: New connection from 198.18.0.10:48826 on port 8883.
1795466224: OpenSSL Error[0]: error:0A000418:SSL routines::tlsv1 alert unknown ca
1795466224: Client <unknown> disconnected: Protocol error.
```

#### Data-breach test — what an on-path attacker sees

| Transport      | Capture                            | Payment data visible? |
|----------------|------------------------------------|-----------------------|
| plaintext_1883 | results/breach_plaintext_1883.pcap | YES — readable        |
| mtls_8883      | results/breach_mtls_8883.pcap      | no — encrypted        |

Open both pcaps in Wireshark: filter `mqtt` on the plaintext capture shows the payload; `tls` on the mTLS capture shows only Application Data.

#### Failover — ring link C1–C2 cut (OSPF + BFD)

| Metric                        | Value                                          |
|-------------------------------|------------------------------------------------|
| Probe                         | EDGE-C1 → FW-C2 (path over C1–C2) every 20 ms  |
| Packets lost                  | 66                                             |
| Measured outage / convergence | ~1320 ms                                       |
| Path before cut (FOG-C1)      | 10.254.0.2 (eth0)                              |
| Path after cut (FOG-C1)       | 10.254.0.17 (eth1)                             |
| Design target                 | no single link failure isolates a cluster (S6) |

#### Scalability — devices added step by step (fog broker C2, mutual TLS, 1 msg/s per device)

| Devices | Gateways | Target msg/s | Fog msg/s | Loss % | p50 ms | p95 ms | p99 ms | Cloud msgs (summaries) | Upstream reduction |
|---------|----------|--------------|-----------|--------|--------|--------|--------|------------------------|--------------------|
| 100     | 5        | 100.0        | 100.0     | 0.0    | 0.31   | 0.52   | 1.58   | 4                      | 99.87%             |
| 500     | 5        | 500.0        | 499.8     | 0.0    | 0.26   | 9.89   | 30.38  | 4                      | 99.97%             |
| 2000    | 10       | 2000.0       | 1998.3    | 0.0    | 0.27   | 3.25   | 8.12   | 4                      | 99.99%             |
| 5000    | 20       | 5000.0       | 4996.0    | 0.0    | 0.36   | 29.14  | 36.44  | 4                      | 100.00%            |
| 10000   | 40       | 10000.0      | 9992.3    | 0.0    | 1.64   | 6.35   | 17.79  | 4                      | 100.00%            |

S1: the fog aggregator forwards one summary per class every 10 s, so cloud traffic stays flat while device count grows.

#### QoS — latency to the cloud while bulk sensor traffic saturates the 10 Mbit/s fog uplink

| Mode    | Traffic class  | Avg RTT ms | Max RTT ms | Loss |
|---------|----------------|------------|------------|------|
| QoS OFF | EF (safety)    | 354.158    | 402.05     | 0%   |
| QoS OFF | AF31 (transit) | 354.422    | 402.787    | 0%   |
| QoS OFF | CS1 (public)   | 354.196    | 402.084    | 0%   |
| QoS ON  | EF (safety)    | 0.33       | 0.848      | 0%   |
| QoS ON  | AF31 (transit) | 0.334      | 0.858      | 0%   |
| QoS ON  | CS1 (public)   | 0.994      | 1.704      | 0%   |

DSCP is set at the fog firewall (trust boundary): EF for VLAN 10/20, AF31 transit, AF21 payment, CS1 sensors/public.

#### DDoS — 3 000 SYN/s from a compromised sensor gateway (→ fog broker) + 3 000 SYN/s from an Internet botnet (→ cloud front door)

Legitimate traffic: 50 transit devices publishing over mutual TLS to the fog broker (one-way latency).

| Protection level              | Legit p95 ms (no attack) | Legit p50 ms (attack) | Legit p95 ms (attack) | Legit p99 ms (attack) | Legit loss % | Cloud connect OK | SYNs dropped at cabinet switch | SYNs dropped at FW-C2 | SYNs dropped at DC-A |
|-------------------------------|--------------------------|-----------------------|-----------------------|-----------------------|--------------|------------------|--------------------------------|-----------------------|----------------------|
| 1 none                        | 0.52                     | 171.47                | 2962.05               | 3416.6                | 0.0          | yes              | 0                              | 0                     | 0                    |
| 2 firewall + front-door guard | 0.51                     | 89.04                 | 492.11                | 802.91                | 0.0          | yes              | 0                              | 311068                | 235773               |
| 3 guard + edge port policing  | 0.64                     | 0.46                  | 1.64                  | 5.1                   | 0.0          | yes              | 2279785                        | 1190                  | 302605               |

Controls (Table 2, C7): per-port SYN policing at the cabinet switch (edge), per-source SYN limit + global SYN cap + per-source connection limit at the fog firewall, front-door SYN limits at DC-A, SYN cookies, egress anti-spoofing, no Internet egress for sensors.

#### Scalability S2 — adding cluster C6 without redesign

| Item                                 | Result                                                                       |
|--------------------------------------|------------------------------------------------------------------------------|
| New fog router                       | FOG-C6, dual-homed to FOG-C4 (eth2) and FOG-C2 (eth3), ports pre-provisioned |
| Config changes on existing routers   | 0                                                                            |
| Route 10.6.50.0/24 learned by FOG-C1 | after 6.4 s                                                                  |
| EDGE-C6 → cloud reachability         | OK                                                                           |

---

## 5. Rebuild from scratch (on the server)

```bash
cd ~/projects/IoT_Applications/simulation
docker build -t iot-lab/router:1.0 images/iot-router      # FRR + nftables + tc + tools
docker build -t iot-lab/host:1.0   images/iot-host        # MQTT broker/clients, CoAP, sensor tools, nmap/nping
python3 scripts/build_project.py --rebuild                 # creates the GNS3 project, writes every node's config
```
Then start all nodes in the web UI. Node configs live in each node's persistent `/etc/lab` (and `/etc/frr` on routers), generated by `scripts/build_project.py`; the lab certificates are in `configs/pki/` (throwaway, lab-only keys).

### Submission package
- **Simulation files:** `simulation/` folder (scripts, Dockerfiles, configs, results) + the portable GNS3 project in `export/` (`IoT_Smart_City_Phase2.gns3project`; import with *File > Import portable project* — the Docker images must be built first with the two `docker build` commands).
- **Report:** use the tables from `results/*.md` and the Wireshark screenshots from section 3.
- **Video:** suggested script — topology tour in the web UI (1 min) → `access secure` vs `open` (1 min) → `breach` in Wireshark (1 min) → `failover` with the I/O graph (1 min) → `qos` and `ddos` tables (1 min) → `add-cluster` (30 s).

## 6. Files

| Path | Purpose |
|---|---|
| `scripts/build_project.py` | Builds the whole GNS3 project and every node's configuration from code |
| `scripts/labctl.py` | Runs the Phase 2 tests and writes results |
| `scripts/gns3api.py` | Minimal GNS3 v3 API client (stdlib only) |
| `scripts/mac-capture.sh` | Live capture from any node interface into Wireshark on the Mac |
| `images/iot-router/` | Router/firewall image (FRR, nftables, tc) |
| `images/iot-host/` | Host image (mosquitto, paho-mqtt tools, libcoap, nmap/nping, iperf3) + `bin/sensor-sim`, `bin/latency-sink`, `bin/fog-aggregator` |
| `configs/pki/` | Lab CA, broker, device and rogue certificates |
| `results/` | Test outputs (`*.md` tables for the report, `*.json`, `scale.csv`, pcaps) |
| `requirements.txt` | Python packages (none required; `paho-mqtt` optional) |

## 7. Known issues and lessons (useful for "suggested improvements")

- **AppArmor on the host** (Ubuntu ships a profile for `/usr/sbin/mosquitto`) also confined the privileged GNS3 containers and blocked the broker from reading its config → the lab runs the broker as `/usr/local/sbin/mqtt-broker`.
- **GNS3 built-in Ethernet switch (dynamips)** did not forward the 802.1Q trunk reliably → the cabinet switch is a Linux VLAN-aware bridge (more realistic anyway).
- **GNS3 link "suspend"** breaks Docker links with this uBridge version → the failover test simulates the fiber cut inside the routers (`tc netem loss 100%` on both ends = silent failure that BFD must detect).
- **GNS3 links are UDP tunnels (uBridge), and GNS3 creates Docker interfaces with MTU 65 521.** Under bulk traffic a container then sends frames bigger than a UDP datagram can carry; uBridge fails with `send: Message too long` and that link stops forever (symptom: one host suddenly can't reach its gateway). Both lab images set **MTU 1500** and disable segmentation offloads on every `eth*` at boot (`ip link set ethX mtu 1500; ethtool -K ethX tso off gso off gro off tx off`). Tests also cap bulk traffic at 16 Mbit/s and SYN floods at 3 000 SYN/s — still far above the 10 Mbit/s uplink and the 20 SYN/s per-source limit. If a node ever loses a link: delete and redraw the link in the web UI (or restart the node).
