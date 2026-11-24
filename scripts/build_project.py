#!/usr/bin/env python3
"""Build the GNS3 project "IoT Smart City - Phase 2" from code.

Implements the Phase 1 design (metro-Atlanta transportation IoT):
  * 5 fog clusters on a ring C1-C2-C4-C3-C5-C1 (OSPFv2 + OSPFv3, BFD for fast failover)
  * DC-A on C1, DC-B dual-homed to C3 and C5; eBGP to ISP-1 / ISP-2; Internet segment with an attacker
  * Cluster C2 (Marietta/Smyrna) in detail: fog firewall (zone matrix of Table 3, DSCP marking,
    QoS, DDoS guard), cabinet switch with VLANs 10/20/30/40/50/90/99, edge devices,
    fog MQTT broker (mTLS) + fog aggregator bridging only summaries to the cloud broker at DC-A
  * One edge gateway per other cluster (C1, C3, C4, C5)
Usage:  python3 build_project.py [--rebuild]
"""
import os, sys, shutil, time, json
sys.path.insert(0, os.path.dirname(__file__))
from gns3api import req

PROJECT = "IoT Smart City - Phase 2"
SIM = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKI = os.path.join(SIM, "configs", "pki")
GNS3_PROJECTS = "/mnt/storage/gns3/projects"

# ---------------------------------------------------------------- addressing
LOOP = {"FOG-C1": 1, "FOG-C2": 2, "FOG-C3": 3, "FOG-C4": 4, "FOG-C5": 5, "DC-A": 11, "DC-B": 12, "FW-C2": 22,
        "ISP-1": 101, "ISP-2": 102}
# point-to-point links: (nodeA, ifA, ipA, nodeB, ifB, ipB, kind)
P2P = [
    ("FOG-C1", "eth0", "10.254.0.1/30",  "FOG-C2", "eth0", "10.254.0.2/30",  "ring"),
    ("FOG-C2", "eth1", "10.254.0.5/30",  "FOG-C4", "eth0", "10.254.0.6/30",  "ring"),
    ("FOG-C4", "eth1", "10.254.0.9/30",  "FOG-C3", "eth0", "10.254.0.10/30", "ring"),
    ("FOG-C3", "eth1", "10.254.0.13/30", "FOG-C5", "eth0", "10.254.0.14/30", "ring"),
    ("FOG-C5", "eth1", "10.254.0.17/30", "FOG-C1", "eth1", "10.254.0.18/30", "ring"),
    ("FOG-C1", "eth2", "10.254.0.21/30", "DC-A",   "eth0", "10.254.0.22/30", "dc"),
    ("FOG-C3", "eth2", "10.254.0.25/30", "DC-B",   "eth0", "10.254.0.26/30", "dc"),
    ("FOG-C5", "eth2", "10.254.0.29/30", "DC-B",   "eth1", "10.254.0.30/30", "dc"),
    ("FOG-C2", "eth2", "10.254.0.33/30", "FW-C2",  "eth0", "10.254.0.34/30", "dc"),
    ("DC-A",   "eth2", "203.0.113.1/30", "ISP-1",  "eth0", "203.0.113.2/30", "bgp"),
    ("DC-B",   "eth2", "198.51.100.1/30", "ISP-2", "eth0", "198.51.100.2/30", "bgp"),
    ("ISP-1",  "eth1", "192.0.2.1/30",   "ISP-2",  "eth1", "192.0.2.2/30",   "bgp"),
]
# reserved for the "add cluster C6" scalability test (S2): pre-configured, unconnected until the test
RESERVED = [("FOG-C4", "eth2", "10.254.0.37/30"), ("FOG-C2", "eth3", "10.254.0.41/30")]
# edge LANs on fog routers (other clusters): router, iface, cluster
EDGE_LAN = [("FOG-C1", "eth3", 1), ("FOG-C3", "eth3", 3), ("FOG-C4", "eth3", 4), ("FOG-C5", "eth3", 5)]
# C2 zones: vlan -> (name, IPv4 /24, IPv6 /64 of sample site 0x02A)
ZONES = {10: ("safety", "10.2.10", "2001:db8:2:102a"), 20: ("v2x", "10.2.20", "2001:db8:2:202a"),
         30: ("transit", "10.2.30", "2001:db8:2:302a"), 40: ("payment", "10.2.40", "2001:db8:2:402a"),
         50: ("sensors", "10.2.50", "2001:db8:2:502a"), 90: ("public", "10.2.90", "2001:db8:2:902a"),
         99: ("mgmt", "10.2.99", "2001:db8:2:f02a")}
FOG_SVC = ("10.2.200", "2001:db8:2:e000")
CLOUD = ("10.100.1", "2001:db8:a:1")
INET = "198.18.0"

# ---------------------------------------------------------------- layout (x, y)
POS = {
    "INET-USER": (-260, -560), "ATTACKER": (-60, -560), "INTERNET-SW": (-160, -470),
    "ISP-1": (-260, -370), "ISP-2": (260, -370),
    "DC-A": (-260, -250), "CLOUD-A": (-500, -250), "DC-B": (300, -230),
    "FOG-C1": (-260, -110), "FOG-C5": (260, -110), "FOG-C3": (330, 110), "FOG-C4": (20, 250), "FOG-C2": (-380, 110),
    "EDGE-C1": (-60, -170), "EDGE-C5": (470, -150), "EDGE-C3": (540, 160), "EDGE-C4": (20, 400),
    "FW-C2": (-620, 110), "BROKER-C2": (-620, -40), "CABINET-SW": (-860, 110),
    "SIGNAL-CTRL": (-1100, -120), "RSU": (-1130, -10), "TRANSIT-GW": (-1140, 100), "EV-CHARGER": (-1130, 210),
    "LORA-GW": (-1100, 320), "PUBLIC-WIFI": (-960, 400), "MGMT-JUMP": (-820, 400),
}

# ---------------------------------------------------------------- FRR config
OSPF_IF = """ ip ospf area 0
 ip ospf network point-to-point
 ip ospf hello-interval 1
 ip ospf dead-interval 4
 ip ospf bfd
 ip ospf bfd profile fast
 ipv6 ospf6 area 0
 ipv6 ospf6 network point-to-point
 ipv6 ospf6 hello-interval 1
 ipv6 ospf6 dead-interval 4
 ipv6 ospf6 bfd
"""


def frr_conf(name):
    rid = f"10.255.0.{LOOP[name]}"
    out = [f"frr defaults traditional", f"hostname {name}", "log syslog informational", "service integrated-vtysh-config", "!",
           "bfd", " profile fast", "  transmit-interval 150", "  receive-interval 150", "  detect-multiplier 3", " exit", "exit", "!",
           "interface lo", f" ip address {rid}/32", f" ipv6 address 2001:db8:ffff::{LOOP[name]}/128", "exit", "!"]
    ospf = name.startswith("FOG") or name in ("DC-A", "DC-B", "FW-C2")
    for a, ia, ipa, b, ib, ipb, kind in P2P:
        for me, iface, ip, peer in ((a, ia, ipa, b), (b, ib, ipb, a)):
            if me != name:
                continue
            out += [f"interface {iface}", f" description to {peer}", f" ip address {ip}"]
            if kind in ("ring", "dc"):
                out.append(OSPF_IF.rstrip("\n"))
            out += ["exit", "!"]
    for me, iface, ip in RESERVED:
        if me == name:
            out += [f"interface {iface}", " description reserved: new cluster C6 (S2 test)", f" ip address {ip}", OSPF_IF.rstrip("\n"), "exit", "!"]
    for me, iface, c in EDGE_LAN:
        if me == name:
            out += [f"interface {iface}", f" description edge LAN cluster C{c}", f" ip address 10.{c}.50.1/24",
                    f" ipv6 address 2001:db8:{c}:502a::1/64", "exit", "!"]
    if name == "FW-C2":
        for v, (zn, p4, p6) in ZONES.items():
            out += [f"interface eth1.{v}", f" description VLAN {v} {zn}", f" ip address {p4}.1/24", f" ipv6 address {p6}::1/64", "exit", "!"]
        out += ["interface eth2", " description fog services (broker, aggregator, LNS)", f" ip address {FOG_SVC[0]}.1/24",
                f" ipv6 address {FOG_SVC[1]}::1/64", "exit", "!"]
    if name == "DC-A":
        out += ["interface eth1", " description cloud services LAN (broker, API, payment processor)", f" ip address {CLOUD[0]}.1/24",
                f" ipv6 address {CLOUD[1]}::1/64", "exit", "!"]
    if name == "ISP-1":
        out += ["interface eth2", " description Internet users / botnet", f" ip address {INET}.1/24", "exit", "!"]
    if ospf:
        out += ["router ospf", f" ospf router-id {rid}", " redistribute connected", " passive-interface default"]
        for a, ia, ipa, b, ib, ipb, kind in P2P:
            for me, iface in ((a, ia), (b, ib)):
                if me == name and kind in ("ring", "dc"):
                    out.append(f" no passive-interface {iface}")
        for me, iface, ip in RESERVED:
            if me == name:
                out.append(f" no passive-interface {iface}")
        if name in ("DC-A", "DC-B"):
            out.append(" default-information originate metric " + ("10" if name == "DC-A" else "20"))
        out += ["exit", "!", "router ospf6", f" ospf6 router-id {rid}", " redistribute connected", "exit", "!"]
    # BGP: city AS 65000 at the two data centers; ISPs 64501/64502
    if name in ("DC-A", "DC-B", "ISP-1", "ISP-2"):
        asn = {"DC-A": 65000, "DC-B": 65000, "ISP-1": 64501, "ISP-2": 64502}[name]
        nbrs = {"DC-A": [("203.0.113.2", 64501)], "DC-B": [("198.51.100.2", 64502)],
                "ISP-1": [("203.0.113.1", 65000), ("192.0.2.2", 64502)], "ISP-2": [("198.51.100.1", 65000), ("192.0.2.1", 64501)]}[name]
        out += [f"router bgp {asn}", f" bgp router-id {rid}", " no bgp ebgp-requires-policy", " no bgp network import-check"]
        for ip, ras in nbrs:
            out.append(f" neighbor {ip} remote-as {ras}")
        out.append(" address-family ipv4 unicast")
        if name in ("DC-A", "DC-B"):
            out.append(f"  network {CLOUD[0]}.0/24")        # anycast front door: both DCs announce the cloud prefix
            if name == "DC-B":                              # DC-B is the backup path: prepend
                out += ["  neighbor 198.51.100.2 route-map PREPEND out"]
        if name == "ISP-1":
            out += [f"  network {INET}.0/24", "  neighbor 203.0.113.1 default-originate"]
        if name == "ISP-2":
            out += ["  neighbor 198.51.100.1 default-originate"]
        out += [" exit-address-family", "exit", "!"]
        if name == "DC-B":
            out += ["route-map PREPEND permit 10", " set as-path prepend 65000 65000", "exit", "!"]
    out.append("end")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------- host / service configs
def sh(lines):
    return "#!/bin/bash\n# generated by build_project.py\n" + "\n".join(lines) + "\n"


def host_net(ip4, gw4, ip6=None, gw6=None):
    l = [f"ip addr add {ip4} dev eth0", f"ip route add default via {gw4}"]
    if ip6:
        l += [f"ip -6 addr add {ip6} dev eth0", f"ip -6 route add default via {gw6}"]
    return l


HOSTS = {  # name -> (ip4/len, gw4, ip6/len, gw6, extra startup lines, role)
    "SIGNAL-CTRL": (f"{ZONES[10][1]}.10/24", f"{ZONES[10][1]}.1", f"{ZONES[10][2]}::10/64", f"{ZONES[10][2]}::1",
                    ["coap-server -A 10.2.10.10 -p 5683 >/var/log/coap.log 2>&1 &   # preemption request endpoint (CoAP/UDP)"],
                    "Signal controller (VLAN 10 safety)"),
    "RSU": (f"{ZONES[20][1]}.10/24", f"{ZONES[20][1]}.1", f"{ZONES[20][2]}::10/64", f"{ZONES[20][2]}::1", [], "Roadside unit C-V2X (VLAN 20)"),
    "TRANSIT-GW": (f"{ZONES[30][1]}.10/24", f"{ZONES[30][1]}.1", f"{ZONES[30][2]}::10/64", f"{ZONES[30][2]}::1", [], "Transit/station gateway (VLAN 30)"),
    "EV-CHARGER": (f"{ZONES[40][1]}.10/24", f"{ZONES[40][1]}.1", f"{ZONES[40][2]}::10/64", f"{ZONES[40][2]}::1", [], "EV charger + payment (VLAN 40)"),
    "LORA-GW": (f"{ZONES[50][1]}.10/24", f"{ZONES[50][1]}.1", f"{ZONES[50][2]}::10/64", f"{ZONES[50][2]}::1", [], "LoRaWAN gateway: parking/env sensors (VLAN 50)"),
    "PUBLIC-WIFI": (f"{ZONES[90][1]}.10/24", f"{ZONES[90][1]}.1", f"{ZONES[90][2]}::10/64", f"{ZONES[90][2]}::1", [], "Public Wi-Fi client / insider attacker (VLAN 90)"),
    "MGMT-JUMP": (f"{ZONES[99][1]}.10/24", f"{ZONES[99][1]}.1", f"{ZONES[99][2]}::10/64", f"{ZONES[99][2]}::1", [], "Management jump host (VLAN 99)"),
    "BROKER-C2": (f"{FOG_SVC[0]}.10/24", f"{FOG_SVC[0]}.1", f"{FOG_SVC[1]}::10/64", f"{FOG_SVC[1]}::1",
                  ["mqtt-broker -c /etc/lab/mosquitto.conf -d",
                   "sleep 1; nohup fog-aggregator --cluster c2 --window 10 >/var/log/fog-aggregator.out 2>&1 &"],
                  "Fog MQTT broker C2 (mTLS) + aggregator + bridge to cloud"),
    "CLOUD-A": (f"{CLOUD[0]}.10/24", f"{CLOUD[0]}.1", f"{CLOUD[1]}::10/64", f"{CLOUD[1]}::1",
                ["mqtt-broker -c /etc/lab/mosquitto.conf -d",
                 "nohup openssl s_server -quiet -accept 443 -cert /etc/lab/pki/cloud-a.crt -key /etc/lab/pki/cloud-a.key -www >/var/log/payment-api.log 2>&1 &   # payment processor / API (TLS)",
                 "nohup iperf3 -s -D"],
                "Cloud DC-A: broker, API/payment (TLS 443), iperf3"),
    "INET-USER": (f"{INET}.10/24", f"{INET}.1", None, None, [], "Legitimate Internet user"),
    "ATTACKER": (f"{INET}.66/24", f"{INET}.1", None, None, [], "Internet attacker / botnet"),
}
for c in (1, 3, 4, 5):
    HOSTS[f"EDGE-C{c}"] = (f"10.{c}.50.10/24", f"10.{c}.50.1", f"2001:db8:{c}:502a::10/64", f"2001:db8:{c}:502a::1", [], f"Edge gateway cluster C{c}")

MOSQ_BROKER_C2 = f"""# Fog broker C2 (generated)
user root
per_listener_settings true
log_dest file /var/log/mosquitto.log
max_queued_messages 10000

# Secure listener: mutual TLS, device identity = certificate CN (C1, C3)
listener 8883 {FOG_SVC[0]}.10
cafile /etc/lab/pki/ca.crt
certfile /etc/lab/pki/broker-c2.crt
keyfile /etc/lab/pki/broker-c2.key
require_certificate true
use_identity_as_username true
allow_anonymous false

# INSECURE plaintext listener, kept only for the data-breach demonstration (blocked by the firewall in secure mode)
listener 1883 {FOG_SVC[0]}.10
allow_anonymous true

# Local listener for the fog aggregator
listener 1884 127.0.0.1
allow_anonymous true

# Bridge: only aggregated summaries go to the cloud (S1), over mutual TLS (C3)
connection cloud-a
address {CLOUD[0]}.10:8883
bridge_cafile /etc/lab/pki/ca.crt
bridge_certfile /etc/lab/pki/broker-c2.crt
bridge_keyfile /etc/lab/pki/broker-c2.key
cleansession true
topic city/c2/summary/# out 1
"""
MOSQ_CLOUD = f"""# Cloud broker DC-A (generated)
user root
per_listener_settings true
log_dest file /var/log/mosquitto.log
listener 8883 {CLOUD[0]}.10
cafile /etc/lab/pki/ca.crt
certfile /etc/lab/pki/cloud-a.crt
keyfile /etc/lab/pki/cloud-a.key
require_certificate true
use_identity_as_username true
allow_anonymous false
"""

# ---------------------------------------------------------------- firewall FW-C2 (Table 3 zone matrix)
FW_SECURE = f"""#!/usr/sbin/nft -f
# FW-C2 fog firewall — SECURE mode: default deny, zone matrix of Table 3 (generated)
flush ruleset
table inet fw {{
  chain input {{
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iif "lo" accept
    meta l4proto {{ icmp, ipv6-icmp }} accept
    iifname "eth0" meta l4proto 89 accept                       # OSPFv2/v3 from FOG-C2
    iifname "eth0" udp dport {{ 3784, 3785, 4784 }} accept       # BFD
    iifname "eth1.99" tcp dport 22 accept                       # management only from VLAN 99
    counter comment "input-default-deny"
  }}
  chain forward {{
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
    ct state invalid counter drop
    jump antispoof
    jump ddos
    # --- Zone 1 safety (VLAN 10): edge gateway -> fog broker; fog coordination -> controllers; nothing from Internet
    iifname "eth1.10" ip daddr {FOG_SVC[0]}.10 tcp dport 8883 counter accept comment "safety->broker"
    iifname "eth2" oifname "eth1.10" counter accept comment "fog coordination->safety"
    # --- Zone 2 V2X (VLAN 20): RSU -> controller preemption request only (CoAP/UDP 5683), RSU -> broker
    iifname "eth1.20" oifname "eth1.10" udp dport 5683 counter accept comment "rsu->controller preemption"
    iifname "eth1.20" ip daddr {FOG_SVC[0]}.10 tcp dport 8883 counter accept comment "rsu->broker"
    # --- Zone 3 transit (VLAN 30): broker only
    iifname "eth1.30" ip daddr {FOG_SVC[0]}.10 tcp dport 8883 counter accept comment "transit->broker"
    # --- Zone 4 payment/EV (VLAN 40): payment processor over TLS only, isolated from all zones
    iifname "eth1.40" ip daddr {CLOUD[0]}.10 tcp dport 443 counter accept comment "payment->processor TLS"
    # --- Zone 5 bulk sensors (VLAN 50): LoRaWAN network server / broker only (no Internet = no botnet egress)
    iifname "eth1.50" ip daddr {FOG_SVC[0]}.10 tcp dport 8883 counter accept comment "sensors->broker"
    # --- Zone 9 public (VLAN 90): Internet only, never internal
    iifname "eth1.90" ip daddr != 10.0.0.0/8 counter accept comment "public->internet"
    # --- Zone F management (VLAN 99): jump hosts reach devices; cloud management -> jump host SSH
    iifname "eth1.99" counter accept comment "mgmt->all"
    iifname "eth0" ip saddr {CLOUD[0]}.0/24 oifname "eth1.99" tcp dport 22 counter accept comment "cloud mgmt->jump"
    # --- fog services -> cloud broker bridge (mTLS)
    iifname "eth2" ip daddr {CLOUD[0]}.10 tcp dport 8883 counter accept comment "fog bridge->cloud"
    # --- diagnostics: zones may ping backbone/cloud (latency measurements), not each other
    iifname "eth1.*" icmp type echo-request ip daddr {{ 10.254.0.0/16, 10.255.0.0/16, {CLOUD[0]}.0/24 }} counter accept comment "diag ping upstream"
    counter comment "forward-default-deny"
  }}
  chain antispoof {{
    # egress filtering (C7): a device may only send with its own zone's source address
    iifname "eth1.10" ip saddr != {ZONES[10][1]}.0/24 counter drop
    iifname "eth1.20" ip saddr != {ZONES[20][1]}.0/24 counter drop
    iifname "eth1.30" ip saddr != {ZONES[30][1]}.0/24 counter drop
    iifname "eth1.40" ip saddr != {ZONES[40][1]}.0/24 counter drop
    iifname "eth1.50" ip saddr != {ZONES[50][1]}.0/24 counter drop
    iifname "eth1.90" ip saddr != {ZONES[90][1]}.0/24 counter drop
    iifname "eth1.99" ip saddr != {ZONES[99][1]}.0/24 counter drop
  }}
  chain ddos {{
    # filled by 'ddos-guard on'
  }}
  chain classify {{
    type filter hook prerouting priority -150; policy accept;
    # DiffServ classification at the trust boundary (S5): EF for safety/V2X, AF31 transit, AF21 payment, CS1 bulk/public
    iifname "eth1.10" ip dscp set ef
    iifname "eth1.20" ip dscp set ef
    iifname "eth1.30" ip dscp set af31
    iifname "eth1.40" ip dscp set af21
    iifname "eth1.50" ip dscp set cs1
    iifname "eth1.90" ip dscp set cs1
  }}
}}
"""
FW_OPEN = """#!/usr/sbin/nft -f
# FW-C2 — OPEN mode (baseline for comparison): flat network, no zone filtering, no DSCP marking
flush ruleset
table inet fw {
  chain forward {
    type filter hook forward priority 0; policy accept;
    counter
  }
}
"""
FW_MODE = """#!/bin/bash
# fw-mode secure|open|status — switch the C2 fog firewall between the designed zone matrix and a flat baseline
case "$1" in
  secure) nft -f /etc/lab/fw-secure.nft && echo secure > /etc/lab/.fwmode && echo "firewall: SECURE (zone matrix, default deny)";;
  open)   nft -f /etc/lab/fw-open.nft   && echo open > /etc/lab/.fwmode   && echo "firewall: OPEN (flat baseline)";;
  status|*) echo "firewall: $(cat /etc/lab/.fwmode 2>/dev/null || echo unknown)"; nft list ruleset | grep -E 'counter packets [1-9]' | sed 's/^ */  /';;
esac
"""
DDOS_GUARD_FW = f"""#!/bin/bash
# ddos-guard on|off|status — C7 controls on the fog firewall protecting the fog broker {FOG_SVC[0]}.10
B={FOG_SVC[0]}.10
case "$1" in
  on)
    nft flush chain inet fw ddos
    nft add set inet fw synsrc '{{ type ipv4_addr; size 65535; flags dynamic,timeout; timeout 30s; }}' 2>/dev/null
    nft add set inet fw connsrc '{{ type ipv4_addr; size 65535; flags dynamic; }}' 2>/dev/null
    # per-source SYN rate limit (zone/device rate limit)
    nft add rule inet fw ddos ip daddr $B tcp flags \\& \\(syn\\|ack\\) == syn add @synsrc {{ ip saddr limit rate over 20/second burst 40 packets }} counter drop comment \\"per-source SYN limit\\"
    # global SYN cap towards the broker
    nft add rule inet fw ddos ip daddr $B tcp flags \\& \\(syn\\|ack\\) == syn limit rate over 400/second burst 800 packets counter drop comment \\"global SYN cap\\"
    # per-source concurrent connection limit
    nft add rule inet fw ddos ip daddr $B tcp dport 8883 ct state new add @connsrc {{ ip saddr ct count over 50 }} counter reject with tcp reset comment \\"per-source conn limit\\"
    echo "ddos-guard: ON";;
  off) nft flush chain inet fw ddos; echo "ddos-guard: OFF";;
  *) nft list chain inet fw ddos;;
esac
"""
QOS_FW = """#!/bin/bash
# qos on|off|status — uplink eth0 (fog -> backbone) is shaped to 10 Mbit/s to emulate a congested backhaul.
#   off: single FIFO (no priority)       on: HTB with strict priority for EF (safety/V2X), weights for AF, rest best effort (S5)
DEV=eth0; RATE=10mbit
case "$1" in
  on)
    tc qdisc del dev $DEV root 2>/dev/null
    tc qdisc add dev $DEV root handle 1: htb default 30
    tc class add dev $DEV parent 1: classid 1:1 htb rate $RATE ceil $RATE
    tc class add dev $DEV parent 1:1 classid 1:10 htb rate 2mbit ceil $RATE prio 0    # EF (policed share, strict priority)
    tc class add dev $DEV parent 1:1 classid 1:20 htb rate 4mbit ceil $RATE prio 1    # AF31/AF21 transit, payment
    tc class add dev $DEV parent 1:1 classid 1:30 htb rate 4mbit ceil $RATE prio 2    # best effort / CS1 bulk
    tc qdisc add dev $DEV parent 1:10 handle 10: pfifo limit 50
    tc qdisc add dev $DEV parent 1:20 handle 20: fq_codel
    tc qdisc add dev $DEV parent 1:30 handle 30: fq_codel
    tc filter add dev $DEV parent 1: protocol ip prio 1 u32 match ip dsfield 0xb8 0xfc flowid 1:10   # EF
    tc filter add dev $DEV parent 1: protocol ip prio 2 u32 match ip dsfield 0x68 0xfc flowid 1:20   # AF31
    tc filter add dev $DEV parent 1: protocol ip prio 2 u32 match ip dsfield 0x48 0xfc flowid 1:20   # AF21
    tc filter add dev $DEV parent 1: protocol ip prio 3 u32 match ip protocol 89 0xff flowid 1:10    # OSPF control plane
    echo "qos: ON (HTB + EF strict priority, uplink $RATE)";;
  off)
    tc qdisc del dev $DEV root 2>/dev/null
    tc qdisc add dev $DEV root tbf rate $RATE burst 32kbit latency 400ms
    echo "qos: OFF (single FIFO, uplink $RATE)";;
  *) tc -s qdisc show dev $DEV;;
esac
"""
# DC-A front door (anycast entry from the Internet): only the cloud service ports, NAT for public Wi-Fi, DDoS guard
DCA_FW = f"""#!/usr/sbin/nft -f
# DC-A front door (generated)
flush ruleset
table inet frontdoor {{
  chain forward {{
    type filter hook forward priority 0; policy accept;
    ct state established,related accept
    jump ddos
    iifname "eth2" ip daddr {CLOUD[0]}.10 tcp dport {{ 443, 8883 }} counter accept comment "Internet -> cloud API/broker"
    iifname "eth2" ip daddr {CLOUD[0]}.10 icmp type echo-request counter accept
    iifname "eth2" counter drop comment "Internet -> anything else"
  }}
  chain ddos {{ }}
}}
table ip nat {{
  chain postrouting {{
    type nat hook postrouting priority 100;
    oifname "eth2" ip saddr {ZONES[90][1]}.0/24 masquerade comment "public Wi-Fi egress NAT"
  }}
}}
"""
DDOS_GUARD_DCA = f"""#!/bin/bash
# ddos-guard on|off — DC-A front door protection for the cloud broker/API {CLOUD[0]}.10 (SYN-flood protection, rate limits)
B={CLOUD[0]}.10
case "$1" in
  on)
    nft flush chain inet frontdoor ddos
    nft add set inet frontdoor synsrc '{{ type ipv4_addr; size 65535; flags dynamic,timeout; timeout 30s; }}' 2>/dev/null
    nft add rule inet frontdoor ddos iifname eth2 ip daddr $B tcp flags \\& \\(syn\\|ack\\) == syn add @synsrc {{ ip saddr limit rate over 20/second burst 40 packets }} counter drop comment \\"per-source SYN limit\\"
    nft add rule inet frontdoor ddos iifname eth2 ip daddr $B tcp flags \\& \\(syn\\|ack\\) == syn limit rate over 400/second burst 800 packets counter drop comment \\"global SYN cap\\"
    echo "front door ddos-guard: ON";;
  off) nft flush chain inet frontdoor ddos; echo "front door ddos-guard: OFF";;
  *) nft list chain inet frontdoor ddos;;
esac
"""


PORT_POLICE = '#!/bin/bash\n# port-police on|off|status — C7 per-port rate limit at the edge (cabinet switch ingress):\n# new TCP connection attempts (SYN without ACK) from the bulk-sensor (eth5, VLAN 50) and public (eth6, VLAN 90)\n# access ports are policed to 64 kbit/s (~130 SYN/s per port); floods are dropped before they reach the trunk.\nPORTS="eth5 eth6"\ncase "$1" in\n  on)\n    for p in $PORTS; do\n      tc qdisc del dev $p ingress 2>/dev/null\n      tc qdisc add dev $p ingress\n      tc filter add dev $p parent ffff: protocol ip prio 1 u32 match ip protocol 6 0xff match u8 0x02 0x12 at 33 \\\n         action police rate 64kbit burst 8k conform-exceed drop\n    done; echo "port-police: ON ($PORTS)";;\n  off) for p in $PORTS; do tc qdisc del dev $p ingress 2>/dev/null; done; echo "port-police: OFF";;\n  *) for p in $PORTS; do echo "== $p"; tc -s filter show dev $p parent ffff: | grep -E \'police|Sent|dropped\' ; done;;\nesac\n'

CABINET_ACCESS = [("SIGNAL-CTRL", 10), ("RSU", 20), ("TRANSIT-GW", 30), ("EV-CHARGER", 40), ("LORA-GW", 50), ("PUBLIC-WIFI", 90), ("MGMT-JUMP", 99)]


def node_files(name):
    """Return {relative path inside container: (content, mode)} for a node."""
    f = {}
    if name == "CABINET-SW":                            # 802.1Q switch built from a Linux VLAN-aware bridge
        l = ["# Cabinet switch: eth0 = trunk (all zone VLANs tagged) to FW-C2, eth1..eth7 = access ports",
             "ip link add br0 type bridge vlan_filtering 1 vlan_default_pvid 0 stp_state 0",
             "ip link set br0 up", "ip link set eth0 master br0 && ip link set eth0 up"]
        l += [f"bridge vlan add dev eth0 vid {v}" for _, v in CABINET_ACCESS]
        for i, (h, v) in enumerate(CABINET_ACCESS):
            l += [f"ip link set eth{i + 1} master br0 && ip link set eth{i + 1} up   # {h}",
                  f"bridge vlan add dev eth{i + 1} vid {v} pvid untagged"]
        l.append("bridge vlan show > /var/log/vlans.txt")
        l += ["ln -sf /etc/lab/port-police /usr/local/bin/", "/etc/lab/port-police on   # C7 edge rate limit (SYN policing on sensor/public ports)"]
        f["etc/lab/startup.sh"] = (sh(l), 0o755)
        f["etc/lab/port-police"] = (PORT_POLICE, 0o755)
        f["etc/lab/ROLE"] = ("Cabinet switch (802.1Q, VLANs 10/20/30/40/50/90/99)\n", 0o644)
        return f
    if name in LOOP:                                    # routers
        f["etc/frr/frr.conf"] = (frr_conf(name), 0o644)
        f["etc/frr/vtysh.conf"] = ("service integrated-vtysh-config\n", 0o644)
        start = []
        if name == "FW-C2":
            f["etc/lab/pre-frr.sh"] = (sh(["# VLAN sub-interfaces on the trunk to the cabinet switch (802.1Q)"] +
                                          [f"ip link add link eth1 name eth1.{v} type vlan id {v}; ip link set eth1.{v} up" for v in ZONES]), 0o755)
            f["etc/lab/fw-secure.nft"] = (FW_SECURE, 0o644)
            f["etc/lab/fw-open.nft"] = (FW_OPEN, 0o644)
            f["etc/lab/fw-mode"] = (FW_MODE, 0o755)
            f["etc/lab/ddos-guard"] = (DDOS_GUARD_FW, 0o755)
            f["etc/lab/qos"] = (QOS_FW, 0o755)
            start += ["ln -sf /etc/lab/fw-mode /etc/lab/ddos-guard /etc/lab/qos /usr/local/bin/",
                      "/etc/lab/fw-mode secure", "/etc/lab/qos on"]
        if name == "DC-A":
            f["etc/lab/frontdoor.nft"] = (DCA_FW, 0o644)
            f["etc/lab/ddos-guard"] = (DDOS_GUARD_DCA, 0o755)
            start += ["ln -sf /etc/lab/ddos-guard /usr/local/bin/", "nft -f /etc/lab/frontdoor.nft"]
        if name == "DC-B":
            start += [f"nft add table ip nat; nft add chain ip nat post '{{ type nat hook postrouting priority 100; }}'; nft add rule ip nat post oifname eth2 ip saddr {ZONES[90][1]}.0/24 masquerade"]
        f["etc/lab/startup.sh"] = (sh(start or [":"]), 0o755)
    else:                                               # hosts
        ip4, gw4, ip6, gw6, extra, role = HOSTS[name]
        lines = [f"# {role}"] + host_net(ip4, gw4, ip6, gw6) + extra
        f["etc/lab/startup.sh"] = (sh(lines), 0o755)
        f["etc/lab/ROLE"] = (role + "\n", 0o644)
        if name == "BROKER-C2":
            f["etc/lab/mosquitto.conf"] = (MOSQ_BROKER_C2, 0o644)
        if name == "CLOUD-A":
            f["etc/lab/mosquitto.conf"] = (MOSQ_CLOUD, 0o644)
        # PKI: brokers get their server cert; devices get the device cert; the attacker gets the rogue cert
        pki = {"BROKER-C2": ["ca.crt", "broker-c2.crt", "broker-c2.key", ("device.crt", "client.crt"), ("device.key", "client.key")],
               "CLOUD-A": ["ca.crt", "cloud-a.crt", "cloud-a.key", ("device.crt", "client.crt"), ("device.key", "client.key")],
               "ATTACKER": ["ca.crt", ("rogue.crt", "client.crt"), ("rogue.key", "client.key")],
               "PUBLIC-WIFI": ["ca.crt", ("rogue.crt", "client.crt"), ("rogue.key", "client.key")]}.get(
            name, ["ca.crt", ("device.crt", "client.crt"), ("device.key", "client.key")])
        for item in pki:
            src, dst = (item, item) if isinstance(item, str) else item
            f[f"etc/lab/pki/{dst}"] = (open(os.path.join(PKI, src)).read(), 0o600 if dst.endswith(".key") else 0o644)
    return f


# ---------------------------------------------------------------- build
def main():
    rebuild = "--rebuild" in sys.argv
    for p in req("GET", "/projects"):
        if p["name"] == PROJECT:
            if not rebuild:
                sys.exit(f"Project '{PROJECT}' exists (id {p['project_id']}). Use --rebuild to replace it.")
            if p.get("status") == "opened":
                req("POST", f"/projects/{p['project_id']}/nodes/stop", {})
            req("DELETE", f"/projects/{p['project_id']}")
            print("removed old project")
    tpl = {t["name"]: t["template_id"] for t in req("GET", "/templates")}
    pid = req("POST", "/projects", {"name": PROJECT, "auto_close": False, "show_interface_labels": True,
                                    "scene_width": 2400, "scene_height": 1400})["project_id"]
    print("project", pid)
    nodes = {}

    def add(name, template):
        x, y = POS[name]
        n = req("POST", f"/projects/{pid}/templates/{tpl[template]}", {"x": x, "y": y})
        req("PUT", f"/projects/{pid}/nodes/{n['node_id']}", {"name": name})
        nodes[name] = n["node_id"]

    for r in LOOP:
        add(r, "IoT Lab Router")
    for h in HOSTS:
        add(h, "IoT Lab Host")
    # cabinet switch (Linux VLAN-aware bridge): eth0 = 802.1Q trunk to FW-C2, eth1-eth7 = access ports per zone
    add("CABINET-SW", "IoT Lab Switch")
    access = CABINET_ACCESS
    add("INTERNET-SW", "Ethernet switch")

    def link(a, ia, b, ib, label=None):
        def ep(n, i):
            return {"node_id": nodes[n], "adapter_number": i, "port_number": 0} if isinstance(i, int) else i
        sw = lambda n, port: {"node_id": nodes[n], "adapter_number": 0, "port_number": port}
        A = sw(a, ia[1]) if isinstance(ia, tuple) else {"node_id": nodes[a], "adapter_number": int(ia.replace("eth", "")), "port_number": 0}
        B = sw(b, ib[1]) if isinstance(ib, tuple) else {"node_id": nodes[b], "adapter_number": int(ib.replace("eth", "")), "port_number": 0}
        req("POST", f"/projects/{pid}/links", {"nodes": [A, B]})

    for a, ia, ipa, b, ib, ipb, kind in P2P:
        link(a, ia, b, ib)
    for r, iface, c in EDGE_LAN:
        link(r, iface, f"EDGE-C{c}", "eth0")
    link("FW-C2", "eth1", "CABINET-SW", "eth0")
    for i, (h, v) in enumerate(access):
        link(h, "eth0", "CABINET-SW", f"eth{i + 1}")
    link("FW-C2", "eth2", "BROKER-C2", "eth0")
    link("DC-A", "eth1", "CLOUD-A", "eth0")
    link("ISP-1", "eth2", "INTERNET-SW", ("sw", 0))
    link("INET-USER", "eth0", "INTERNET-SW", ("sw", 1))
    link("ATTACKER", "eth0", "INTERNET-SW", ("sw", 2))

    # write configs into each node's persistent volumes
    base = os.path.join(GNS3_PROJECTS, pid, "project-files", "docker")
    for name, nid in nodes.items():
        if name == "INTERNET-SW":
            continue
        for rel, (content, mode) in node_files(name).items():
            p = os.path.join(base, nid, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as fh:
                fh.write(content)
            os.chmod(p, mode)

    # drawings: title and area labels
    def text(x, y, s, size=16, color="#1f3b57", bold=True):
        svg = (f'<svg height="{size + 10}" width="{len(s) * size * 0.62:.0f}"><text font-family="Helvetica" font-size="{size}" '
               f'font-weight="{"bold" if bold else "normal"}" fill="{color}">{s}</text></svg>')
        req("POST", f"/projects/{pid}/drawings", {"x": x, "y": y, "svg": svg})

    def box(x, y, w, h, color):
        svg = f'<svg height="{h}" width="{w}"><rect height="{h}" width="{w}" fill="{color}" fill-opacity="0.08" stroke="{color}" stroke-width="2" rx="12"/></svg>'
        req("POST", f"/projects/{pid}/drawings", {"x": x, "y": y, "svg": svg, "z": -1})

    box(-1200, -170, 700, 640, "#c0392b"); text(-1190, -200, "Cluster C2 Marietta/Smyrna — intersection site 0x02A (VLANs 10/20/30/40/50/90/99)", 14, "#c0392b")
    box(-330, -190, 900, 660, "#2e86c1"); text(-320, -215, "Fog ring (OSPF + BFD): C1–C2–C4–C3–C5–C1", 14, "#2e86c1")
    box(-560, -620, 1000, 420, "#7d3c98"); text(-550, -645, "Cloud DC-A / DC-B, ISPs (eBGP), Internet", 14, "#7d3c98")
    text(-1190, -690, "IoT Smart City — Phase 2 simulation (metro-Atlanta transportation)", 20)
    req("POST", f"/projects/{pid}/close", {})
    req("POST", f"/projects/{pid}/open", {})
    print(json.dumps({"project_id": pid, "nodes": len(nodes)}))
    return pid


if __name__ == "__main__":
    main()
