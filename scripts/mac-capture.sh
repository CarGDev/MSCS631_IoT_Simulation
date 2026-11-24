#!/usr/bin/env bash
# Live capture from any lab node interface straight into Wireshark on your Mac (over Tailscale + SSH).
#
#   ./mac-capture.sh NODE IFACE ["capture filter"] [save.pcapng]
#
# Examples:
#   ./mac-capture.sh FOG-C1 eth0 "ospf or udp port 3784"        # OSPF + BFD on ring link C1-C2
#   ./mac-capture.sh FW-C2  eth1                                 # 802.1Q trunk to the cabinet switch (all zone VLANs)
#   ./mac-capture.sh FW-C2  eth0 "icmp or tcp port 8883"         # fog uplink: DSCP marks, bridge to the cloud
#   ./mac-capture.sh DC-A   eth2 "tcp port 179"                  # eBGP with ISP-1
#   ./mac-capture.sh FW-C2  eth1 "" ~/Desktop/trunk.pcapng       # also save a copy for the report
#
# Needs: Tailscale on, Wireshark installed (brew install --cask wireshark), SSH key access to carlos.
set -euo pipefail
SERVER="${GNS3_SERVER:-carlos@100.99.194.92}"
SIM="${SIM_DIR:-/home/carlos/projects/IoT_Applications/simulation}"
NODE="${1:?node name, e.g. FW-C2}"; IFACE="${2:?interface, e.g. eth1}"; FILTER="${3:-}"; SAVE="${4:-}"
WS="/Applications/Wireshark.app/Contents/MacOS/Wireshark"
[ -x "$WS" ] || WS="$(command -v wireshark || true)"
[ -n "$WS" ] || { echo "Wireshark not found. Install: brew install --cask wireshark"; exit 1; }

PID=$(ssh "$SERVER" "cat $SIM/.project_id")
REMOTE="docker exec GNS3.${NODE}.${PID} tcpdump -i ${IFACE} -U -s 0 -w - ${FILTER:+'$FILTER'} 2>/dev/null"
echo "Capturing ${NODE}:${IFACE} ${FILTER:+(filter: $FILTER)} — close Wireshark or press Ctrl+C to stop"
if [ -n "$SAVE" ]; then
  ssh "$SERVER" "$REMOTE" | tee "$SAVE" | "$WS" -k -i -
else
  ssh "$SERVER" "$REMOTE" | "$WS" -k -i -
fi
