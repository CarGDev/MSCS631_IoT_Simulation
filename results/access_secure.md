### Access-control matrix — firewall SECURE mode

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
