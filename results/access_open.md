### Access-control matrix — firewall OPEN mode

| Flow                                            | Source      | Result  |
|-------------------------------------------------|-------------|---------|
| Safety ctrl -> fog broker 8883 (mTLS)           | SIGNAL-CTRL | ALLOWED |
| RSU -> signal controller CoAP 5683 (preemption) | RSU         | ALLOWED |
| Transit -> fog broker 8883 (mTLS)               | TRANSIT-GW  | ALLOWED |
| Transit -> fog broker 1883 (plaintext)          | TRANSIT-GW  | ALLOWED |
| EV charger -> payment processor 443 (TLS)       | EV-CHARGER  | ALLOWED |
| EV charger -> fog broker 8883                   | EV-CHARGER  | ALLOWED |
| EV charger -> signal controller                 | EV-CHARGER  | ALLOWED |
| LoRa sensors -> fog broker 8883 (mTLS)          | LORA-GW     | ALLOWED |
| LoRa sensors -> signal controller CoAP          | LORA-GW     | ALLOWED |
| LoRa sensors -> Internet (botnet egress)        | LORA-GW     | blocked |
| Public Wi-Fi -> Internet                        | PUBLIC-WIFI | ALLOWED |
| Public Wi-Fi -> signal controller CoAP          | PUBLIC-WIFI | ALLOWED |
| Public Wi-Fi -> fog broker 8883                 | PUBLIC-WIFI | blocked |
| Public Wi-Fi -> payment zone (EV charger)       | PUBLIC-WIFI | ALLOWED |
| Mgmt jump host -> signal controller             | MGMT-JUMP   | ALLOWED |
| Internet attacker -> cloud front door 8883      | ATTACKER    | ALLOWED |
| Internet attacker -> signal controller          | ATTACKER    | blocked |
| Internet attacker -> fog broker                 | ATTACKER    | blocked |
