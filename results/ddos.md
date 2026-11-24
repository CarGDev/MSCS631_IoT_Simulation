### DDoS — 3 000 SYN/s from a compromised sensor gateway (→ fog broker) + 3 000 SYN/s from an Internet botnet (→ cloud front door)

Legitimate traffic: 50 transit devices publishing over mutual TLS to the fog broker (one-way latency).

| Protection level              | Legit p95 ms (no attack) | Legit p50 ms (attack) | Legit p95 ms (attack) | Legit p99 ms (attack) | Legit loss % | Cloud connect OK | SYNs dropped at cabinet switch | SYNs dropped at FW-C2 | SYNs dropped at DC-A |
|-------------------------------|--------------------------|-----------------------|-----------------------|-----------------------|--------------|------------------|--------------------------------|-----------------------|----------------------|
| 1 none                        | 0.52                     | 171.47                | 2962.05               | 3416.6                | 0.0          | yes              | 0                              | 0                     | 0                    |
| 2 firewall + front-door guard | 0.51                     | 89.04                 | 492.11                | 802.91                | 0.0          | yes              | 0                              | 311068                | 235773               |
| 3 guard + edge port policing  | 0.64                     | 0.46                  | 1.64                  | 5.1                   | 0.0          | yes              | 2279785                        | 1190                  | 302605               |

Controls (Table 2, C7): per-port SYN policing at the cabinet switch (edge), per-source SYN limit + global SYN cap + per-source connection limit at the fog firewall, front-door SYN limits at DC-A, SYN cookies, egress anti-spoofing, no Internet egress for sensors.
