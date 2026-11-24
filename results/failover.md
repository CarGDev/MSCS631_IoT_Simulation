### Failover — ring link C1–C2 cut (OSPF + BFD)

| Metric                        | Value                                          |
|-------------------------------|------------------------------------------------|
| Probe                         | EDGE-C1 → FW-C2 (path over C1–C2) every 20 ms  |
| Packets lost                  | 66                                             |
| Measured outage / convergence | ~1320 ms                                       |
| Path before cut (FOG-C1)      | 10.254.0.2 (eth0)                              |
| Path after cut (FOG-C1)       | 10.254.0.17 (eth1)                             |
| Design target                 | no single link failure isolates a cluster (S6) |
