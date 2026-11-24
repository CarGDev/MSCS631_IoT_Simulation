### Scalability S2 — adding cluster C6 without redesign

| Item                                 | Result                                                                       |
|--------------------------------------|------------------------------------------------------------------------------|
| New fog router                       | FOG-C6, dual-homed to FOG-C4 (eth2) and FOG-C2 (eth3), ports pre-provisioned |
| Config changes on existing routers   | 0                                                                            |
| Route 10.6.50.0/24 learned by FOG-C1 | after 6.4 s                                                                  |
| EDGE-C6 → cloud reachability         | OK                                                                           |
