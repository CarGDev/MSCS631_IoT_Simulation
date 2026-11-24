### QoS — latency to the cloud while bulk sensor traffic saturates the 10 Mbit/s fog uplink

| Mode    | Traffic class  | Avg RTT ms | Max RTT ms | Loss |
|---------|----------------|------------|------------|------|
| QoS OFF | EF (safety)    | 354.158    | 402.05     | 0%   |
| QoS OFF | AF31 (transit) | 354.422    | 402.787    | 0%   |
| QoS OFF | CS1 (public)   | 354.196    | 402.084    | 0%   |
| QoS ON  | EF (safety)    | 0.33       | 0.848      | 0%   |
| QoS ON  | AF31 (transit) | 0.334      | 0.858      | 0%   |
| QoS ON  | CS1 (public)   | 0.994      | 1.704      | 0%   |

DSCP is set at the fog firewall (trust boundary): EF for VLAN 10/20, AF31 transit, AF21 payment, CS1 sensors/public.
