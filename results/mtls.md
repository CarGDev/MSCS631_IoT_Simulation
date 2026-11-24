### Device identity — mutual TLS at the cloud broker

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
