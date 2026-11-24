### Data-breach test — what an on-path attacker sees

| Transport      | Capture                            | Payment data visible? |
|----------------|------------------------------------|-----------------------|
| plaintext_1883 | results/breach_plaintext_1883.pcap | YES — readable        |
| mtls_8883      | results/breach_mtls_8883.pcap      | no — encrypted        |

Open both pcaps in Wireshark: filter `mqtt` on the plaintext capture shows the payload; `tls` on the mTLS capture shows only Application Data.
