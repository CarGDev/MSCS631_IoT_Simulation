# Router/firewall image for the IoT smart-city GNS3 lab: FRR (OSPF/BGP/BFD) + nftables + tc + tools
FROM frrouting/frr:latest
RUN apk add --no-cache ethtool nftables iproute2 iproute2-tc tcpdump iperf3 bash iputils curl nmap nmap-nping mosquitto-clients \
 && cp -a /etc/frr /opt/frr-default
COPY lab-boot /usr/local/bin/lab-boot
RUN chmod 755 /usr/local/bin/lab-boot
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/lab-boot"]
