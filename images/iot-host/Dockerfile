# Host image for the IoT smart-city GNS3 lab: IoT devices, brokers, cloud services, attacker
FROM alpine:3.22
RUN apk add --no-cache ethtool bash iproute2 iproute2-tc iputils tcpdump iperf3 curl openssl nftables \
      mosquitto mosquitto-clients python3 py3-paho-mqtt nmap nmap-nping nmap-scripts libcoap
# Lab broker binary under its own path: Ubuntu hosts ship an AppArmor profile attached to /usr/sbin/mosquitto
# that also confines privileged GNS3 containers and blocks reading /etc/lab/mosquitto.conf.
RUN mkdir -p /usr/local/sbin && cp /usr/sbin/mosquitto /usr/local/sbin/mqtt-broker
COPY lab-boot /usr/local/bin/lab-boot
COPY bin/ /usr/local/bin/
RUN chmod 755 /usr/local/bin/*
ENTRYPOINT ["/usr/local/bin/lab-boot"]
