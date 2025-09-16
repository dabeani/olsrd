# Use ARM-compatible BusyBox
FROM arm32v5/busybox:latest

# Install dependencies manually (BusyBox lacks `apt-get`)
#RUN mkdir -p /etc/opkg && \
#    echo "src/gz openwrt_base https://downloads.openwrt.org/releases/22.03.0/packages/arm_cortex-a8/base" > /etc/opkg/custom-feed.conf && \
#    opkg update && opkg install libc6-compat socat

# Set root user and add necessary files
USER root
ADD ./ /

# Open OLSRd ports for routing, HTTP info, TXT info, JSON info
EXPOSE 698/udp 2006/tcp 9090/tcp

CMD ["/bin/sh", "/init.sh"]