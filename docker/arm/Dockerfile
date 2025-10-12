# Use ARM-compatible BusyBox
FROM arm32v5/busybox:latest

# Set root user and add necessary files
USER root
ADD ./ /

# Open OLSRd ports for routing, HTTP info, TXT info, JSON info
EXPOSE 698/udp 2006/tcp 9090/tcp

CMD ["/bin/sh", "/init.sh"]
