FROM alpine:latest
RUN apk add --no-cache curl libc6-compat socat
# Use ARM-compatible BusyBox
#FROM arm64v8/busybox:latest

USER root
ADD ./ /
# open OLSRd ports for: routing, HTTPinfo, TXTinfo, JSONinfo
EXPOSE 698/udp 2006/tcp 9090/tcp

CMD ["/bin/sh","/init.sh"]
#ENTRYPOINT ["/usr/local/bin/olsrd"]
