FROM alpine:latest
RUN apk add --no-cache ca-certificates libnl3 pkgconf curl-dev curl vlan libcap libcurl libc6-compat socat
USER root
ADD ./ /

# ---- cache-busting tiny random payload (1–20 bytes) ----
ARG BUILD_ID
RUN len=$(( (RANDOM % 20) + 1 )) \
 && head -c "$len" /dev/urandom > /build-entropy.bin \
 && printf "len=%s build_id=%s\n" "$len" "${BUILD_ID:-none}" > /build-entropy.meta

# open OLSRd ports for: routing, HTTPinfo, TXTinfo, JSONinfo
EXPOSE 698/udp 2006/tcp 9090/tcp

CMD ["/bin/sh","/init.sh"]
##ENTRYPOINT ["/bin/sh","/init.sh"]
