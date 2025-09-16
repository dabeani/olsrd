FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Vienna

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Base tooling + cross-compilers (C and C++)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      tzdata ca-certificates \
      doxygen musl libnl-3-dev libnl-genl-3-dev libtomcrypt-dev \
      git wget curl nano \
      tar xz-utils unzip \
      make flex bison build-essential cmake automake autoconf libtool pkg-config \
      python3 apt-utils \
      gcc-aarch64-linux-gnu g++-aarch64-linux-gnu \
      gcc-arm-linux-gnueabi g++-arm-linux-gnueabi binutils-arm-linux-gnueabi \
      gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf binutils-arm-linux-gnueabihf \
      libcurl4-openssl-dev && \
    ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ >/etc/timezone && \
    rm -rf /var/lib/apt/lists/*

# ARMv5 Toolchain with glibc
WORKDIR /opt
COPY ./armv5-eabi--glibc--stable-2024.05-1.tar.xz /opt/
RUN tar -xf armv5-eabi--glibc--stable-2024.05-1.tar.xz

#COPY ./openwrt-sdk-22.03.0-ramips-mt7621_gcc-11.2.0_musl.Linux-x86_64.tar.xz /opt/
#RUN tar -xf openwrt-sdk-22.03.0-ramips-mt7621_gcc-11.2.0_musl.Linux-x86_64.tar.xz \
#    && mv openwrt-sdk-22.03.0-ramips-mt7621_gcc-11.2.0_musl.Linux-x86_64 openwrt-sdk && rm -R *.tar.xz

# Clone OLSRd repository
WORKDIR /workspace
#RUN git clone git@github.com:dabeani/olsrd.git /workspace/olsrd

#RUN git clone https://github.com/OLSR/olsrd.git /workspace/olsrd
#RUN git clone https://github.com/OLSR/OONF.git /workspace/olsrd2
#RUN git clone https://github.com/dabeani/olsrd-status-plugin /workspace/olsrd/lib/olsrd-status-plugin

#COPY extras/olsrd-* /workspace/olsrd/

#COPY extras/cp_* /workspace/olsrd/
#COPY extras/arm*.cmake /workspace/olsrd2/cmake/cross/
#COPY extras/build_*.sh /workspace/olsrd2/
#COPY extras/integrate-status-plugin.sh /workspace/olsrd/
#COPY extras/olsrdtest.conf /workspace/olsrd/

# Make scripts executable (if present)
#RUN chmod +x /workspace/olsrd2/build_*.sh || true
#RUN chmod +x /workspace/olsrd/cp_*.sh || true


# Set entrypoint to bash for interactive use
ENTRYPOINT ["/bin/bash"]
