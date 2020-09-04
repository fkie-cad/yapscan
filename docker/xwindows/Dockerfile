FROM ubuntu:latest

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /opt

RUN apt-get update
RUN apt-get install -y build-essential pkg-config \
    git gcc-multilib gcc-mingw-w64 autoconf automake \
    libtool libjansson-dev libmagic-dev libssl-dev \
    golang

RUN git clone --depth=1 --branch v4.0.2 https://github.com/VirusTotal/yara.git /opt/yara

COPY buildYara.sh /opt/

RUN /opt/buildYara.sh

ENTRYPOINT /bin/bash