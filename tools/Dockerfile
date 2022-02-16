FROM ubuntu:20.04

LABEL version="1.0"

ARG DEBIAN_FRONTEND=noninteractive

RUN  apt-get update && apt-get install -y --no-install-recommends \
    sudo \
    vim \
    make \
    autotools-dev \
    autoconf \
    automake \
    doxygen \
    perl \
    build-essential \
    gcc \
    clang \
    bear \
    libtool \
    net-tools \
    iproute2 \
    indent \
    libcmocka-dev && \
    apt-get clean

RUN useradd -m -s /bin/bash builder && \
    adduser builder sudo && \
    echo "builder:builder" | chpasswd
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
WORKDIR /home/builder

USER builder

CMD ["/bin/bash", "--login"]
