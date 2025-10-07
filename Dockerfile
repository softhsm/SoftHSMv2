FROM ubuntu:24.04 AS openssl_builder

RUN apt update && \
    apt install -y \
    build-essential \
    make \
    libtext-template-perl \
    wget \
    git && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /crypt

RUN wget https://github.com/openssl/openssl/archive/refs/tags/openssl-3.5.1.tar.gz && \
    mkdir openssl && \
    tar -xvf openssl-3.5.1.tar.gz -C openssl --strip-components=1 && \
    rm openssl-3.5.1.tar.gz

WORKDIR /crypt/openssl

RUN ./config --prefix=/usr/local --openssldir=/usr/local/ssl -Wl,-rpath=/usr/local/lib && \
    make -j$(nproc) && \
    make install

FROM ubuntu:24.04 AS softhsm_builder

COPY --from=openssl_builder /usr/local/bin/openssl /usr/local/bin/
COPY --from=openssl_builder /usr/local/lib64/ /usr/local/lib64/
COPY --from=openssl_builder /usr/local/ssl/ /usr/local/ssl/
COPY --from=openssl_builder /usr/local/include/ /usr/local/include/

RUN echo '/usr/local/lib64' > /etc/ld.so.conf.d/openssl.conf && \
    ldconfig

ENV LD_LIBRARY_PATH=/usr/local/lib64

RUN apt update && \
    apt install -y \
    automake \
    autoconf \
    libtool \
    pkg-config \
    make \
    g++ \
    libsqlite3-dev \
    libp11-kit-dev \
    libcppunit-dev \
    sudo \
    opensc \
    opensc-pkcs11 \
    busybox-syslogd

WORKDIR /app
COPY . /app

RUN sh autogen.sh

RUN ./configure --with-objectstore-backend-db --disable-gost --enable-eddsa --enable-slhdsa --with-crypto-backend=openssl

RUN make

RUN make install

# If needed, the conf file definitions goes here.
# about conf file: man softhsm2.conf

# Create config dir and log file
RUN mkdir -p /etc/softhsm /var/lib/softhsm/tokens

# Write softhsm2.conf
RUN cat > /etc/softhsm2.conf <<'EOF'
directories.tokendir = /var/lib/softhsm/tokens/

log.level = INFO
EOF

# INIT SYSLOG
# syslogd -n -O /var/log/syslog &

RUN softhsm2-util --init-token --slot 0 --label "My SoftHSM Token" --so-pin 0000 --pin 0000

CMD ["bash"]
