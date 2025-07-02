FROM ubuntu:24.04 AS softhsm_builder

RUN apt update && \
    apt install -y \
    automake \
    autoconf \
    libtool \
    pkg-config \
    openssl \
    libbotan-2-dev \
    make \
    g++ \
    libssl-dev \
    libsqlite3-dev \
    libp11-kit-dev \
    libcppunit-dev \
    sudo \
    git

WORKDIR /app
COPY . /app

RUN sh autogen.sh

RUN ./configure --with-objectstore-backend-db --disable-gost --enable-eddsa --enable-ecc --with-crypto-backend=openssl

RUN make
# Tests
# RUN make check

RUN make install

# If needed, the conf file definitions goes here.
# about conf file: man softhsm2.conf

RUN mkdir -p /var/lib/softhsm/tokens/

RUN softhsm2-util --init-token --slot 0 --label "My SoftHSM Token" --so-pin 0000 --pin 0000

RUN apt install -y opensc opensc-pkcs11

CMD ["bash"]
