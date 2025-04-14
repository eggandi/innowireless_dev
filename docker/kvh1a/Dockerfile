FROM ubuntu:22.04

RUN apt-get update

RUN apt -y install build-essential file git unzip wget dos2unix vim net-tools iputils-ping iproute2 \
    binutils-aarch64-linux-gnu cpp-aarch64-linux-gnu g++-aarch64-linux-gnu gcc-aarch64-linux-gnu \
    binutils-arm-linux-gnueabihf cpp-arm-linux-gnueabihf g++-arm-linux-gnueabihf gcc-arm-linux-gnueabihf

RUN mkdir -p /workspace/

RUN wget -O /workspace/openssl-3.0.2.tar.gz --no-check-certificate https://www.openssl.org/source/openssl-3.0.2.tar.gz \
  && cd /workspace \
  && tar zxvf /workspace/openssl-3.0.2.tar.gz \
  && cd /workspace/openssl-3.0.2 \
  && ./config \
  && make -j 4 \
  && make install -j 4 \
  && ldconfig

RUN wget -O /workspace/cmake-3.28.3.tar.gz --no-check-certificate https://github.com/Kitware/CMake/releases/download/v3.28.3/cmake-3.28.3.tar.gz \
	&& cd /workspace \
	&& tar xvfz /workspace/cmake-3.28.3.tar.gz \
	&& cd /workspace/cmake-3.28.3 \
	&& ./configure \
	&& make -j 4 \
	&& make install -j 4

ENV ARCH="arm64"
ENV CROSS_COMPILE="aarch64-linux-gnu-"
ENV AR="aarch64-linux-gnu-ar"
ENV AS="aarch64-linux-gnu-as"
ENV CC="aarch64-linux-gnu-gcc"
ENV CPP="aarch64-linux-gnu-gcc"
ENV CXX="aarch64-linux-gnu-g++"
ENV LD="aarch64-linux-gnu-ld"
ENV NM="aarch64-linux-gnu-nm"
ENV OBJCOPY="aarch64-linux-gnu-objcopy"
ENV OBJDUMP="aarch64-linux-gnu-objdump"
ENV RANLIB="aarch64-linux-gnu-ranlib"
ENV READELF="aarch64-linux-gnu-readelf"
ENV STRIP="aarch64-linux-gnu-strip"

VOLUME /workspace/kvh
WORKDIR /workspace/

CMD ["/bin/bash"]
