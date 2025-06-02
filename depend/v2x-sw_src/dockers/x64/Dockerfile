FROM ubuntu:22.04

#RUN sed -i 's/archive.ubuntu.com/mirror.kakao.com/g' /etc/apt/sources.list
RUN apt-get clean
RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y git unzip wget g++ python3 net-tools iputils-ping iproute2 lcov dos2unix vim rsyslog build-essential curl ntpdate

RUN mkdir -p /workspace/

RUN wget -O /workspace/openssl-3.0.12.tar.gz --no-check-certificate https://www.openssl.org/source/openssl-3.0.12.tar.gz \
  && cd /workspace \
  && tar zxvf /workspace/openssl-3.0.12.tar.gz \
  && cd /workspace/openssl-3.0.12 \
  && ./config \
  && make \
  && make install \
  && ldconfig

RUN wget -O /workspace/cmake-3.28.3.tar.gz --no-check-certificate https://github.com/Kitware/CMake/releases/download/v3.28.3/cmake-3.28.3.tar.gz \
  && cd /workspace \
  && tar zxvf /workspace/cmake-3.28.3.tar.gz \
  && cd /workspace/cmake-3.28.3 \
  && ./configure -- -DCMAKE_USE_OPENSSL=OFF \
  && make \
  && make install

RUN wget -O /workspace/googletest-1.13.0.tar.gz --no-check-certificate https://github.com/google/googletest/archive/refs/tags/v1.13.0.tar.gz \
  && cd /workspace \
  && tar zxvf /workspace/googletest-1.13.0.tar.gz \
  && cd /workspace/googletest-1.13.0 \
  && cmake . \
  && make \
  && make install \
  && ldconfig

RUN echo "local0.* /var/log/v2x" >> /etc/rsyslog.conf

VOLUME /workspace/v2x-sw
WORKDIR /workspace/

CMD ["/bin/bash"]