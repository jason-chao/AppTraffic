FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive

RUN mkdir /tmp/install
WORKDIR /tmp/install

COPY ./env-init.sh ./
COPY ./softether-download.sh ./
COPY ./softether-build.sh ./
COPY ./softether-start.sh ./

RUN chmod 700 ./*.sh
RUN ./env-init.sh
RUN ./softether-download.sh
RUN ./softether-build.sh

RUN locale-gen en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

# expose the port for controlling softher
EXPOSE 5555/tcp

# expose the ports for L2TP
EXPOSE 500/udp
EXPOSE 4500/udp
EXPOSE 1194/udp

CMD ./softether-start.sh
