FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive

RUN mkdir /tmp/install
WORKDIR /tmp/install

COPY ./env-init.sh ./
COPY ./softether-vpncmd-download.sh ./
COPY ./softether-vpncmd-build.sh ./

RUN chmod 700 ./*.sh
RUN ./env-init.sh
RUN ./softether-vpncmd-download.sh
RUN ./softether-vpncmd-build.sh

RUN locale-gen en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

CMD /usr/local/vpnclient/vpncmd
