FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive

RUN mkdir /tmp/install
WORKDIR /tmp/install

COPY ./env-init.sh ./
COPY ./mitmproxy-install.sh ./
COPY ./har_dump.py /

RUN chmod 700 ./*.sh
RUN ./env-init.sh
RUN ./mitmproxy-install.sh

RUN locale-gen en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

CMD ["/bin/bash"]

