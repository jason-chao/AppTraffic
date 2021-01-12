FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive

RUN mkdir /routing
WORKDIR /routing

COPY ./env-init.sh ./
COPY ./route_traffic_mitm.sh ./
COPY ./undo_route_traffic_mitm.sh ./
COPY ./route_traffic_gateway.sh ./
COPY ./undo_route_traffic_gateway.sh ./
COPY ./intercept_raw.sh ./
COPY ./intercept_header.sh ./

RUN chmod 700 ./*.sh
RUN ./env-init.sh

CMD ["/bin/bash"]
