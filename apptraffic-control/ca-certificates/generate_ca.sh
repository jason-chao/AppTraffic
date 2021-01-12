#!/usr/bin/env bash

# Reference https://jamielinux.com/docs/openssl-certificate-authority/create-the-root-pair.html

if [ "$1" != "" ]; then
    CN="AppTraffic_CA_$1"
else
    CN="AppTraffic_CA"
fi

openssl genrsa -out ca-key.pem 4096

openssl req -config openssl_ca.cnf \
      -key ca-key.pem \
      -new -x509 -days 7300 -sha256 -extensions v3_ca \
      -subj "/C=DE/ST=NRW/L=Siegen/O=AppTraffic/CN=${CN}" \
      -out ca-cert.pem

cp ca-key.pem ca.pem
cat ca-cert.pem >> ca.pem

openssl x509 -noout -text -in ca.pem
