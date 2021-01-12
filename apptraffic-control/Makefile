SHELL := /bin/bash
$(VERBOSE).SILENT:
.DEFAULT_GOAL := help
IMAGE_VERSION := 0.0.1a

help:
	echo "Makefile for AppTraffic"
	echo "	init		Install Python3 and pull the required docker images (root required)"
	echo "	install		Install the dependencies for AppTraffic in a Python venv"

init:
ifneq ($(shell id -u), 0)
	echo "Please run as root to perform init"
else
	apt-get install python3 python3-pip python3-venv -y
	docker image pull jasonthc/apptraffic-softether-vpnserver:$(IMAGE_VERSION)
	docker image pull jasonthc/apptraffic-softether-vpncmd:$(IMAGE_VERSION)
	docker image pull jasonthc/apptraffic-mitmproxy:$(IMAGE_VERSION)
	docker image pull jasonthc/apptraffic-routing:$(IMAGE_VERSION)
endif

install:
	rm -r -f ./venv
	python3 -m venv venv
	source venv/bin/activate; \
	pip3 install -r requirements.txt; \
