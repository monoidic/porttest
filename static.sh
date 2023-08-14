#!/bin/sh

apk add alpine-sdk go libpcap-dev
git clone https://github.com/monoidic/porttest
go build -C porttest/server -tags netgo -trimpath -ldflags="-s -w '-extldflags=-static -lpcap'"
go build -C porttest/client -tags netgo -trimpath -ldflags="-s -w"
