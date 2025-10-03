#!/bin/sh

# lol
# lmao
#sed -i 's/v3.22/edge/' /etc/apk/repositories

apk add alpine-sdk go libpcap-dev

go build -C src/server -tags netgo -trimpath -buildmode=pie -ldflags="-s -w -linkmode=external '-extldflags=-static-pie -lpcap'"
go build -C src/client -tags netgo -trimpath -buildmode=pie -ldflags="-s -w -linkmode=external '-extldflags=-static-pie'"
