#!/bin/sh

# lol
# lmao
sed -i 's/v3.20/edge/' /etc/apk/repositories

apk add alpine-sdk go libpcap-dev

## workaround for alpine breaking Go with this error:
## go: cannot find GOROOT directory: 'go' binary is trimmed and GOROOT is not set
export GOROOT=/usr/lib/go

go build -C src/server -tags netgo -trimpath -buildmode=pie -ldflags="-s -w -linkmode=external '-extldflags=-static-pie -lpcap'"
go build -C src/client -tags netgo -trimpath -buildmode=pie -ldflags="-s -w -linkmode=external '-extldflags=-static-pie'"
