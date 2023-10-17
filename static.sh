#!/bin/sh

apk add alpine-sdk go libpcap-dev
go build -C src/server -tags netgo -trimpath -buildmode=pie -ldflags="-s -w '-extldflags=-static -lpcap'"
go build -C src/client -tags netgo -trimpath -buildmode=pie -ldflags="-s -w"
