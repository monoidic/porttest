module github.com/monoidic/porttest/server

go 1.23.1

replace github.com/monoidic/porttest/common => ../common

require (
	github.com/google/gopacket v1.1.19
	github.com/monoidic/porttest/common v0.0.0-20231231224459-7b2fb67490a8
	github.com/jellydator/ttlcache/v3 v3.3.0
)

require (
	golang.org/x/sync v0.8.0 // indirect
	golang.org/x/sys v0.26.0 // indirect
)
