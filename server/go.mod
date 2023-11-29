module github.com/monoidic/porttest/server

go 1.21.4

replace github.com/monoidic/porttest/common => ../common

require (
	github.com/google/gopacket v1.1.19
	github.com/monoidic/porttest/common v0.0.0-20231113221815-e072372d693f
)

require golang.org/x/sys v0.15.0 // indirect
