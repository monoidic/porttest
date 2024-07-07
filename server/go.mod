module github.com/monoidic/porttest/server

go 1.22.5

replace github.com/monoidic/porttest/common => ../common

require (
	github.com/google/gopacket v1.1.19
	github.com/monoidic/porttest/common v0.0.0-20231231224459-7b2fb67490a8
)

require golang.org/x/sys v0.22.0 // indirect
