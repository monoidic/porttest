package common

import (
	"log"
	"math/bits"
)

// constants used in messages between the client and server
const (
	// server=>client simple message response to initmsg, after server setup is done
	MSG_HELLOVALUE = 0x23 + iota
	// client=>server, request a PortsResult
	MSG_GETPORTS
	// client=>server, end of communication
	MSG_DONE
	// client=>server, continuation of communication
	MSG_MORE
	// client=>server initmsg constant header value
	MSG_HELLOHEADER = 0xdefceb
)

// initial message sent from the client to the server at the start of communication
// has a constant header, a source IP, and a length indicating whether the IP is v4 or v6
type InitMsg struct {
	// constant value MSG_HELLOHEADER
	Header uint64
	// IPv4 or IPv6 in binary representation
	Ip [16]byte
	// 4 or 16, depending on IP version
	Length uint8
	// mask of ports that will be asked for
	PortsResult
}

// simple error type
type Error struct {
	S string
}

// implement error interface
func (err Error) Error() string {
	return err.S
}

// single-byte message sent between the server and client
type Simple struct {
	Value uint8
}

// 65536 bits packed into 8192 bytes, indicating all 65536 ports
type PackedPorts struct {
	Packed [0x2000]byte
}

// count the number of ports indicated as reachable in the given PackedPorts
func (p *PackedPorts) Len() (total int) {
	for _, b := range p.Packed {
		total += bits.OnesCount8(b)
	}
	return total
}

// returns a channel to which every port marked in PackedPorts is written and which is closed at the end
func (p *PackedPorts) Iter() <-chan uint16 {
	ret := make(chan uint16, 16)

	go func(arr [0x2000]byte, ch chan<- uint16) {
		for i, b := range arr {
			if b == 0 {
				continue
			}
			for j := 0; j < 8; j++ {
				if (b & (1 << j)) != 0 {
					ch <- uint16(i*8 + j)
				}
			}
		}

		close(ch)
	}(p.Packed, ret)

	return ret
}

// response from the server to the client, indicating what ports were seen to be contacted on TCP and UDP
type PortsResult struct {
	Tcp, Udp PackedPorts
}

// count the number of ports indicated as reachable TCP and UDP ports in the given PortsResult
func (p *PortsResult) Len() int {
	return p.Tcp.Len() + p.Udp.Len()
}

// pack two arrays of 65536 bools into two arrays of 8192 bytes
func (p *PortsResult) Pack(tcp, udp [65536]bool) {
	for arrI, arr := range [][65536]bool{tcp, udp} {
		outArr := []*PackedPorts{&p.Tcp, &p.Udp}[arrI]
		for i := 0; i < 0x2000; i++ {
			outArr.Packed[i] = boolsToByte(arr, i*8)
		}
	}
}

// helper function for boolsToByte, essentially b*i
func b2i(b bool, i uint8) uint8 {
	if !b {
		return i
	}
	return 0
}

// converts 8 bools at arr[i:i+8] into a uint8
func boolsToByte(arr [65536]bool, i int) uint8 {
	return b2i(arr[i], 1) + b2i(arr[i+1], 2) + b2i(arr[i+2], 4) + b2i(arr[i+3], 8) +
		b2i(arr[i+4], 16) + b2i(arr[i+5], 32) + b2i(arr[i+6], 64) + b2i(arr[i+7], 128)
}

// panic out on an error;
// usage: common.Check(mayReturnError(args)), where the return type of mayReturnError is `error`
func Check(err error) {
	if err != nil {
		log.Panicf("%T %[1]v", err)
	}
}

// panic out on an error, and return one value;
// usage: x := common.Check1(mayReturnError(args)), where the return type of mayReturnError is `someType, error`
func Check1[T any](arg1 T, err error) T {
	Check(err)
	return arg1
}
