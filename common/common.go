package common

import "log"

const (
	MSG_HELLOVALUE = 0x23 + iota
	MSG_GETPORTS
	MSG_DONE
	MSG_MORE
	MSG_HELLOHEADER = 0xdefceb

	NUMCONNS = 20
)

type InitMsg struct {
	Header uint64
	Ip     [16]byte
	Length uint8
}

type Error struct {
	S string
}

func (err Error) Error() string {
	return err.S
}

type Simple struct {
	Value uint8
}

type PortsResult struct {
	Tcp, Udp PackedPorts
}

type PackedPorts struct {
	Packed [0x2000]byte
}

func (p *PortsResult) Pack(tcp, udp [65536]bool) {
	for arrI, arr := range [][65536]bool{tcp, udp} {
		outArr := []*PackedPorts{&p.Tcp, &p.Udp}[arrI]
		for i := 0; i < 0x2000; i++ {
			outArr.Packed[i] = boolsToByte(arr, i*8)
		}
	}
}

func (p PackedPorts) Len() (total int) {
	for _, b := range p.Packed {
		total += popcntTable[b]
	}
	return total
}

func (p PortsResult) Len() int {
	return p.Tcp.Len() + p.Udp.Len()
}

var popcntTable = [256]int{
	0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
	1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
	1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
	2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
	1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
	2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
	2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
	3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
	1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
	2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
	2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
	3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
	2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
	3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
	3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
	4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8,
}

func b2i(b bool, i uint8) uint8 {
	if !b {
		return i
	}
	return 0
}

func boolsToByte(arr [65536]bool, i int) uint8 {
	return b2i(arr[i], 1) + b2i(arr[i+1], 2) + b2i(arr[i+2], 4) + b2i(arr[i+3], 8) +
		b2i(arr[i+4], 16) + b2i(arr[i+5], 32) + b2i(arr[i+6], 64) + b2i(arr[i+7], 128)
}

func Check(err error) {
	if err != nil {
		log.Panicf("%T %[1]v", err)
	}
}

func Check1[T any](arg1 T, err error) T {
	Check(err)
	return arg1
}

func (p PackedPorts) Iter() <-chan uint16 {
	ret := make(chan uint16)

	go func(arr [0x2000]byte, ch chan uint16) {
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