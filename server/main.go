package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	MSG_HELLOVALUE = 0x23 + iota
	MSG_GETPORTS
	MSG_DONE
	MSG_MORE
	MSG_HELLOHEADER = 0xdefceb

	NUMREADERS = 20
	ETHLEN     = 14
	IPLEN      = 60
	TCPUDPLEN  = 60
	BUFFER     = 128
	PACKETLEN  = ETHLEN + IPLEN + TCPUDPLEN + BUFFER
)

func main() {
	var netif string
	var ip string
	flag.StringVar(&netif, "netif", "eth0", "interface name to capture on")
	flag.StringVar(&ip, "ip", "127.0.0.1:57005", "IP:port to bind to")
	flag.Parse()

	if _, err := netip.ParseAddrPort(ip); err != nil {
		log.Panicf("invalid IP:port: %q", ip)
	}

	server := check1(net.Listen("tcp", ip))

	for {
		if conn, err := server.Accept(); err == nil {
			fmt.Printf("got conn %v\n", conn)
			go handleConn(netif, conn)
		} else {
			log.Printf("error accepting conn: %s", err)
		}

	}
}

func handleConn(netif string, conn net.Conn) {
	defer conn.Close()

	ipStr, err := getInitMsg(conn)
	if err != nil {
		log.Printf("error getting initmsg: %s", err)
		return
	}

	handle := check1(pcap.OpenLive(netif, PACKETLEN, false, pcap.BlockForever))
	check(handle.SetBPFFilter(fmt.Sprintf("src host %s and (tcp or udp)", ipStr)))
	defer handle.Close() // duplicate close is fine

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.Lazy = true
	packetSource.NoCopy = true
	pcapChan := packetSource.Packets()

	var wg sync.WaitGroup
	wg.Add(NUMREADERS)

	var tcpA, udpA [65536]bool

	for i := 0; i < NUMREADERS; i++ {
		go packetReader(pcapChan, &wg, &tcpA, &udpA)
	}

	if err := sendSimple(conn, MSG_HELLOVALUE); err != nil {
		log.Printf("error sending ready message: %s", err)
		return
	}

	var result PortsResult

	for {
		if i, err := getSimple(conn); err != nil {
			log.Printf("error getting simple message in loop: %s", err)
			return
		} else if i != MSG_GETPORTS {
			log.Printf("unexpected simple message value: %x", i)
			return
		}

		// for any stray packets
		time.Sleep(time.Second * 1)

		result.Pack(tcpA, udpA)
		if err := sendPortsResult(conn, result); err != nil {
			log.Printf("error sending ports result: %s", err)
			return
		}

		if i, err := getSimple(conn); err != nil {
			log.Printf("error getting ports result response: %s", err)
			return
		} else if i == MSG_DONE {
			handle.Close()
			wg.Wait()
			return
		} else if i != MSG_MORE {
			log.Printf("unexpected ports result response value: %x", i)
			return
		}
	}

}

func sendPortsResult(conn net.Conn, result PortsResult) error {
	totalCount := 0

	for portsI, ports := range []PackedPorts{result.Tcp, result.Udp} {
		proto := []string{"tcp", "udp"}[portsI]
		protoLen := ports.Len()
		fmt.Printf("sending %d %s ports\n", protoLen, proto)
		totalCount += protoLen
	}
	fmt.Printf("%d ports total\n", totalCount)

	return binary.Write(conn, binary.BigEndian, &result)
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

func getInitMsg(conn net.Conn) (ip string, err error) {
	var initmsg InitMsg
	if err := binary.Read(conn, binary.BigEndian, &initmsg); err != nil {
		return "", err
	}

	if initmsg.Header != MSG_HELLOHEADER {
		return "", Error{s: fmt.Sprintf("invalid header value: %x", initmsg.Header)}
	}

	if addr, ok := netip.AddrFromSlice(initmsg.Ip[:initmsg.Length]); ok {
		return addr.String(), nil
	}
	return "", Error{s: fmt.Sprintf("invalid addr length %d", initmsg.Length)}
}

func getSimple(conn net.Conn) (uint8, error) {
	var msg Simple
	if err := binary.Read(conn, binary.BigEndian, &msg); err != nil {
		return 0, err
	}
	fmt.Printf("got simple %x\n", msg.Value)
	return msg.Value, nil
}

func sendSimple(conn net.Conn, i uint8) error {
	fmt.Printf("sending simple %x\n", i)
	msg := Simple{Value: i}
	return binary.Write(conn, binary.BigEndian, &msg)

}

func packetReader(pcapChan <-chan gopacket.Packet, wg *sync.WaitGroup, tcp, udp *[65536]bool) {
	for packet := range pcapChan {

		switch layer := packet.TransportLayer().(type) {
		case *layers.TCP:
			tcp[layer.DstPort] = true
		case *layers.UDP:
			udp[layer.DstPort] = true
		default:
			log.Panicf("unexpected type %T\n", layer)
		}
	}

	wg.Done()
}

func check(err error) {
	if err != nil {
		log.Panicf("%T %[1]v", err)
	}
}

func check1[T any](arg1 T, err error) T {
	check(err)
	return arg1
}

type InitMsg struct {
	Header uint64
	Ip     [16]byte
	Length uint8
}

type Error struct {
	s string
}

func (err Error) Error() string {
	return err.s
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
