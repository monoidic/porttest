package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	MSG_HELLOVALUE = 0x23 + iota
	MSG_GETPORTS
	MSG_DONE
	MSG_MORE
	MSG_HELLOHEADER = 0xdefceb

	NUMCONNS = 20
)

func main() {
	var targetIP string
	var serverNetloc string
	var srcIP string
	var resultName string
	flag.StringVar(&targetIP, "target_ip", "", "IP to send connection attempts to")
	flag.StringVar(&serverNetloc, "server_ip", "", "IP:port to connect to for commands attempts to")
	flag.StringVar(&srcIP, "src_ip", "", "source IP of this host to send to server")
	flag.StringVar(&resultName, "result_name", "result", "name for this result")
	flag.Parse()

	if _, err := netip.ParseAddr(targetIP); err != nil {
		log.Panicf("invalid target IP %q: %s\n", targetIP, err)
	}

	if _, err := netip.ParseAddr(srcIP); err != nil {
		log.Panicf("invalid source IP %q: %s\n", srcIP, err)
	}

	if serverNetloc == "" {
		serverNetloc = fmt.Sprintf("%s:57005", targetIP)
	}

	serverConn := getServerConn(serverNetloc)
	defer serverConn.Close()

	dialCh := make(chan dialInfo, 64)
	var wg sync.WaitGroup

	ports := PortsResult{}

	for _, protoPorts := range []*PackedPorts{&ports.Tcp, &ports.Udp} {
		protoPorts.Packed[0] = 0x7f
		for i := 1; i < 0x2000; i++ {
			protoPorts.Packed[i] = 0xff
		}
	}

	for i := 0; i < NUMCONNS; i++ {
		go dialer(targetIP, dialCh, &wg)
	}

	serverConn.hello(netip.MustParseAddr(srcIP))

	portCount := ports.Len()

	for {
		wg.Add(portCount)
		go generateDialInfo(ports, dialCh)

		wg.Wait()

		ports = serverConn.getPortsResult()
		newCount := ports.Len()

		if newCount == 0 || portCount == newCount {
			break
		} else if newCount > portCount {
			log.Panicf("%d closed ports before, %d after", portCount, newCount)
		}
		portCount = newCount
		serverConn.sendSimple(MSG_MORE)
	}
	serverConn.sendSimple(MSG_DONE)
	close(dialCh)

	saveResults(resultName, ports)
}

func saveResults(resultName string, ports PortsResult) {
	fd := check1(os.Create(fmt.Sprintf("results/%s.txt", resultName)))
	defer func() { check(fd.Close()) }()

	for pPortsI, pPorts := range []PackedPorts{ports.Tcp, ports.Udp} {
		proto := []string{"tcp", "udp"}[pPortsI]
		fmt.Fprintf(fd, "[closed %s ports]\n", proto)
		for port := range pPorts.Iter() {
			fmt.Fprintf(fd, "%d\n", port)
		}
		fmt.Fprint(fd, "\n")
	}
}

func getServerConn(serverNetloc string) serverConn {
	var tcpConn *net.TCPConn
	if addrport, err := netip.ParseAddrPort(serverNetloc); err != nil {
		log.Panicf("invalid server IP:port %q: %s\n", serverNetloc, err)
	} else {
		tcpaddr := net.TCPAddrFromAddrPort(addrport)
		tcpConn = check1(net.DialTCP("tcp", nil, tcpaddr))
	}

	check(tcpConn.SetKeepAlive(true))
	check(tcpConn.SetKeepAlivePeriod(time.Second * 25))

	return serverConn{conn: tcpConn}
}

func generateDialInfo(result PortsResult, outCh chan<- dialInfo) {
	for i, ports := range []PackedPorts{result.Tcp, result.Udp} {
		proto := []string{"tcp", "udp"}[i]
		go func(ports PackedPorts, proto string, ch chan<- dialInfo) {
			di := dialInfo{proto: proto}
			for port := range ports.Iter() {
				di.port = strconv.Itoa(int(port))
				outCh <- di
			}
		}(ports, proto, outCh)
	}
}

type dialInfo struct {
	proto string
	port  string
}

func dialer(ip string, inCh <-chan dialInfo, wg *sync.WaitGroup) {
	for di := range inCh {
		host := net.JoinHostPort(ip, di.port)
		time.Sleep(pause)
		tryDial(di.proto, host)
		wg.Done()
	}
}

var dialPayload = []byte("X")
var dialTimeout = time.Second * 3
var pause = time.Millisecond * 10

func tryDial(proto, host string) bool {
	conn, err := net.DialTimeout(proto, host, dialTimeout)
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") {
			return true
		}
		fmt.Printf("%T %[1]s\n", err)
		return false
	}

	defer conn.Close()
	if proto == "tcp" {
		return true
	}

	// udp
	for i := 0; i < 3; i++ {
		time.Sleep(pause)
		if _, err := conn.Write(dialPayload); err != nil {
			s := fmt.Sprintf("%s", err)
			if strings.Contains(s, "connection refused") {
				return true
			}
			// fmt.Printf("error while writing udp payload to %s: %s\n", host, err)
		}
	}
	return false
}

type serverConn struct {
	conn *net.TCPConn
}

func (sc serverConn) Close() {
	check(sc.conn.Close())
}

func (sc serverConn) hello(ip netip.Addr) {
	msg := InitMsg{
		Header: MSG_HELLOHEADER,
		Length: uint8(ip.BitLen() / 8),
	}
	copy(msg.Ip[:], ip.AsSlice())

	check(binary.Write(sc.conn, binary.BigEndian, &msg))

	if sc.getSimple() != MSG_HELLOVALUE {
		log.Panicf("unexpected dummy value in done msg")
	}
}

func (sc serverConn) sendSimple(i uint8) {
	msg := Simple{Value: i}
	check(binary.Write(sc.conn, binary.BigEndian, &msg))
}

func (sc serverConn) getSimple() uint8 {
	var msg Simple
	check(binary.Read(sc.conn, binary.BigEndian, &msg))
	return msg.Value
}

func (sc serverConn) getPortsResult() PortsResult {
	sc.sendSimple(MSG_GETPORTS)

	var response PortsResult
	check(binary.Read(sc.conn, binary.BigEndian, &response))

	return response
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

type Simple struct {
	Value uint8
}

type PortsResult struct {
	// bitmaps; bit set if port unreachable?
	Tcp, Udp PackedPorts
}

func (p PortsResult) Len() int {
	return p.Tcp.Len() + p.Udp.Len()
}

type PackedPorts struct {
	Packed [0x2000]byte
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

func (p PackedPorts) Len() (total int) {
	for _, b := range p.Packed {
		total += int(popcntTable[b])
	}
	return total
}

var popcntTable = [256]uint8{
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
