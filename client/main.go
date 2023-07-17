package main

import (
	"compress/zlib"
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

	"github.com/monoidic/porttest/common"
)

func main() {
	var targetIP string
	var serverNetloc string
	var srcIP string
	var resultName string
	var portS string
	var numConns int
	flag.StringVar(&targetIP, "target_ip", "", "IP to send connection attempts to")
	flag.StringVar(&serverNetloc, "server_ip", "", "IP:port to connect to for commands attempts to")
	flag.StringVar(&srcIP, "src_ip", "0.0.0.0", "source IP of this host to send to server")
	flag.StringVar(&resultName, "result_name", "result", "name for this result")
	flag.StringVar(&portS, "ports", "0-1024", "ports to scan (format: comma-seperated ports or inclusive ranges, e.g 80,443,600-700)")
	flag.IntVar(&numConns, "conns", 20, "number of parallel connections to use")
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

	ports := common.PortsResult{}

	for port := range parsePortString(portS) {
		index := port / 8
		mask := uint8(1 << (port % 8))
		ports.Tcp.Packed[index] |= mask
		ports.Udp.Packed[index] |= mask
	}

	for i := 0; i < numConns; i++ {
		go dialer(targetIP, dialCh, &wg)
	}

	serverConn.hello(netip.MustParseAddr(srcIP), &ports)

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
		serverConn.sendSimple(common.MSG_MORE)
	}
	serverConn.sendSimple(common.MSG_DONE)
	close(dialCh)

	saveResults(resultName, ports)
}

// save results as formatted text to results/{resultName}.txt
func saveResults(resultName string, ports common.PortsResult) {
	common.Check(os.MkdirAll("results", 0o755))
	fd := common.Check1(os.Create(fmt.Sprintf("results/%s.txt", resultName)))
	defer func() { common.Check(fd.Close()) }()

	for pPortsI, pPorts := range []common.PackedPorts{ports.Tcp, ports.Udp} {
		proto := []string{"tcp", "udp"}[pPortsI]
		fmt.Fprintf(fd, "[closed %s ports]\n", proto)
		for portRange := range numsToRanges(pPorts.Iter()) {
			fmt.Fprintf(fd, "%s\n", portRange)
		}
		fmt.Fprint(fd, "\n")
	}
}

// converts numbers, e.g 1,2,3,4,5,6,7,8,10,11,12,14,16,17,18 to ranges, e.g 1-8,10-12,14,16-18
// expects the numbers in order
func numsToRanges(inCh <-chan uint16) <-chan string {
	outCh := make(chan string, 16)

	go func(inCh <-chan uint16, outCh chan<- string) {
		defer close(outCh)
		rangeStart, ok := <-inCh
		if !ok {
			return
		}

		prevNum := rangeStart
		for num := range inCh {
			if num != prevNum+1 {
				// yield previous range, start new one
				outCh <- formatRange(rangeStart, prevNum)
				rangeStart = num
			}
			prevNum = num
		}
		// final range
		outCh <- formatRange(rangeStart, prevNum)
	}(inCh, outCh)

	return outCh
}

func formatRange(start, end uint16) string {
	if start == end {
		return fmt.Sprintf("%d", start)
	}
	return fmt.Sprintf("%d-%d", start, end)
}

// set up and configure connection to the server
func getServerConn(serverNetloc string) serverConn {
	var tcpConn *net.TCPConn
	if addrport, err := netip.ParseAddrPort(serverNetloc); err != nil {
		log.Panicf("invalid server IP:port %q: %s\n", serverNetloc, err)
	} else {
		tcpaddr := net.TCPAddrFromAddrPort(addrport)
		tcpConn = common.Check1(net.DialTCP("tcp", nil, tcpaddr))
	}

	common.Check(tcpConn.SetKeepAlive(true))
	common.Check(tcpConn.SetKeepAlivePeriod(time.Second * 25))

	return serverConn{conn: tcpConn}
}

// generate protocol:port pairs to attempt to connect to from PortsResult
func generateDialInfo(result common.PortsResult, outCh chan<- dialInfo) {
	for i, ports := range []common.PackedPorts{result.Tcp, result.Udp} {
		proto := []string{"tcp", "udp"}[i]
		go func(ports common.PackedPorts, proto string, ch chan<- dialInfo) {
			di := dialInfo{proto: proto}
			for port := range ports.Iter() {
				di.port = strconv.Itoa(int(port))
				outCh <- di
			}
		}(ports, proto, outCh)
	}
}

// protocol:port pairs for dialer workers
type dialInfo struct {
	proto string
	port  string
}

// worker function waiting for protocol:port pairs from a channel to attempt to connect to
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

// attempt a connection to a protoocol:port pair
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

// wrapper struct for a connection to a server
type serverConn struct {
	conn *net.TCPConn
}

// close the server connection
func (sc serverConn) Close() {
	common.Check(sc.conn.Close())
}

// initial handshake between the client and server
func (sc serverConn) hello(ip netip.Addr, ports *common.PortsResult) {
	msg := common.InitMsg{
		Header: common.MSG_HELLOHEADER,
		Length: uint8(ip.BitLen() / 8),
	}
	copy(msg.Tcp.Packed[:], ports.Tcp.Packed[:])
	copy(msg.Udp.Packed[:], ports.Udp.Packed[:])
	copy(msg.Ip[:], ip.AsSlice())

	w := zlib.NewWriter(sc.conn)
	common.Check(binary.Write(w, binary.BigEndian, &msg))
	common.Check(w.Close())

	if sc.getSimple() != common.MSG_HELLOVALUE {
		log.Panicf("unexpected dummy value in done msg")
	}
}

// send a simple one-byte message to the server
func (sc serverConn) sendSimple(i uint8) {
	msg := common.Simple{Value: i}
	common.Check(binary.Write(sc.conn, binary.BigEndian, &msg))
}

// receive a simple one-byte message from the server
func (sc serverConn) getSimple() uint8 {
	var msg common.Simple
	common.Check(binary.Read(sc.conn, binary.BigEndian, &msg))
	return msg.Value
}

// send a GETPORTS message to the server and receive a PortsResult
func (sc serverConn) getPortsResult() common.PortsResult {
	sc.sendSimple(common.MSG_GETPORTS)

	var response common.PortsResult
	r := common.Check1(zlib.NewReader(sc.conn))
	common.Check(binary.Read(r, binary.BigEndian, &response))
	common.Check(r.Close())

	return response
}

// parse port string, e.g 80,443,600-700, and returns a channel
// with the resulting port numbers
func parsePortString(portS string) <-chan uint16 {
	ret := make(chan uint16, 16)

	go func(ch chan<- uint16, portS string) {
		for _, s := range strings.Split(portS, ",") {
			if !strings.Contains(s, "-") {
				ch <- uint16(common.Check1(strconv.ParseUint(s, 10, 16)))
				continue
			}
			startEnd := strings.SplitN(s, "-", 2)
			start := common.Check1(strconv.ParseUint(startEnd[0], 10, 16))
			end := common.Check1(strconv.ParseUint(startEnd[1], 10, 16))
			if start >= end {
				log.Panicf("invalid port range, %d >= %d (start >= end)", start, end)
			}

			for i := start; i <= end; i++ {
				ch <- uint16(i)
			}
		}
		close(ch)
	}(ret, portS)

	return ret
}
