package main

import (
	"compress/zlib"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"math/rand"
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
	var settings common.InitSettings
	flag.StringVar(&targetIP, "target_ip", "", "IP to send connection attempts to")
	flag.StringVar(&serverNetloc, "server_ip", "", "IP:port to connect to for commands attempts to")
	flag.StringVar(&srcIP, "src_ip", "0.0.0.0", "source IP of this host to send to server")
	flag.StringVar(&resultName, "result_name", "result", "name for this result")
	flag.StringVar(&portS, "ports", "0-1024", "ports to scan (format: comma-seperated ports or inclusive ranges, e.g 80,443,600-700)")
	flag.IntVar(&numConns, "conns", 20, "number of parallel connections to use")
	flag.BoolVar(&settings.Async, "async", false, "use async comms")
	flag.Parse()

	if targetIP == "" {
		log.Panicln("target IP unpsecified")
	}

	if _, err := netip.ParseAddr(targetIP); err != nil {
		log.Panicf("invalid target IP %q: %s\n", targetIP, err)
	}

	if _, err := netip.ParseAddr(srcIP); err != nil {
		log.Panicf("invalid source IP %q: %s\n", srcIP, err)
	}

	if serverNetloc == "" {
		serverNetloc = fmt.Sprintf("%s:57005", targetIP)
	}

	dialCh := make(chan dialInfo, 64)
	var wg sync.WaitGroup

	var ports common.PortsResult

	for port := range parsePortString(portS) {
		index := port / 8
		mask := uint8(1 << (port % 8))
		ports.Tcp.Packed[index] |= mask
		ports.Udp.Packed[index] |= mask
	}

	for i := 0; i < numConns; i++ {
		go dialer(targetIP, dialCh, &wg)
	}

	doScan(serverNetloc, srcIP, &ports, settings, dialCh, &wg)

	saveResults(resultName, ports)
}

func doScan(serverNetloc, srcIP string, ports *common.PortsResult, settings common.InitSettings, dialCh chan dialInfo, wg *sync.WaitGroup) {
	var sc serverConn
	var ticket uint64

	if settings.Async {
		ticket = asyncSetup(serverNetloc, srcIP, ports, settings)
	} else {
		sc = syncSetup(serverNetloc, srcIP, ports, settings)
		defer sc.Close()
	}

	portCount := ports.Len()
	for {
		wg.Add(portCount)
		go generateDialInfo(ports, dialCh)

		wg.Wait()

		if settings.Async {
			asyncGetports(serverNetloc, ports, settings, ticket)
		} else {
			sc.getPortsResult(ports)
		}
		newCount := ports.Len()

		if newCount == 0 || portCount == newCount {
			break
		}
		if newCount > portCount {
			log.Panicf("%d closed ports before, %d after", portCount, newCount)
		}

		portCount = newCount
		fmt.Printf("\nport count: %d\n", portCount)

		if !settings.Async {
			sc.sendSimple(common.MSG_SYNC_MORE)
		}
	}

	if settings.Async {
		asyncDone(serverNetloc, ports, settings, ticket)
	} else {
		sc.sendSimple(common.MSG_DONE)
	}

	close(dialCh)
}

func syncSetup(serverNetloc, srcIP string, ports *common.PortsResult, settings common.InitSettings) serverConn {
	sc := getServerConn(serverNetloc)

	sc.hello(netip.MustParseAddr(srcIP), settings)
	sc.sendPortsResult(ports)

	if sc.getSimple() != common.MSG_INIT_DONE {
		log.Panicf("expected init done msg")
	}
	return sc
}

func asyncSetup(serverNetloc, srcIP string, ports *common.PortsResult, settings common.InitSettings) uint64 {
	sc := getServerConn(serverNetloc)
	defer sc.Close()

	sc.hello(netip.MustParseAddr(srcIP), settings)
	ticket := rand.Uint64()
	sc.SendAsyncInit(&common.AsyncInit{Ticket: ticket})
	sc.sendSimple(common.MSG_ASYNC_START)
	sc.sendPortsResult(ports)

	if msg := sc.getSimple(); msg != common.MSG_INIT_DONE {
		log.Panicf("expected init done message, got 0x%x", msg)
	}

	return ticket
}

func asyncGetports(serverNetloc string, ports *common.PortsResult, settings common.InitSettings, ticket uint64) {
	sc := getServerConn(serverNetloc)
	defer sc.Close()

	sc.hello(netip.IPv6Loopback(), settings)
	sc.SendAsyncInit(&common.AsyncInit{Ticket: ticket})
	sc.getPortsResult(ports)
}

func asyncDone(serverNetloc string, ports *common.PortsResult, settings common.InitSettings, ticket uint64) {
	sc := getServerConn(serverNetloc)
	defer sc.Close()

	sc.hello(netip.IPv6Loopback(), settings)
	sc.SendAsyncInit(&common.AsyncInit{Ticket: ticket})
	sc.sendSimple(common.MSG_DONE)
	if sc.getSimple() != common.MSG_DONE {
		log.Panicf("expected async done message")
	}
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
func generateDialInfo(result *common.PortsResult, outCh chan<- dialInfo) {
	// status info for printing
	var currentTCP, currentUDP uint16
	var numTCP, numUDP int
	var tcpDone, udpDone bool

	for i, ports := range []common.PackedPorts{result.Tcp, result.Udp} {
		// per-protocol info
		proto := []string{"tcp", "udp"}[i]
		currentPort := []*uint16{&currentTCP, &currentUDP}[i]
		currentProtoDone := []*bool{&tcpDone, &udpDone}[i]
		numPorts := []*int{&numTCP, &numUDP}[i]

		go func(ports common.PackedPorts, proto string, ch chan<- dialInfo, currentPort *uint16, currentProto *bool, numPorts *int) {
			// collect together and shuffle ports instead of scanning through linearly
			var infos []dialInfo
			for port := range ports.Iter() {
				infos = append(infos, dialInfo{proto: proto, port: strconv.Itoa(int(port))})
			}

			rand.Shuffle(len(infos), func(i, j int) { infos[i], infos[j] = infos[j], infos[i] })
			*numPorts = len(infos)

			for i, inf := range infos {
				*currentPort = uint16(i)
				outCh <- inf
			}

			*currentProto = true
		}(ports, proto, outCh, currentPort, currentProtoDone, numPorts)
	}

	// periodically print out scan status info
	go func(currentTCP, currentUDP *uint16, tcpDone, udpDone *bool, numTcp, numUDP *int) {
		for {
			time.Sleep(time.Second)
			currentTCP := *currentTCP + 1
			currentUDP := *currentUDP + 1
			numTcp := *numTcp
			numUDP := *numUDP
			if *tcpDone && *udpDone {
				break
			}
			fmt.Printf("\rTCP: %d/%d, UDP: %d/%d        ", currentTCP, numTcp, currentUDP, numUDP)
		}
	}(&currentTCP, &currentUDP, &tcpDone, &udpDone, &numTCP, &numUDP)
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

var (
	dialPayload = []byte("X")
	dialTimeout = time.Second * 3
	pause       = time.Millisecond * 10
)

// attempt a connection to a protoocol:port pair
func tryDial(proto, host string) bool {
	conn, err := net.DialTimeout(proto, host, dialTimeout)
	if err != nil {
		return strings.Contains(err.Error(), "connection refused")
		// fmt.Printf("%T %[1]s\n", err)
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
func (sc serverConn) hello(ip netip.Addr, settings common.InitSettings) {
	msg := common.InitMsg{
		Header:  common.MSG_HELLOHEADER,
		Version: common.VERSION,
	}

	copy(msg.Ip[:], ip.AsSlice())

	if ip.Is6() {
		msg.Flags |= common.FLAG_V6
	}
	if settings.Async {
		msg.Flags |= common.FLAG_ASYNC
	}

	common.Check(binary.Write(sc.conn, binary.BigEndian, &msg))
}

// send a simple one-byte message to the server
func (sc serverConn) sendSimple(i uint8) {
	common.Check(binary.Write(sc.conn, binary.BigEndian, &i))
}

// receive a simple one-byte message from the server
func (sc serverConn) getSimple() uint8 {
	var msg uint8
	common.Check(binary.Read(sc.conn, binary.BigEndian, &msg))
	return msg
}

// send a GETPORTS message to the server and receive a PortsResult
func (sc serverConn) getPortsResult(response *common.PortsResult) {
	sc.sendSimple(common.MSG_GETPORTS)
	r := common.Check1(zlib.NewReader(sc.conn))
	common.Check(binary.Read(r, binary.BigEndian, response))
	common.Check(r.Close())
}

// send a PortsResult to the client
func (sc serverConn) sendPortsResult(result *common.PortsResult) {
	w := zlib.NewWriter(sc.conn)
	common.Check(binary.Write(w, binary.BigEndian, result))
	common.Check(w.Close())
}

func (sc serverConn) SendAsyncInit(msg *common.AsyncInit) {
	common.Check(binary.Write(sc.conn, binary.BigEndian, msg))
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
