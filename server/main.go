package main

import (
	"compress/zlib"
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

	"github.com/monoidic/porttest/common"
)

const (
	NUMREADERS = 20
	ETHLEN     = 14
	IPLEN      = 60
	TCPUDPLEN  = 60
	BUFFER     = 128
	PACKETLEN  = ETHLEN + IPLEN + TCPUDPLEN + BUFFER
)

var scanLimit int

type asyncScanInfo struct {
	handle   *pcap.Handle
	tcp, udp *[65536]bool
	workerWG *sync.WaitGroup
}

func main() {
	var netif string
	var ip string
	flag.StringVar(&netif, "netif", "eth0", "interface name to capture on")
	flag.StringVar(&ip, "ip", "127.0.0.1:57005", "IP:port to bind to")
	flag.IntVar(&scanLimit, "scan_limit", 16, "limit of parallel async scans")
	flag.Parse()

	if _, err := netip.ParseAddrPort(ip); err != nil {
		log.Panicf("invalid IP:port: %q", ip)
	}

	server := common.Check1(net.Listen("tcp", ip))

	asyncScans := map[uint64]asyncScanInfo{}
	var asyncMux sync.Mutex

	for {
		if conn, err := server.Accept(); err == nil {
			fmt.Printf("got conn from %s\n", conn.RemoteAddr())
			go handleConn(netif, conn, asyncScans, &asyncMux)
		} else {
			log.Printf("error accepting conn: %s", err)
		}

	}
}

func handleConn(netif string, conn net.Conn, asyncScans map[uint64]asyncScanInfo, asyncMux *sync.Mutex) {
	defer conn.Close()

	ipStr, settings, err := getInitMsg(conn)
	if err != nil {
		log.Printf("error getting initmsg: %s", err)
		return
	}

	if settings.Async {
		handleAsync(netif, ipStr, conn, settings, asyncScans, asyncMux)
	} else {
		handleSync(netif, ipStr, conn, settings)
	}

}

func handleSync(netif, ipStr string, conn net.Conn, settings common.InitSettings) {
	var tcp, udp [65536]bool

	ports, err := getPortsResult(conn)
	if err != nil {
		log.Printf("error getting port result: %s", err)
		return
	}

	initPortArrs(&tcp, &udp, ports)

	handle := common.Check1(pcap.OpenLive(netif, PACKETLEN, false, pcap.BlockForever))
	common.Check(handle.SetBPFFilter(fmt.Sprintf("src host %s and (tcp or udp)", ipStr)))
	defer handle.Close() // duplicate close is fine

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.Lazy = true
	packetSource.NoCopy = true
	pcapChan := packetSource.Packets()

	var wg sync.WaitGroup
	wg.Add(NUMREADERS)

	for i := 0; i < NUMREADERS; i++ {
		go packetReader(pcapChan, &wg, &tcp, &udp)
	}

	if err := sendSimple(conn, common.MSG_INIT_DONE); err != nil {
		log.Printf("error sending ready message: %s", err)
		return
	}

	var result common.PortsResult

	for {
		if i, err := getSimple(conn); err != nil {
			log.Printf("error getting simple message in loop: %s", err)
			return
		} else if i != common.MSG_GETPORTS {
			log.Printf("unexpected simple message value: %x", i)
			return
		}

		// for any stray packets
		time.Sleep(time.Second * 1)

		result.Pack(&tcp, &udp)
		if err := sendPortsResult(conn, result); err != nil {
			log.Printf("error sending ports result: %s", err)
			return
		}

		if i, err := getSimple(conn); err != nil {
			log.Printf("error getting ports result response: %s", err)
			return
		} else if i == common.MSG_DONE {
			handle.Close()
			wg.Wait()
			return
		} else if i != common.MSG_SYNC_MORE {
			log.Printf("unexpected ports result response value: 0x%x", i)
			return
		}
	}

}

func handleAsync(netif, ipStr string, conn net.Conn, settings common.InitSettings, asyncScans map[uint64]asyncScanInfo, asyncMux *sync.Mutex) {
	init, err := getAsyncInit(conn)
	if err != nil {
		log.Printf("error getting async init message: %s", err)
		return
	}

	msg, err := getSimple(conn)
	if err != nil {
		log.Printf("error getting async message: %s", err)
		return
	}

	if msgS, ok := common.MsgMap[msg]; ok {
		log.Printf("got %s with ticket 0x%x\n", msgS, init.Ticket)
	} else {
		log.Printf("got invalid msg 0x%x", msg)
		return
	}

	asyncMux.Lock()
	defer asyncMux.Unlock()

	switch msg {
	case common.MSG_ASYNC_START:
		handleAsyncStart(conn, init, netif, ipStr, asyncScans)
	case common.MSG_GETPORTS:
		handleAsyncGetports(conn, init, netif, ipStr, asyncScans)
	case common.MSG_DONE:
		handleAsyncDone(conn, init, netif, ipStr, asyncScans)
	default:
		log.Printf("unexpected async message: 0x%x", msg)
	}
}

func handleAsyncStart(conn net.Conn, init common.AsyncInit, netif, ipStr string, asyncScans map[uint64]asyncScanInfo) {
	_, exists := asyncScans[init.Ticket]
	if exists {
		log.Printf("duplicate ticket 0x%x started", init.Ticket)
		return
	}

	if len(asyncScans) > scanLimit {
		log.Printf("scan limit of %d exceeded", scanLimit)
		return
	}

	ports, err := getPortsResult(conn)
	if err != nil {
		log.Printf("error getting ports in async start: %s", err)
		return
	}

	var tcp, udp [65536]bool
	initPortArrs(&tcp, &udp, ports)

	handle := common.Check1(pcap.OpenLive(netif, PACKETLEN, false, pcap.BlockForever))
	common.Check(handle.SetBPFFilter(fmt.Sprintf("src host %s and (tcp or udp)", ipStr)))

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.Lazy = true
	packetSource.NoCopy = true
	pcapChan := packetSource.Packets()

	var wg sync.WaitGroup
	wg.Add(NUMREADERS)

	for i := 0; i < NUMREADERS; i++ {
		go packetReader(pcapChan, &wg, &tcp, &udp)
	}

	asyncScans[init.Ticket] = asyncScanInfo{
		handle:   handle,
		tcp:      &tcp,
		udp:      &udp,
		workerWG: &wg,
	}

	if err := sendSimple(conn, common.MSG_INIT_DONE); err != nil {
		log.Printf("error sending init done message in async: %s", err)
		return
	}
}

func handleAsyncGetports(conn net.Conn, init common.AsyncInit, netif, ipStr string, asyncScans map[uint64]asyncScanInfo) {
	scanInfo, exists := asyncScans[init.Ticket]
	if !exists {
		log.Printf("non-existing ticket 0x%x accessed in async getports", init.Ticket)
		return
	}

	var result common.PortsResult
	result.Pack(scanInfo.tcp, scanInfo.udp)
	if err := sendPortsResult(conn, result); err != nil {
		log.Printf("error sending async ports result: %s", err)
		return
	}
}

func handleAsyncDone(conn net.Conn, init common.AsyncInit, netif, ipStr string, asyncScans map[uint64]asyncScanInfo) {
	scanInfo, exists := asyncScans[init.Ticket]
	if !exists {
		log.Printf("non-existing ticket 0x%x accessed in async done", init.Ticket)
		return
	}

	scanInfo.handle.Close()
	scanInfo.workerWG.Wait()
	delete(asyncScans, init.Ticket)
	if err := sendSimple(conn, common.MSG_DONE); err != nil {
		log.Printf("error sending async done message: %s", err)
		return
	}

}

func getAsyncInit(conn net.Conn) (init common.AsyncInit, err error) {
	err = binary.Read(conn, binary.BigEndian, &init)
	return
}

// send a PortsResult to the client
func sendPortsResult(conn net.Conn, result common.PortsResult) error {
	totalCount := 0

	for portsI, ports := range []common.PackedPorts{result.Tcp, result.Udp} {
		proto := []string{"tcp", "udp"}[portsI]
		protoLen := ports.Len()
		fmt.Printf("sending %d %s ports\n", protoLen, proto)
		totalCount += protoLen
	}
	fmt.Printf("%d ports total\n", totalCount)

	w := zlib.NewWriter(conn)
	if err := binary.Write(w, binary.BigEndian, &result); err != nil {
		w.Close()
		return err
	}
	return w.Close()
}

func getPortsResult(conn net.Conn) (result common.PortsResult, err error) {
	r, err := zlib.NewReader(conn)
	if err != nil {
		return
	}

	if err = binary.Read(r, binary.BigEndian, &result); err != nil {
		r.Close()
		return
	}

	err = r.Close()
	return
}

var zeroAddr = netip.AddrFrom4([4]byte{0, 0, 0, 0})

// perform initial handshake/setup with the client
func getInitMsg(conn net.Conn) (ip string, settings common.InitSettings, err error) {
	var initmsg common.InitMsg

	if err = binary.Read(conn, binary.BigEndian, &initmsg); err != nil {
		return
	}

	if initmsg.Header != common.MSG_HELLOHEADER {
		err = common.Error{S: fmt.Sprintf("invalid header value: %x", initmsg.Header)}
		return
	}

	if initmsg.Version != common.VERSION {
		err = common.Error{S: fmt.Sprintf("unknown version 0x%x (built for version 0x%x)", initmsg.Version, common.VERSION)}
		return
	}

	if initmsg.Flags > common.FLAG_MAX {
		err = common.Error{S: fmt.Sprintf("unknown flags set (0x%x)", initmsg.Flags)}
		return
	}

	ipB := initmsg.Ip[:]

	if (initmsg.Flags & common.FLAG_V6) == 0 {
		ipB = ipB[:4]
	}

	if (initmsg.Flags & common.FLAG_ASYNC) != 0 {
		settings.Async = true
	}

	addr, _ := netip.AddrFromSlice(ipB)

	if addr == zeroAddr {
		var addrP netip.AddrPort
		addrP, err = netip.ParseAddrPort(conn.RemoteAddr().String())
		if err != nil {
			return
		}
		addr = addrP.Addr()
	}

	ip = addr.String()

	return
}

func initPortArrs(tcp, udp *[65536]bool, result common.PortsResult) {
	for i := 0; i < 65536; i++ {
		tcp[i] = true
		udp[i] = true
	}

	for i, msgPorts := range []common.PackedPorts{result.Tcp, result.Udp} {
		arr := []*[65536]bool{tcp, udp}[i]

		for port := range msgPorts.Iter() {
			arr[port] = false
		}
	}
}

// receive a simple one-byte message from the client
func getSimple(conn net.Conn) (uint8, error) {
	var msg uint8
	if err := binary.Read(conn, binary.BigEndian, &msg); err != nil {
		return 0, err
	}
	fmt.Printf("got simple %x (%q)\n", msg, common.MsgMap[msg])
	return msg, nil
}

// send a simple one-byte message to the client
func sendSimple(conn net.Conn, i uint8) error {
	fmt.Printf("sending simple %x (%q)\n", i, common.MsgMap[i])
	return binary.Write(conn, binary.BigEndian, &i)

}

// read pcap channel messages and mark ports as being reachable
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
