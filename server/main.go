package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sync"

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

var (
	scanLimit  int
	asyncScans = map[uint64]asyncScanInfo{}
	asyncMux   sync.Mutex
	netif      string
)

type asyncScanInfo struct {
	handle   *pcap.Handle
	tcp, udp *[65536]bool
	workerWG *sync.WaitGroup
}

func main() {
	var (
		httpIP string
		tcpIP  string
	)

	flag.StringVar(&netif, "netif", "eth0", "interface name to capture on")
	flag.StringVar(&tcpIP, "tcp_ip", "127.0.0.1:57005", "IP:port to bind to for tcp")
	flag.StringVar(&httpIP, "http_ip", "127.0.0.1:8008", "IP:port to bind to for http")
	flag.IntVar(&scanLimit, "scan_limit", 16, "limit of parallel async scans")
	flag.Parse()

	if _, err := netip.ParseAddrPort(tcpIP); err != nil {
		log.Panicf("invalid tcp IP:port: %q", tcpIP)
	}

	if _, err := netip.ParseAddrPort(httpIP); err != nil {
		log.Panicf("invalid http IP:port: %q", tcpIP)
	}

	server := common.Check1(net.Listen("tcp", tcpIP))

	http.HandleFunc("/", httpHandler)
	go http.ListenAndServe(httpIP, nil)

	for {
		if conn, err := server.Accept(); err == nil {
			fmt.Printf("got conn from %s\n", conn.RemoteAddr())
			go handleConn(conn)
		} else {
			log.Printf("error accepting conn: %s", err)
		}
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()

	ipStr, settings, err := getInitMsg(conn)
	if err != nil {
		log.Printf("error getting initmsg: %s", err)
		return
	}

	if settings.Async {
		handleAsync(ipStr, conn)
	} else {
		handleSync(ipStr, conn)
	}
}
