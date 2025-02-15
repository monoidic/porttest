package main

import (
	"flag"
	"fmt"
	"log"
	"net/netip"
	"net/url"
	"os"
	"sync"

	"github.com/monoidic/porttest/common"
)

var (
	numRetries int
)

func main() {
	var (
		targetIP     string
		serverNetloc string
		srcIP        string
		resultName   string
		portS        string
		numConns     int
		settings     common.InitSettings
		insecure     bool
	)

	flag.StringVar(&targetIP, "target_ip", "", "IP to send connection attempts to")
	flag.StringVar(&serverNetloc, "server_ip", "", "IP:port or URL for control channel")
	flag.StringVar(&srcIP, "src_ip", "0.0.0.0", "source IP of this host to send to server")
	flag.StringVar(&resultName, "result_name", "result", "name for this result")
	flag.StringVar(&portS, "ports", "0-1024", "ports to scan (format: comma-seperated ports or inclusive ranges, e.g 80,443,600-700)")
	flag.IntVar(&numConns, "conns", 20, "number of parallel connections to use")
	flag.IntVar(&numRetries, "retries", 3, "number of connection retries for server conn establishment")
	flag.BoolVar(&settings.Async, "async", false, "use async comms")
	flag.BoolVar(&settings.Http, "http", false, "use http comms")
	flag.BoolVar(&insecure, "insecure", false, "disable TLS certificate checks under HTTPS")
	flag.Parse()

	var numMatches int
	if settings.Async {
		numMatches++
	}
	if settings.Http {
		numMatches++
	}
	if numMatches > 1 {
		log.Panicln("multiple query variants specified")
	}

	if numRetries < 1 {
		log.Panicln("invalid retries value")
	}

	if targetIP == "" {
		log.Panicln("target IP unspecified")
	}

	if _, err := netip.ParseAddr(targetIP); err != nil {
		log.Panicf("invalid target IP %q: %s\n", targetIP, err)
	}

	srcAddr, err := netip.ParseAddr(srcIP)
	if err != nil {
		log.Panicf("invalid source IP %q: %s\n", srcIP, err)
	}

	if settings.Http && srcAddr == netip.IPv4Unspecified() {
		log.Panic("currently need specified source address for http")
	}

	var addrPort netip.AddrPort
	if settings.Http {
		_, err = url.ParseRequestURI(serverNetloc)
		if err != nil {
			log.Panicf("error trying to parse url %q: %s", serverNetloc, err)
		}
	} else {
		if serverNetloc == "" {
			serverNetloc = fmt.Sprintf("%s:57005", targetIP)
		}
		addrPort, err = netip.ParseAddrPort(serverNetloc)
		if err != nil {
			log.Panicf("invalid server IP:port %q: %s\n", serverNetloc, err)
		}
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

	for range numConns {
		go dialer(targetIP, dialCh, &wg)
	}

	var sc serverConn

	switch {
	case settings.Async:
		sc = getAsyncConn(addrPort, srcAddr, &ports)
	case settings.Http:
		sc = getHttpConn(serverNetloc, insecure, srcAddr, &ports)
	default:
		sc = getSyncConn(addrPort, srcAddr, &ports)
	}

	doScan(sc, &ports, dialCh, &wg)

	saveResults(resultName, &ports)
}

func doScan(sc serverConn, ports *common.PortsResult, dialCh chan dialInfo, wg *sync.WaitGroup) {
	sc.setup()
	defer sc.close()

	portCount := ports.Len()
	for {
		wg.Add(portCount)
		go generateDialInfo(ports, dialCh)
		wg.Wait()

		sc.getPorts()
		newCount := ports.Len()
		fmt.Printf("\nport count: %d\n", newCount)

		if newCount == 0 || portCount == newCount {
			break
		} else if newCount > portCount {
			log.Panicf("%d closed ports before, %d after", portCount, newCount)
		}

		portCount = newCount

		sc.more()
	}

	sc.done()
	close(dialCh)
}

type serverConn interface {
	// initiate connection/ticket init etc.
	setup()
	// update list of currently seen ports
	getPorts()
	// ask to continue connection (can be no-op)
	more()
	// signal end of connection
	done()
	// cleanup
	close()
}

// save results as formatted text to results/{resultName}.txt
func saveResults(resultName string, ports *common.PortsResult) {
	common.Check(os.MkdirAll("results", 0o755))
	fd := common.Check1(os.Create(fmt.Sprintf("results/%s.txt", resultName)))
	defer fd.Close()

	for pPortsI, pPorts := range []common.PackedPorts{ports.Tcp, ports.Udp} {
		proto := []string{"tcp", "udp"}[pPortsI]

		fmt.Fprintf(fd, "[closed %s ports]\n", proto)
		for portRange := range numsToRanges(pPorts.IterClosed) {
			fmt.Fprintf(fd, "%s\n", portRange)
		}
		fmt.Fprint(fd, "\n")

		fmt.Fprintf(fd, "[open %s ports]\n", proto)
		for portRange := range numsToRanges(pPorts.IterOpen) {
			fmt.Fprintf(fd, "%s\n", portRange)
		}
		fmt.Fprint(fd, "\n")

	}
}
