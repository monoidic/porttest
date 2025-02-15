package main

import (
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/monoidic/porttest/common"
)

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
	for range 3 {
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
			for port := range ports.IterClosed {
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
