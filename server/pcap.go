package main

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/monoidic/porttest/common"
)

func setupPcap(tcp, udp *[65536]bool, ports *common.PortsResult, ip string) (*pcap.Handle, *sync.WaitGroup) {
	initPortArrs(tcp, udp, ports)

	handle := common.Check1(pcap.OpenLive(netif, PACKETLEN, false, time.Millisecond))
	common.Check(handle.SetBPFFilter(fmt.Sprintf("src host %s and (tcp or udp)", ip)))

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.Lazy = true
	packetSource.NoCopy = true
	pcapChan := packetSource.Packets()

	var wg sync.WaitGroup
	wg.Add(NUMREADERS)

	for range NUMREADERS {
		go packetReader(pcapChan, &wg, tcp, udp)
	}

	return handle, &wg
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
