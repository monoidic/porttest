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

func main() {
	var netif string
	var ip string
	flag.StringVar(&netif, "netif", "eth0", "interface name to capture on")
	flag.StringVar(&ip, "ip", "127.0.0.1:57005", "IP:port to bind to")
	flag.Parse()

	if _, err := netip.ParseAddrPort(ip); err != nil {
		log.Panicf("invalid IP:port: %q", ip)
	}

	server := common.Check1(net.Listen("tcp", ip))

	for {
		if conn, err := server.Accept(); err == nil {
			fmt.Printf("got conn from %s\n", conn.RemoteAddr())
			go handleConn(netif, conn)
		} else {
			log.Printf("error accepting conn: %s", err)
		}

	}
}

func handleConn(netif string, conn net.Conn) {
	defer conn.Close()

	var tcpA, udpA [65536]bool

	ipStr, err := getInitMsg(conn, &tcpA, &udpA)
	if err != nil {
		log.Printf("error getting initmsg: %s", err)
		return
	}

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
		go packetReader(pcapChan, &wg, &tcpA, &udpA)
	}

	if err := sendSimple(conn, common.MSG_HELLOVALUE); err != nil {
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

		result.Pack(tcpA, udpA)
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
		} else if i != common.MSG_MORE {
			log.Printf("unexpected ports result response value: %x", i)
			return
		}
	}

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

var zeroAddr = netip.AddrFrom4([4]byte{0, 0, 0, 0})

// perform initial handshake/setup with the client
func getInitMsg(conn net.Conn, tcp, udp *[65536]bool) (ip string, err error) {
	var initmsg common.InitMsg
	r, err := zlib.NewReader(conn)
	if err != nil {
		return "", err
	}

	if err = binary.Read(r, binary.BigEndian, &initmsg); err != nil {
		r.Close()
		return "", err
	}

	if err = r.Close(); err != nil {
		return "", err
	}

	if initmsg.Header != common.MSG_HELLOHEADER {
		return "", common.Error{S: fmt.Sprintf("invalid header value: %x", initmsg.Header)}
	}

	if !(initmsg.Length == 4 || initmsg.Length == 16) {
		return "", common.Error{S: fmt.Sprintf("invalid addr length %d", initmsg.Length)}
	}

	addr, _ := netip.AddrFromSlice(initmsg.Ip[:initmsg.Length])

	if addr == zeroAddr {
		addrP, err := netip.ParseAddrPort(conn.RemoteAddr().String())
		if err != nil {
			return "", err
		}
		addr = addrP.Addr()
	}

	ip = addr.String()

	for i := 0; i < 65536; i++ {
		tcp[i] = true
		udp[i] = true
	}

	for i, msgPorts := range []common.PackedPorts{initmsg.Tcp, initmsg.Udp} {
		arr := []*[65536]bool{tcp, udp}[i]

		for port := range msgPorts.Iter() {
			arr[port] = false
		}
	}

	return ip, nil
}

// receive a simple one-byte message from the client
func getSimple(conn net.Conn) (uint8, error) {
	var msg common.Simple
	if err := binary.Read(conn, binary.BigEndian, &msg); err != nil {
		return 0, err
	}
	fmt.Printf("got simple %x\n", msg.Value)
	return msg.Value, nil
}

// send a simple one-byte message to the client
func sendSimple(conn net.Conn, i uint8) error {
	fmt.Printf("sending simple %x\n", i)
	return binary.Write(conn, binary.BigEndian, &common.Simple{Value: i})

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
