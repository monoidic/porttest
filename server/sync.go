package main

import (
	"compress/zlib"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/monoidic/porttest/common"
)

func handleSync(ipStr string, conn net.Conn) {
	var tcp, udp [65536]bool

	ports, err := getPortsResult(conn)
	if err != nil {
		log.Printf("error getting port result: %s", err)
		return
	}

	handle, wg := setupPcap(&tcp, &udp, &ports, ipStr)

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

	if addr == netip.IPv4Unspecified() {
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

func initPortArrs(tcp, udp *[65536]bool, result *common.PortsResult) {
	for i := range 65536 {
		tcp[i] = true
		udp[i] = true
	}

	for i, msgPorts := range []common.PackedPorts{result.Tcp, result.Udp} {
		arr := []*[65536]bool{tcp, udp}[i]

		for port := range msgPorts.IterClosed {
			arr[port] = false
		}
	}
}

func makeCache() *ttlcache.Cache[uint64, *asyncScanInfo] {
	cache := ttlcache.New(
		ttlcache.WithTTL[uint64, *asyncScanInfo](6 * time.Hour),
	)
	cache.OnEviction(func(ctx context.Context, reason ttlcache.EvictionReason, item *ttlcache.Item[uint64, *asyncScanInfo]) {
		v := item.Value()
		v.handle.Close()
		v.workerWG.Wait()

	})
	return cache
}
