package main

import (
	"encoding/binary"
	"log"
	"net"

	"github.com/jellydator/ttlcache/v3"
	"github.com/monoidic/porttest/common"
)

func handleAsync(ipStr string, conn net.Conn) {
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
		log.Printf("got %s with ticket 0x%x, %d scans active\n", msgS, init.Ticket, asyncScans.Len())
	} else {
		log.Printf("got invalid msg 0x%x", msg)
		return
	}

	asyncMux.Lock()
	defer asyncMux.Unlock()

	switch msg {
	case common.MSG_ASYNC_START:
		handleAsyncStart(conn, init, ipStr)
	case common.MSG_GETPORTS:
		handleAsyncGetports(conn, init)
	case common.MSG_DONE:
		handleAsyncDone(conn, init)
	default:
		log.Printf("unexpected async message: 0x%x", msg)
	}
}

func handleAsyncStart(conn net.Conn, init common.AsyncInit, ipStr string) {
	if asyncScans.Has(init.Ticket) {
		log.Printf("duplicate ticket 0x%x started", init.Ticket)
		return
	}

	if asyncScans.Len() > scanLimit {
		log.Printf("scan limit of %d exceeded", scanLimit)
		return
	}

	ports, err := getPortsResult(conn)
	if err != nil {
		log.Printf("error getting ports in async start: %s", err)
		return
	}

	var tcp, udp [65536]bool
	handle, wg := setupPcap(&tcp, &udp, &ports, ipStr)

	info := &asyncScanInfo{
		handle:   handle,
		tcp:      &tcp,
		udp:      &udp,
		workerWG: wg,
	}
	asyncScans.Set(init.Ticket, info, ttlcache.DefaultTTL)

	if err := sendSimple(conn, common.MSG_INIT_DONE); err != nil {
		log.Printf("error sending init done message in async: %s", err)
		return
	}
}

func handleAsyncGetports(conn net.Conn, init common.AsyncInit) {
	item := asyncScans.Get(init.Ticket)
	if item == nil {
		log.Printf("non-existing ticket 0x%x accessed in async getports", init.Ticket)
		return
	}

	scanInfo := item.Value()

	var result common.PortsResult
	result.Pack(scanInfo.tcp, scanInfo.udp)
	if err := sendPortsResult(conn, result); err != nil {
		log.Printf("error sending async ports result: %s", err)
		return
	}
}

func handleAsyncDone(conn net.Conn, init common.AsyncInit) {
	_, existed := asyncScans.GetAndDelete(init.Ticket)
	if !existed {
		log.Printf("non-existing ticket 0x%x accessed in async done", init.Ticket)
		return
	}

	if err := sendSimple(conn, common.MSG_DONE); err != nil {
		log.Printf("error sending async done message: %s", err)
		return
	}
}

func getAsyncInit(conn net.Conn) (init common.AsyncInit, err error) {
	err = binary.Read(conn, binary.BigEndian, &init)
	return
}
