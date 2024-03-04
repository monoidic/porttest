package main

import (
	"encoding/binary"
	"log"
	"math/rand"
	"net/netip"

	"github.com/monoidic/porttest/common"
)

type asyncServerConn struct {
	serverNetloc netip.AddrPort
	srcIP        netip.Addr
	ports        *common.PortsResult
	ticket       uint64
}

var _ serverConn = (*asyncServerConn)(nil)

func getAsyncConn(addrPort netip.AddrPort, srcIP netip.Addr, ports *common.PortsResult) *asyncServerConn {
	sc := &asyncServerConn{
		serverNetloc: addrPort,
		srcIP:        srcIP,
		ports:        ports,
		ticket:       rand.Uint64(),
	}
	return sc
}

func (sc *asyncServerConn) setup() {
	conn := sc.tmpConn()
	defer conn.close()

	conn.sendSimple(common.MSG_ASYNC_START)
	conn.sendPortsResult()

	if msg := conn.getSimple(); msg != common.MSG_INIT_DONE {
		log.Panicf("expected init done message, got 0x%x", msg)
	}
}

func (sc *asyncServerConn) tmpConn() *syncServerConn {
	ret := getSyncConn(sc.serverNetloc, sc.srcIP, sc.ports)
	ret.dial()
	ret.hello(true)
	common.Check(binary.Write(ret.conn, binary.BigEndian, &common.AsyncInit{Ticket: sc.ticket}))
	return ret
}

func (sc *asyncServerConn) getPorts() {
	conn := sc.tmpConn()
	defer conn.close()
	conn.getPorts()
}

func (sc *asyncServerConn) done() {
	conn := sc.tmpConn()
	defer conn.close()

	conn.sendSimple(common.MSG_DONE)
	if conn.getSimple() != common.MSG_DONE {
		log.Panicf("expected async done message")
	}
}

func (sc *asyncServerConn) close() {
	// no-op
}

func (sc *asyncServerConn) more() {
	// no-op
}
