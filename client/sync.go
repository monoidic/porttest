package main

import (
	"compress/zlib"
	"encoding/binary"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/monoidic/porttest/common"
)

// wrapper struct for a connection to a server
type syncServerConn struct {
	serverNetloc netip.AddrPort
	conn         *net.TCPConn
	srcIP        netip.Addr
	ports        *common.PortsResult
}

var _ serverConn = (*syncServerConn)(nil)

func getSyncConn(addrPort netip.AddrPort, srcIP netip.Addr, ports *common.PortsResult) *syncServerConn {
	return &syncServerConn{
		serverNetloc: addrPort,
		srcIP:        srcIP,
		ports:        ports,
	}
}

func (sc *syncServerConn) dial() {
	tcpaddr := net.TCPAddrFromAddrPort(sc.serverNetloc)
	var tcpConn *net.TCPConn
	var err error
	for range numRetries {
		tcpConn, err = net.DialTCP("tcp", nil, tcpaddr)
		if err == nil {
			break
		}
	}

	common.Check(err)

	common.Check(tcpConn.SetKeepAlive(true))
	common.Check(tcpConn.SetKeepAlivePeriod(time.Second * 25))

	sc.conn = tcpConn
}

func (sc *syncServerConn) setup() {
	sc.dial()
	sc.hello(false)
	sc.sendPortsResult()

	if sc.getSimple() != common.MSG_INIT_DONE {
		log.Panicf("expected init done msg")
	}
}

// send a GETPORTS message to the server and receive a PortsResult
func (sc *syncServerConn) getPorts() {
	sc.sendSimple(common.MSG_GETPORTS)
	r := common.Check1(zlib.NewReader(sc.conn))
	common.Check(binary.Read(r, binary.BigEndian, sc.ports))
	common.Check(r.Close())
}

func (sc *syncServerConn) more() {
	sc.sendSimple(common.MSG_SYNC_MORE)
}

func (sc *syncServerConn) done() {
	sc.sendSimple(common.MSG_DONE)
}

// close the server connection
func (sc *syncServerConn) close() {
	common.Check(sc.conn.Close())
}

// initial handshake between the client and server
func (sc *syncServerConn) hello(async bool) {
	msg := common.InitMsg{
		Header:  common.MSG_HELLOHEADER,
		Version: common.VERSION,
	}

	copy(msg.Ip[:], sc.srcIP.AsSlice())

	if sc.srcIP.Is6() {
		msg.Flags |= common.FLAG_V6
	}

	if async {
		msg.Flags |= common.FLAG_ASYNC
	}

	common.Check(binary.Write(sc.conn, binary.BigEndian, &msg))
}

// send a simple one-byte message to the server
func (sc *syncServerConn) sendSimple(i uint8) {
	common.Check(binary.Write(sc.conn, binary.BigEndian, &i))
}

// receive a simple one-byte message from the server
func (sc *syncServerConn) getSimple() uint8 {
	var msg uint8
	common.Check(binary.Read(sc.conn, binary.BigEndian, &msg))
	return msg
}

// send a PortsResult to the client
func (sc *syncServerConn) sendPortsResult() {
	w := zlib.NewWriter(sc.conn)
	common.Check(binary.Write(w, binary.BigEndian, sc.ports))
	common.Check(w.Close())
}
