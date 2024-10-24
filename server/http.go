package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/netip"

	"github.com/jellydator/ttlcache/v3"
	"github.com/monoidic/porttest/common"
)

func httpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		log.Printf("non-POST method: %q", r.Method)
		return
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("error reading body: %s", err)
		return
	}

	var msg common.HttpMessage
	err = json.Unmarshal(raw, &msg)
	if err != nil {
		log.Printf("error reading message: %s", err)
		return
	}

	if msgS, ok := common.MsgMap[msg.Code]; ok {
		log.Printf("got http %s with ticket 0x%x, %d scans active\n", msgS, msg.Ticket, asyncScans.Len())
	} else {
		log.Printf("got invalid http msg 0x%x", msg.Code)
		return
	}

	srcIPPort := r.Host

	asyncMux.Lock()
	defer asyncMux.Unlock()

	switch msg.Code {
	case common.MSG_ASYNC_START:
		httpStart(w, &msg, srcIPPort)
	case common.MSG_GETPORTS:
		httpGetPorts(w, &msg)
	case common.MSG_DONE:
		httpDone(w, &msg)
	}
}

func httpStart(w http.ResponseWriter, msg *common.HttpMessage, srcIPPort string) {
	var initMsg common.HttpInitMsg
	err := json.Unmarshal(msg.Body, &initMsg)
	if err != nil {
		log.Printf("unable to decode initMsg: %s", err)
		return
	}

	if initMsg.Version != common.VERSION {
		log.Printf("mismatching version (expected %d, got %d)", common.VERSION, initMsg.Version)
		return
	}

	ip, err := netip.ParseAddr(initMsg.Ip)
	if err != nil {
		log.Printf("error parsing ip: %s", err)
		return
	}

	if ip == netip.IPv4Unspecified() {
		ip = netip.MustParseAddrPort(srcIPPort).Addr()
	}

	if asyncScans.Has(msg.Ticket) {
		log.Printf("ticket already present: 0x%x", msg.Ticket)
		return
	}

	if asyncScans.Len() > scanLimit {
		log.Print("over scan limit")
		return
	}

	portsBin, err := common.FromZlib(initMsg.Ports)
	if err != nil {
		log.Printf("failed to decode zlib: %s", err)
		return
	}

	var ports common.PortsResult

	if err = binary.Read(bytes.NewBuffer(portsBin), binary.BigEndian, &ports); err != nil {
		log.Printf("error parsing ports: %s", err)
		return
	}

	var tcp, udp [65536]bool

	handle, wg := setupPcap(&tcp, &udp, &ports, ip.String())

	info := &asyncScanInfo{
		handle:   handle,
		tcp:      &tcp,
		udp:      &udp,
		workerWG: wg,
	}
	asyncScans.Set(msg.Ticket, info, ttlcache.DefaultTTL)

	resp := common.HttpMessage{
		Code: common.MSG_INIT_DONE,
	}

	if err = sendMsg(w, &resp); err != nil {
		log.Printf("httpStart: error sending message: %s", err)
		return
	}
}

func httpGetPorts(w http.ResponseWriter, msg *common.HttpMessage) {
	item := asyncScans.Get(msg.Ticket)
	if item == nil {
		log.Printf("ticket not present: 0x%x", msg.Ticket)
		return
	}

	scanInfo := item.Value()

	var result common.PortsResult
	result.Pack(scanInfo.tcp, scanInfo.udp)

	body, err := common.ToZlib(&result)
	if err != nil {
		log.Printf("failed to encode to zlib: %s", err)
		return
	}

	body, err = json.Marshal(&body)
	if err != nil {
		log.Printf("failed to encode to json: %s", err)
	}

	resp := common.HttpMessage{
		Body: body,
	}

	if err := sendMsg(w, &resp); err != nil {
		log.Printf("httpGetPorts: error sending message: %s", err)
		return
	}
}

func httpDone(w http.ResponseWriter, msg *common.HttpMessage) {
	_, existed := asyncScans.GetAndDelete(msg.Ticket)
	if !existed {
		log.Printf("ticket not present: 0x%x", msg.Ticket)
		return
	}

	resp := common.HttpMessage{
		Code: common.MSG_DONE,
	}

	if err := sendMsg(w, &resp); err != nil {
		log.Printf("httpDone: error sending message: %s", err)
		return
	}

}

func sendMsg(w http.ResponseWriter, msg *common.HttpMessage) error {
	raw, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	_, err = w.Write(raw)
	return err
}
