package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/netip"

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
		log.Printf("got http %s with ticket 0x%x\n", msgS, msg.Ticket)
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
	rawMap := msg.Body.(map[string]any)
	initMsg := common.HttpInitMsg{
		Version: uint8(rawMap["Version"].(float64)),
		Ip:      rawMap["Ip"].(string),
	}
	portsB64 := rawMap["Ports"].(string)
	portsB, err := base64.StdEncoding.AppendDecode(nil, []byte(portsB64))
	if err != nil {
		log.Printf("unable to decode base64: %s", err)
		return
	}
	initMsg.Ports = portsB

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

	_, exists := asyncScans[msg.Ticket]
	if exists {
		log.Printf("ticket already present: 0x%x", msg.Ticket)
		return
	}

	if len(asyncScans) > scanLimit {
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

	asyncScans[msg.Ticket] = asyncScanInfo{
		handle:   handle,
		tcp:      &tcp,
		udp:      &udp,
		workerWG: wg,
	}

	resp := common.HttpMessage{
		Code: common.MSG_INIT_DONE,
	}

	if err = sendMsg(w, &resp); err != nil {
		log.Printf("error sending message: %s", err)
		return
	}
}

func httpGetPorts(w http.ResponseWriter, msg *common.HttpMessage) {
	scanInfo, exists := asyncScans[msg.Ticket]
	if !exists {
		log.Printf("ticket not present: 0x%x", msg.Ticket)
		return
	}

	var result common.PortsResult
	result.Pack(scanInfo.tcp, scanInfo.udp)

	body, err := common.ToZlib(&result)
	if err != nil {
		log.Printf("failed to encode to zlib: %s", err)
		return
	}

	resp := common.HttpMessage{
		Body: body,
	}

	if err := sendMsg(w, &resp); err != nil {
		log.Printf("error sending message: %s", err)
		return
	}
}

func httpDone(w http.ResponseWriter, msg *common.HttpMessage) {
	scanInfo, exists := asyncScans[msg.Ticket]
	if !exists {
		log.Printf("ticket not present: 0x%x", msg.Ticket)
		return
	}

	scanInfo.handle.Close()
	scanInfo.workerWG.Wait()
	delete(asyncScans, msg.Ticket)

	resp := common.HttpMessage{
		Code: common.MSG_DONE,
	}

	if err := sendMsg(w, &resp); err != nil {
		log.Printf("error sending message: %s", err)
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
