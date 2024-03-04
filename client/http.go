package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/netip"

	"github.com/monoidic/porttest/common"
)

type httpServerConn struct {
	url    string
	srcIP  netip.Addr
	ports  *common.PortsResult
	client *http.Client
	ticket uint64
}

var _ serverConn = (*httpServerConn)(nil)

func getHttpConn(urlS string, insecure bool, srcIP netip.Addr, ports *common.PortsResult) *httpServerConn {
	var client http.Client

	if insecure {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
	}

	return &httpServerConn{
		url:    urlS,
		client: &client,
		srcIP:  srcIP,
		ports:  ports,
		ticket: rand.Uint64(),
	}
}

func (sc *httpServerConn) setup() {
	msg := common.HttpMessage{
		Code: common.MSG_ASYNC_START,
		Body: &common.HttpInitMsg{
			Version: common.VERSION,
			Ip:      sc.srcIP.String(),
			Ports:   common.Check1(common.ToZlib(sc.ports)),
		},
	}
	resp := sc.exchange(&msg)
	if resp.Code != common.MSG_INIT_DONE {
		log.Panicf("unexpected code %d", resp.Code)
	}
}

func (sc *httpServerConn) exchange(msg *common.HttpMessage) *common.HttpMessage {
	msg.Ticket = sc.ticket
	encoded := common.Check1(json.Marshal(msg))
	buf := bytes.NewBuffer(encoded)
	var err error
	for range numRetries {
		var resp *http.Response
		resp, err = sc.client.Post(sc.url, "application/json; charset=UTF-8", buf)
		if err == nil {
			var ret common.HttpMessage
			body := common.Check1(io.ReadAll(resp.Body))
			common.Check(json.Unmarshal(body, &ret))
			return &ret
		}
	}

	log.Panicf("error on exchange: %s", err)
	panic("unreachable")
}

func (sc *httpServerConn) getPorts() {
	msg := common.HttpMessage{
		Code: common.MSG_GETPORTS,
	}
	resp := sc.exchange(&msg)

	b64ed := resp.Body.(string)
	compressed := common.Check1(base64.StdEncoding.AppendDecode(nil, []byte(b64ed)))
	decoded := common.Check1(common.FromZlib(compressed))
	common.Check(binary.Read(bytes.NewBuffer(decoded), binary.BigEndian, sc.ports))
}

func (sc *httpServerConn) more() {
	// no-op
}

func (sc *httpServerConn) close() {
	sc.client.CloseIdleConnections()
}

func (sc *httpServerConn) done() {
	msg := common.HttpMessage{
		Code: common.MSG_DONE,
	}

	resp := sc.exchange(&msg)
	if resp.Code != common.MSG_DONE {
		log.Panicf("unexpected code: %d", resp.Code)
	}
}
