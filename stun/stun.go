// This file implements RFC5780's tests:
// - 4.3.  Determining NAT Mapping Behavior
// - 4.4.  Determining NAT Filtering Behavior
package stun

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"time"

	"github.com/pion/stun"
	log "github.com/sirupsen/logrus"
)

type stunServerConn struct {
	conn        net.PacketConn
	LocalAddr   net.Addr
	RemoteAddr  *net.UDPAddr
	OtherAddr   *net.UDPAddr
	messageChan chan *stun.Message
}

func (c *stunServerConn) Close() error {
	return c.conn.Close()
}

type NATMappingBehavior int
type NATFilteringBehavior int

const (
	NoNAT NATMappingBehavior = iota
	EndpointIndependentMapping
	AddressDependentMapping
	AddressAndPortDependentMapping
	UnknownMapping
)

const (
	EndpointIndependentFiltering NATFilteringBehavior = iota + 10
	AddressDependentFiltering
	AddressAndPortDependentFiltering
	UnknownFiltering
)

var (
	timeoutPtr = flag.Int("timeout", 3, "time to wait for STUN server's response (in seconds)")
)

// RFC5780: 4.3.  Determining NAT Mapping Behavior
func MappingTests(addrStr string) (NATMappingBehavior, error) {
	mapTestConn, err := connect(addrStr)
	if err != nil {
		log.Warnf("Error creating STUN connection: %s", err)
		return UnknownMapping, err
	}
	defer mapTestConn.Close()

	// Test I: Regular binding request
	log.Debug("Mapping Test I: Regular binding request")
	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	resp, err := mapTestConn.roundTrip(request, mapTestConn.RemoteAddr)
	if err != nil {
		return UnknownMapping, err
	}

	// Parse response message for XOR-MAPPED-ADDRESS and make sure OTHER-ADDRESS valid
	resps1 := parse(resp)
	if resps1.xorAddr == nil || resps1.otherAddr == nil {
		log.Debug("Error: NAT discovery feature not supported by this server")
		return UnknownMapping, fmt.Errorf("no OTHER-ADDRESS in message, NAT discovery feature not supported by %s", addrStr)
	}

	addr, err := net.ResolveUDPAddr("udp4", resps1.otherAddr.String())
	if err != nil {
		log.Debugf("Failed resolving OTHER-ADDRESS: %v", resps1.otherAddr)
		return UnknownMapping, err
	}
	mapTestConn.OtherAddr = addr
	log.Debugf("Received XOR-MAPPED-ADDRESS: %v", resps1.xorAddr)

	// Assert mapping behavior
	if resps1.xorAddr.String() == mapTestConn.LocalAddr.String() {
		return NoNAT, nil
	}

	// Test II: Send binding request to the other address but primary port
	log.Debug("Mapping Test II: Send binding request to the other address but primary port")
	oaddr := *mapTestConn.OtherAddr
	oaddr.Port = mapTestConn.RemoteAddr.Port
	resp, err = mapTestConn.roundTrip(request, &oaddr)
	if err != nil {
		return UnknownMapping, err
	}

	// Assert mapping behavior
	resps2 := parse(resp)
	log.Debugf("Received XOR-MAPPED-ADDRESS: %v", resps2.xorAddr)
	if resps2.xorAddr.String() == resps1.xorAddr.String() {
		return EndpointIndependentMapping, nil
	}

	// Test III: Send binding request to the other address and port
	log.Debug("Mapping Test III: Send binding request to the other address and port")
	resp, err = mapTestConn.roundTrip(request, mapTestConn.OtherAddr)
	if err != nil {
		return UnknownMapping, err
	}

	// Assert mapping behavior
	resps3 := parse(resp)
	log.Debugf("Received XOR-MAPPED-ADDRESS: %v", resps3.xorAddr)
	if resps3.xorAddr.String() == resps2.xorAddr.String() {
		return AddressDependentMapping, nil
	} else {
		return AddressAndPortDependentMapping, nil
	}
}

// RFC5780: 4.4.  Determining NAT Filtering Behavior
func FilteringTests(addrStr string) (NATFilteringBehavior, error) {
	mapTestConn, err := connect(addrStr)
	if err != nil {
		log.Warnf("Error creating STUN connection: %s", err)
		return UnknownFiltering, err
	}
	defer mapTestConn.Close()

	// Test I: Regular binding request
	log.Debug("Filtering Test I: Regular binding request")
	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	resp, err := mapTestConn.roundTrip(request, mapTestConn.RemoteAddr)
	if err != nil {
		return UnknownFiltering, err
	}
	resps := parse(resp)
	if resps.xorAddr == nil || resps.otherAddr == nil {
		log.Debug("Error: NAT discovery feature not supported by this server")
		return UnknownFiltering, fmt.Errorf("no OTHER-ADDRESS in message, NAT discovery feature not supported by %s", addrStr)
	}

	addr, err := net.ResolveUDPAddr("udp4", resps.otherAddr.String())
	if err != nil {
		log.Debugf("Failed resolving OTHER-ADDRESS: %v", resps.otherAddr)
		return UnknownFiltering, err
	}
	mapTestConn.OtherAddr = addr

	// Test II: Request to change both IP and port
	log.Debug("Filtering Test II: Request to change both IP and port")
	request = stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	request.Add(stun.AttrChangeRequest, []byte{0x00, 0x00, 0x00, 0x06})

	resp, err = mapTestConn.roundTrip(request, mapTestConn.RemoteAddr)
	if err == nil {
		parse(resp) // just to print out the resp
		return EndpointIndependentFiltering, nil
	} else if err.Error() != "timed out waiting for response" {
		return UnknownFiltering, err
	}

	// Test III: Request to change port only
	log.Debug("Filtering Test III: Request to change port only")
	request = stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	request.Add(stun.AttrChangeRequest, []byte{0x00, 0x00, 0x00, 0x02})

	resp, err = mapTestConn.roundTrip(request, mapTestConn.RemoteAddr)
	if err == nil {
		parse(resp) // just to print out the resp
		return AddressDependentFiltering, nil
	} else if err.Error() == "timed out waiting for response" {
		return AddressAndPortDependentFiltering, nil
	} else {
		return UnknownFiltering, err
	}
}

// Parse a STUN message
func parse(msg *stun.Message) (ret struct {
	xorAddr    *stun.XORMappedAddress
	otherAddr  *stun.OtherAddress
	respOrigin *stun.ResponseOrigin
	mappedAddr *stun.MappedAddress
	software   *stun.Software
},
) {
	ret.mappedAddr = &stun.MappedAddress{}
	ret.xorAddr = &stun.XORMappedAddress{}
	ret.respOrigin = &stun.ResponseOrigin{}
	ret.otherAddr = &stun.OtherAddress{}
	ret.software = &stun.Software{}
	if ret.xorAddr.GetFrom(msg) != nil {
		ret.xorAddr = nil
	}
	if ret.otherAddr.GetFrom(msg) != nil {
		ret.otherAddr = nil
	}
	if ret.respOrigin.GetFrom(msg) != nil {
		ret.respOrigin = nil
	}
	if ret.mappedAddr.GetFrom(msg) != nil {
		ret.mappedAddr = nil
	}
	if ret.software.GetFrom(msg) != nil {
		ret.software = nil
	}
	log.Tracef("%v", msg)
	log.Tracef("\tMAPPED-ADDRESS:     %v", ret.mappedAddr)
	log.Tracef("\tXOR-MAPPED-ADDRESS: %v", ret.xorAddr)
	log.Tracef("\tRESPONSE-ORIGIN:    %v", ret.respOrigin)
	log.Tracef("\tOTHER-ADDRESS:      %v", ret.otherAddr)
	log.Tracef("\tSOFTWARE: %v", ret.software)

	for _, attr := range msg.Attributes {
		switch attr.Type {
		case
			stun.AttrXORMappedAddress,
			stun.AttrOtherAddress,
			stun.AttrResponseOrigin,
			stun.AttrMappedAddress,
			stun.AttrSoftware:
			// already printed, do nothing
		default:
			log.Tracef("\t%v (l=%v)", attr, attr.Length)
		}
	}

	return ret
}

// Given an address string, returns a StunServerConn
func connect(addrStr string) (*stunServerConn, error) {
	log.Debugf("Connecting to STUN server: %s", addrStr)
	addr, err := net.ResolveUDPAddr("udp4", addrStr)
	if err != nil {
		log.Warnf("Error resolving address: %s", err)
		return nil, err
	}

	// Just to get real local address
	c, _ := net.DialUDP("udp4", nil, addr)
	localAddr := c.LocalAddr()

	// Create a new connection
	c, err = net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, err
	}
	log.Debugf("Local address: %s", localAddr)
	log.Debugf("Remote address: %s", addr.String())

	// Start reading messages
	messages := make(chan *stun.Message)
	go func() {
		for {
			buf := make([]byte, 1024)

			n, addr, err := c.ReadFromUDP(buf)
			if err != nil {
				log.Tracef("Error reading from UDP, messsage channel closing: %v", err)
				close(messages)
				return
			}
			log.Debugf("Response from %v: (%v bytes)", addr, n)
			buf = buf[:n]

			m := new(stun.Message)
			m.Raw = buf
			err = m.Decode()
			if err != nil {
				log.Warnf("Error decoding message: %v", err)
				close(messages)
				return
			}

			messages <- m
		}
	}()

	return &stunServerConn{
		conn:        c,
		LocalAddr:   localAddr,
		RemoteAddr:  addr,
		messageChan: messages,
	}, nil
}

// Send request and wait for response or timeout
func (c *stunServerConn) roundTrip(msg *stun.Message, addr net.Addr) (*stun.Message, error) {
	_ = msg.NewTransactionID()
	log.Debugf("Sending to %v: (%v bytes)", addr, msg.Length+20) // 20 is Message header size

	log.Tracef("%v", msg)
	for _, attr := range msg.Attributes {
		log.Tracef("\t%v (l=%v)", attr, attr.Length)
	}

	_, err := c.conn.WriteTo(msg.Raw, addr)
	if err != nil {
		log.Warnf("Error sending request to %v: %s", addr, err.Error())
		return nil, err
	}

	// Wait for response or timeout
	select {
	case m, ok := <-c.messageChan:
		if !ok {
			return nil, errors.New("error reading from response message channel")
		}
		return m, nil
	case <-time.After(time.Duration(*timeoutPtr) * time.Second):
		log.Debugf("Timed out waiting for response from server %v", addr)
		return nil, errors.New("timed out waiting for response")
	}
}
