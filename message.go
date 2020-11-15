package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"github.com/google/gopacket"
	"log"
	"sync"
	"time"
)

// Handler message handler
type HandlerFunc func(*Message)

type Message struct {
	packets []*Packet
	done    chan bool
	data    []byte
	IPversion  byte
	SrcAddr    string
	DstAddr    string
	Length     int       // length of the data
	Start      time.Time // first packet's timestamp
	End        time.Time // last packet's timestamp
}

type MessagePool struct {
	sync.Mutex
	pool          map[string]*Message
	handler       HandlerFunc
}

// NewMessage ...
func NewMessage(srcAddr, dstAddr string, ipVersion uint8) (m *Message) {
	m = new(Message)
	m.DstAddr = dstAddr
	m.SrcAddr = srcAddr
	m.IPversion = ipVersion
	m.done = make(chan bool)
	return
}

// NewMessagePool returns a new instance of message pool
func NewMessagePool(handler HandlerFunc) (pool *MessagePool) {
	pool = new(MessagePool)
	pool.handler = handler
	pool.pool = make(map[string]*Message)
	return pool
}

func (pool *MessagePool) MessageHandler(packet gopacket.Packet) {
	log.Println("pckt")
	var _, _ bool
	pckt, err := ParsePacket(packet)
	if err != nil {
		log.Fatalln(fmt.Sprintf("error decoding packet(%dBytes):%s\n", packet.Metadata().CaptureLength, err))
		return
	}
	pool.Lock()
	defer pool.Unlock()
	srcKey := pckt.Src()
	dstKey := srcKey + "=" + pckt.Dst()
	m, ok := pool.pool[srcKey]
	if !ok {
		m, ok = pool.pool[dstKey]
	}
	switch {
	case ok:
		pool.addPacket(m, pckt)
		return
	case pckt.SYN:
		_ = !pckt.ACK
	default:
		return
	}
	m = NewMessage(srcKey, pckt.Dst(), pckt.Version)
	key := srcKey
	pool.pool[key] = m
	// 通过done实现了保证dispatch方法在addPacket完成前完成
	go pool.dispatch(key, m)
	pool.addPacket(m, pckt)
}

func (pool *MessagePool) dispatch(key string, m *Message) {
	select {
	case <-m.done:
		defer func() { m.done <- true }()
	}
	delete(pool.pool, key)
	pool.handler(m)
}

func (m *Message) add(pckt *Packet) {
	m.Length += len(pckt.Payload)
	m.packets = append(m.packets, pckt)
	m.data = append(m.data, pckt.Payload...)
	m.End = pckt.Timestamp
}

func (pool *MessagePool) addPacket(m *Message, pckt *Packet) {

	m.add(pckt)
	switch {
	case pckt.FIN:
	case pckt.RST:
		log.Println(fmt.Sprintf("RST flag from %s to %s at %s\n", pckt.Src(), pckt.Dst(), pckt.Timestamp))
	default:
		return
	}
	m.done <- true
	<-m.done
}

// Packets returns packets of this message
func (m *Message) Packets() []*Packet {
	return m.packets
}

// Data returns data in this message
func (m *Message) Data() []byte {
	return m.data
}

// UUID the unique id of a TCP session it is not granted to be unique overtime
func (m *Message) UUID() []byte {
	var src, dst string
	src = m.DstAddr
	dst = m.SrcAddr
	length := len(src) + len(dst)
	uuid := make([]byte, length)
	copy(uuid, src)
	copy(uuid[len(src):], dst)
	sha := sha1.Sum(uuid)
	uuid = make([]byte, 40)
	hex.Encode(uuid, sha[:])

	return uuid
}
