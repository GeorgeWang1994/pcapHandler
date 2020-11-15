package main

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
	"time"
)

type Packet struct {
	// Link layer
	gopacket.LinkLayer

	// IP Header
	gopacket.NetworkLayer
	Version uint8 // Ip version

	// TCP Segment Header
	*layers.TCP

	// Data info
	Lost      uint16
	Timestamp time.Time
}

// Length returns the total length of the packet(IP header, TCP header and the actual data)
func (pckt *Packet) Length() uint16 {
	if l, ok := pckt.NetworkLayer.(*layers.IPv4); ok {
		return l.Length
	}
	return pckt.NetworkLayer.(*layers.IPv6).Length
}

// IHL returns IP header length in bytes
func (pckt *Packet) IHL() uint8 {
	if l, ok := pckt.NetworkLayer.(*layers.IPv4); ok {
		return l.IHL * 4
	}
	// on IPV6 it's constant, https://en.wikipedia.org/wiki/IPv6_packet#Fixed_header
	return 40
}

// ParsePacket parse raw packets
func ParsePacket(packet gopacket.Packet) (pckt *Packet, err error) {
	// early check of error
	_ = packet.ApplicationLayer()
	if e, ok := packet.ErrorLayer().(*gopacket.DecodeFailure); ok {
		err = e.Error()
		return
	}

	// initialization
	pckt = new(Packet)
	pckt.Timestamp = packet.Metadata().Timestamp
	if pckt.Timestamp.IsZero() {
		pckt.Timestamp = time.Now()
	}

	// parsing link layer
	pckt.LinkLayer = packet.LinkLayer()

	// parsing network layer
	if net4, ok := packet.NetworkLayer().(*layers.IPv4); ok {
		pckt.NetworkLayer = net4
		pckt.Version = 4
	} else if net6, ok := packet.NetworkLayer().(*layers.IPv6); ok {
		pckt.NetworkLayer = net6
		pckt.Version = 6
	} else {
		pckt = nil
		return
	}

	// parsing tcp header(transportation layer)
	if tcp, ok := packet.TransportLayer().(*layers.TCP); ok {
		pckt.TCP = tcp
	} else {
		pckt = nil
		err = errors.New("tcp error")
		return
	}
	pckt.DataOffset *= 4

	// calculating lost data
	headerSize := int(uint32(pckt.DataOffset) + uint32(pckt.IHL()))
	if pckt.Version == 6 {
		headerSize -= 40 // in ipv6 the length of payload doesn't include the IPheader size
	}
	pckt.Lost = pckt.Length() - uint16(headerSize+len(pckt.Payload))

	return
}


// Src returns the source socket of a packet
func (pckt *Packet) Src() string {
	return fmt.Sprintf("%s:%d", pckt.SrcIP(), pckt.SrcPort)
}

// Dst returns destination socket
func (pckt *Packet) Dst() string {
	return fmt.Sprintf("%s:%d", pckt.DstIP(), pckt.DstPort)
}

// SrcIP returns source IP address
func (pckt *Packet) SrcIP() net.IP {
	if pckt.Version == 4 {
		return pckt.NetworkLayer.(*layers.IPv4).SrcIP
	}
	return pckt.NetworkLayer.(*layers.IPv6).SrcIP
}

// DstIP returns destination IP address
func (pckt *Packet) DstIP() net.IP {
	if pckt.Version == 4 {
		return pckt.NetworkLayer.(*layers.IPv4).DstIP
	}
	return pckt.NetworkLayer.(*layers.IPv6).DstIP
}

