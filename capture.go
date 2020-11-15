package main

import (
	"context"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"sync"
)

// NetInterface represents network interface
type NetInterface struct {
	net.Interface
	IPs []string
}

type Handler func(gopacket.Packet)

// Listener handle traffic capture, this is its representation.
type Listener struct {
	sync.Mutex
	Handles    map[string]*pcap.Handle
	Transport  string       // transport layer default to tcp
	BPFFilter     string
	Interfaces []NetInterface
	//Reading    chan bool // this channel is closed when the listener has started reading packets
	Activate   func() error // function is used to activate the engine. it must be called before reading packets

	host          string // pcap file name or interface (name, hardware addr, index or ip address)
	port          uint16 // src or/and dst port
	trackResponse bool

	quit    chan bool
	packets chan gopacket.Packet
}

func cutMask(addr net.Addr) string {
	mask := addr.String()
	for i, v := range mask {
		if v == '/' {
			return mask[:i]
		}
	}
	return mask
}

func (l *Listener) setInterfaces() (err error) {
	var Ifis []NetInterface
	var ifis []net.Interface
	ifis, err = net.Interfaces()
	if err != nil {
		return err
	}

	for i := 0; i < len(ifis); i++ {
		if ifis[i].Flags&net.FlagUp == 0 {
			continue
		}
		var addrs []net.Addr
		addrs, err = ifis[i].Addrs()
		if err != nil {
			return err
		}
		if len(addrs) == 0 {
			continue
		}
		ifi := NetInterface{}
		ifi.Interface = ifis[i]
		ifi.IPs = make([]string, len(addrs))
		for j, addr := range addrs {
			ifi.IPs[j] = cutMask(addr)
		}
		Ifis = append(Ifis, ifi)
	}

	switch l.host {
	case "", "0.0.0.0", "[::]", "::":
		l.Interfaces = Ifis
		return
	}

	found := false
	for _, ifi := range Ifis {
		if l.host == ifi.Name || l.host == fmt.Sprintf("%d", ifi.Index) || l.host == ifi.HardwareAddr.String() {
			found = true
		}
		for _, ip := range ifi.IPs {
			if ip == l.host {
				found = true
				break
			}
		}
		if found {
			l.Interfaces = []NetInterface{ifi}
			return
		}
	}
	err = fmt.Errorf("can not find interface with addr, name or index %s", l.host)
	return err
}

// PcapHandle returns new pcap Handle from dev on success.
// this function should be called after setting all necessary options for this listener
func (l *Listener) PcapHandle(ifi NetInterface) (handle *pcap.Handle, err error) {
	var inactive *pcap.InactiveHandle
	inactive, err = pcap.NewInactiveHandle(ifi.Name)
	if inactive != nil && err != nil {
		defer inactive.CleanUp()
	}
	if err != nil {
		return nil, fmt.Errorf("inactive handle error: %q, interface: %q", err, ifi.Name)
	}
	handle, err = inactive.Activate()
	if err != nil {
		return nil, fmt.Errorf("PCAP Activate device error: %q, interface: %q", err, ifi.Name)
	}
	l.BPFFilter = l.Filter(ifi)
	log.Println(l.BPFFilter)
	err = handle.SetBPFFilter(l.BPFFilter)
	if err != nil {
		log.Println(err)
		handle.Close()
		return nil, fmt.Errorf("BPF filter error: %q%s, interface: %q", err, l.BPFFilter, ifi.Name)
	}
	return
}

func (l *Listener) activatePcap() (err error) {
	var e error
	var msg string
	for _, ifi := range l.Interfaces {
		var handle *pcap.Handle
		handle, e = l.PcapHandle(ifi)
		if e != nil {
			log.Println(e)
			msg += ("\n" + e.Error())
			continue
		}
		l.Handles[ifi.Name] = handle
	}
	if len(l.Handles) == 0 {
		return fmt.Errorf("pcap handles error:%s", msg)
	}
	return
}

func NewListener(host string, port uint16) (l *Listener, err error) {
	l = &Listener{}

	l.host = host
	l.port = port
	l.trackResponse = true
	l.Handles = make(map[string]*pcap.Handle)
	l.Transport = "tcp"
	l.Activate = l.activatePcap
	l.packets = make(chan gopacket.Packet, 1000)
	l.quit = make(chan bool, 1)
	//l.Reading = make(chan bool, 1)
	err = l.setInterfaces()
	if err != nil {
		return nil, err
	}
	return
}

func (l *Listener) closeHandles(key string) {
	log.Println("close")
	l.Lock()
	defer l.Unlock()
	if handle, ok := l.Handles[key]; ok {
		handle.Close()
		delete(l.Handles, key)
		if len(l.Handles) == 0 {
			close(l.packets)
		}
	}
}

func (l *Listener) read() {
	l.Lock()
	defer l.Unlock()
	for key, handle := range l.Handles {
		source := gopacket.NewPacketSource(handle, handle.LinkType())
		source.Lazy = true
		source.NoCopy = true
		// 从gopacket中获取到对应的包
		ch := source.Packets()
		log.Println("read")
		go func(handle *pcap.Handle, key string) {
			defer l.closeHandles(key)
			for {
				select {
				case <-l.quit:
					return
				case p, ok := <-ch:
					if !ok {
						return
					}
					log.Println("333333", p)
					l.packets <- p
				}
			}
		}(handle, key)
	}
	//l.Reading <- true
	//close(l.Reading)
}

func (l *Listener) Listen(ctx context.Context, handler Handler) (err error) {
	if err != nil {
		return err
	}
	l.read()
	done := ctx.Done()
	var p gopacket.Packet
	var ok bool
	for {
		select {
		case <-done:
			l.quit <- true
			close(l.quit)
			err = ctx.Err()
			return
		case p, ok = <-l.packets:
			if !ok {
				return
			}
			if p == nil {
				continue
			}
			log.Printf("packet in listen %v", p)
			handler(p)
		}
	}
}

func (l *Listener) ListenBackground(ctx context.Context, handler Handler) chan error {
	err := make(chan error, 1)
	go func() {
		defer close(err)
		if e := l.Listen(ctx, handler); err != nil {
			err <- e
		}
	}()
	return err
}

func (l *Listener) Filter(ifi NetInterface) (filter string) {
	// https://www.tcpdump.org/manpages/pcap-filter.7.html

	port := fmt.Sprintf("portrange 0-%d", 1<<16-1)
	if l.port != 0 {
		port = fmt.Sprintf("port %d", l.port)
	}
	dir := " dst " // direction
	if l.trackResponse {
		dir = " "
	}
	filter = fmt.Sprintf("(%s%s%s)", l.Transport, dir, port)
	if l.host == "" || isDevice(l.host, ifi) {
		return
	}
	filter = fmt.Sprintf("(%s%s%s and host %s)", l.Transport, dir, port, l.host)
	return
}

func isDevice(addr string, ifi NetInterface) bool {
	return addr == ifi.Name || addr == fmt.Sprintf("%d", ifi.Index) || addr == ifi.HardwareAddr.String()
}
