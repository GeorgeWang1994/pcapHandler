package main

import (
	"context"
	"errors"
	"log"
	"net"
	"strconv"
	"sync"
)

type RAWInput struct {
	// 加锁
	sync.Mutex
	// 监听器
	listener       *Listener

	// 消息
	message        chan *Message
	// 取消监听
	cancelListener context.CancelFunc
	quit           chan bool           // Channel used only to indicate goroutine should shutdown
	host           string
	port           uint16
}

func (i *RAWInput) listen(address string) {
	var err error
	i.listener, err = NewListener(i.host, i.port)
	if err != nil {
		log.Fatal(err)
	}
	err = i.listener.Activate()
	if err != nil {
		log.Fatal(err)
	}
	pool := NewMessagePool(i.handler)
	var ctx context.Context
	ctx, i.cancelListener = context.WithCancel(context.Background())
	// 这里是否会阻塞起来，如果阻塞起来的话是否还能创建NewRAWInput对象
	errCh := i.listener.ListenBackground(ctx, pool.MessageHandler)
	select {
	case err := <-errCh:
		log.Fatal(err)
	//case <-i.listener.Reading:
	//	log.Println("222222", i)
	}
}

func (i *RAWInput) handler(m *Message) {
	log.Println(m)
	i.message <- m
}

// Close closes the input raw listener
func (i *RAWInput) Close() error {
	i.cancelListener()
	close(i.quit)
	return nil
}

// NewRAWInput constructor for RAWInput. Accepts raw input config as arguments.
func NewRAWInput(address string) (i *RAWInput) {
	i = new(RAWInput)
	// 用来装message
	i.message = make(chan *Message, 1000)
	i.quit = make(chan bool)
	var host, _port string
	var err error
	var port int
	host, _port, err = net.SplitHostPort(address)
	if err != nil {
		log.Fatalf("input-raw: error while parsing address: %s", err)
	}
	if _port != "" {
		port, err = strconv.Atoi(_port)
	}

	if err != nil {
		log.Fatalf("parsing port error: %v", err)
	}
	i.host = host
	i.port = uint16(port)

	// 监听地址读取数据
	i.listen(address)

	return
}

func (i *RAWInput) Read(data []byte) (n int, err error) {
	var msg *Message
	var buf []byte
	select {
	case <-i.quit:
		return 0, errors.New("reading stopped")
	case msg = <-i.message:
		buf = msg.Data()
		log.Println(buf)
	}
	copy(data, buf)
	return len(buf), nil
}
