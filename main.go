package main

import "log"

func main() {
	input := NewRAWInput(":1234")
	buf := make([]byte, 10000)
	for {
		nr, err := input.Read(buf)
		if err != nil {
			log.Println("not data")
			continue
		}
		payload := buf[:nr]
		log.Println("111111", payload)
	}
}
