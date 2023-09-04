package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
)

func main() {

	listener, err := net.Listen("tcp", ":9000")
	if err != nil {
		fmt.Print(err)
		os.Exit(2)
	}

	for {
		conn, err := listener.Accept()

		if err != nil {
			fmt.Print(err)
		}

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	sharedKey := Handshake(conn)
	secureConnection := SecureConnection{conn: conn, sharedKey: sharedKey}
	recv, send := make(chan string), make(chan string)
	readers := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("> ")
		go func(s chan string) {
			// Read up to the newline character
			msginfo, _ := readers.ReadBytes(0xA)
			// Kill the newline char
			msginfo = msginfo[:len(msginfo)-1]

			_, err := secureConnection.Write(msginfo)
			if err != nil {
				fmt.Print("Connection to the server was closed.\n")
			}
			s <- fmt.Sprintf("server send : %v", string(msginfo))
		}(send)
		go func(r chan string) {
			mesg := make([]byte, 1024)
			cnt, err := secureConnection.Read(mesg)

			if err != nil {
				fmt.Println(err)
			}
			fmt.Println("read %v data", cnt)
			fmt.Println("read %v data", string(mesg))
			r <- fmt.Sprintf("server recive:%v", string(mesg))
			/*
				num, err := secureConnection.Write(mesg)
				if err != nil {
					fmt.Println(err)
				}
				fmt.Println("write %v data", num)
			*/
		}(recv)
		select {
		case accept := <-recv:
			log.Println(accept)
		case to := <-send:
			log.Println(to)
		}
	}
}
