package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
)

func main() {

	conn, err := net.Dial("tcp", ":9000")
	if err != nil {
		fmt.Println(err)
	}
	defer conn.Close()

	sharedKey := Handshake(conn)
	secureConnection := SecureConnection{conn: conn, sharedKey: sharedKey}
	recv, send := make(chan string), make(chan string)

	for {
		fmt.Print("> ")
		go func(s chan string) {
			reader := bufio.NewReader(os.Stdin)
			// Read up to the newline character
			msg, _ := reader.ReadBytes(0xA)
			// Kill the newline char
			msg = msg[:len(msg)-1]

			_, err := secureConnection.Write(msg)
			if err != nil {
				fmt.Print("Connection to the server was closed.\n")
			}
			fmt.Println("client send %v byte data", string(msg))
			s <- fmt.Sprintf("client send: %v", string(msg))

		}(send)
		/*
			response := make([]byte, 1024)

			_, err = secureConnection.Read(response)
			if err != nil {
				fmt.Print("Connection to the server was closed.\n")
				break
			}

			fmt.Printf("%s\n", response)
		*/
		go func(r chan string) {
			mesg1 := make([]byte, 1024)
			cnt1, err := secureConnection.Read(mesg1)

			if err != nil {
				fmt.Println(err)
			}
			fmt.Println("read %v data", cnt1)
			fmt.Println("read %v data", string(mesg1))
			r <- fmt.Sprintf("client recv: %v", string(mesg1))
		}(recv)
		select {
		case accept := <-recv:
			log.Println(accept)
		case to := <-send:
			log.Println(to)
		}

	}
}
