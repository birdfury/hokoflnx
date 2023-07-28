package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"math/rand"
	"net"
	"os"
	"reflect"
	"time"
)

var (
	snapshotLen int32 = 1024
	promiscuous bool  = false
	err         error
	timeout     time.Duration = 30 * time.Second
	handle      *pcap.Handle
)

func main() {
	// Open device
	//defer handle.Close()

	printPacketInfo(os.Args[1])

}

func printPacketInfo(device string) {
	// 判断数据包是否为IP数据包，可解析出源ip、目的ip、协议号等
	var SrcIpList []net.IP
	var DstIpList []net.IP
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	fmt.Println("before capture")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	fmt.Println("after capture")
loop:
	for packet := range packetSource.Packets() {
		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer == nil {
			continue
		}
		arp := arpLayer.(*layers.ARP)
		log.Printf("IP %v is at %v", net.IP(arp.SourceProtAddress), net.HardwareAddr(arp.SourceHwAddress))
		// Check for errors
		// 判断layer是否存在错误
		if err := packet.ErrorLayer(); err != nil {
			fmt.Println("Error decoding some part of the packet:", err)
		}
		SrcIP := arp.SourceProtAddress
		DstIP := arp.DstProtAddress
		/*
		   判断SrcIP和DstIP同时有效，即退出循环
		*/

		SrcIpList = append(SrcIpList, SrcIP)
		DstIpList = append(DstIpList, DstIP)

		var newIPArr []string
		var newsrcIPArray []string
		for index, IpSr := range SrcIpList {
			fmt.Println("srcIP:", index, IpSr[0], "-", IpSr[1], "-", IpSr[2], "-", IpSr[3])
			s := net.IP(IpSr).String()
			newIPArr = append(newIPArr, s) //newIPArr "192.168.1.16"
			getMask(s)
		}

		newsrcIPArray = RemoveRepeatedElement(newIPArr)

		var newdstArr []string
		var newdstArray []string
		for index1, IpDr := range DstIpList {
			fmt.Println("dstIP:", index1, IpDr)
			dstp := net.IP(IpDr).String()
			newdstArr = append(newdstArr, dstp)
			getMask(dstp)
		}

		newdstArray = RemoveRepeatedElement(newdstArr)

		for index2, srcip := range newsrcIPArray {
			println("不重复的srcip:", index2, srcip)
		}

		for index3, dstip := range newdstArray {
			println("不重复的dstip:", index3, dstip)
		}

		randIP1 := getRandomIP(newsrcIPArray)
		getRandIP1 := RemoveRepeatedElement(randIP1)
		fmt.Println("get  random ip1", getRandIP1)
		randIP2 := getRandomIP(newdstArray)
		getRandIP2 := RemoveRepeatedElement(randIP2)
		fmt.Println(" get random ip2", getRandIP2)
		if len(getRandIP1) != 0 || len(getRandIP2) != 0 {
			break loop
		}

	}
	return
}

func getMask(devIP string) {
	ip_addr := net.ParseIP(devIP)
	if ip_addr != nil {
		mask := ip_addr.DefaultMask()
		fmt.Println("mask type:", reflect.TypeOf(mask))
		if mask != nil {
			fmt.Println("default mask:", mask)
		} else {
			fmt.Println("Get default mask is failed")
		}
	} else {
		fmt.Println("Invalid IP address.")
	}
}

func RemoveRepeatedElement(arr []string) (newArr []string) {
	newArr = make([]string, 0)
	for i := 0; i < len(arr); i++ {
		repeat := false
		for j := i + 1; j < len(arr); j++ {
			if arr[i] == arr[j] {
				repeat = true
				break
			}
		}
		if !repeat {
			newArr = append(newArr, arr[i])
		}
	}
	return newArr

}

func getaddr1(ip1 uint8, ip2 uint8) string {
	rand.Seed(time.Now().Unix())
	ip := fmt.Sprintf("%d.%d.%d.%d", ip1, ip2, rand.Intn(255), rand.Intn(255))
	return ip
}
func getaddr2(ip1 uint8, ip2 uint8, ip3 uint8) string {
	rand.Seed(time.Now().Unix())
	ip := fmt.Sprintf("%d.%d.%d.%d", ip1, ip2, ip3, rand.Intn(255))
	return ip
}

func getRandomIP(ipList []string) (ipArr []string) {

	var netmask []string
	var iprandom []string
	for i := 0; i < len(ipList)-1; i++ {
		iparr1 := net.ParseIP(ipList[i]).To4()
		fmt.Println(iparr1)
		fmt.Println("iparr1 type:", reflect.TypeOf(iparr1))

		iparr2 := net.ParseIP(ipList[i+1]).To4()
		fmt.Println("iparr2 type:", reflect.TypeOf(iparr2))

		fmt.Println(iparr2)
		if iparr1[0] == iparr2[0] && iparr1[1] == iparr2[1] && iparr1[2] != iparr2[2] {
			netmask1 := "ffff0000"
			fmt.Println(netmask1)
			netmask = append(netmask, netmask1)
			getip1 := getaddr1(iparr1[0], iparr1[1])
			if getip1 != ipList[i] && getip1 != ipList[i+1] {
				fmt.Println("getiprandom1")
				iprandom = append(iprandom, getip1)
				fmt.Println("random ip1:", iprandom)
			}

		}
		if iparr1[0] == iparr2[0] && iparr1[1] == iparr2[1] && iparr1[2] == iparr2[2] {
			netmask2 := "ffffff00"
			fmt.Println(netmask2)
			netmask = append(netmask, netmask2)
			getip2 := getaddr2(iparr1[0], iparr1[1], iparr1[2])
			if getip2 != ipList[i] && getip2 != ipList[i+1] {
				fmt.Println("getiprandom2")
				iprandom = append(iprandom, getip2)
				fmt.Println("random ip2:", iprandom)
			}
		}
	}
	getRandomIP := minus(iprandom, ipList)
	fmt.Println("final random ip:", getRandomIP)
	return getRandomIP
}

func minus(a []string, b []string) []string {
	var inter []string
	mp := make(map[string]bool)
	for _, s := range a {
		if _, ok := mp[s]; !ok {
			mp[s] = true
		}
	}
	for _, s := range b {
		if _, ok := mp[s]; ok {
			delete(mp, s)
		}
	}
	for key := range mp {
		inter = append(inter, key)
	}
	return inter
}
