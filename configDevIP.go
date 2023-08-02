package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/wonderivan/logger"
)

var (
	snapshotLen int32 = 1024
	promiscuous bool  = false
	err         error
	timeout     time.Duration = 30 * time.Second
	handle      *pcap.Handle
)

func DoCommand(format string, a ...interface{}) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	buffer := fmt.Sprintf(format, a...)
	logger.Info(buffer)
	cmd := exec.CommandContext(ctx, "/bin/bash", "-c", buffer)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Warn(buffer, string(output))
	}
	return string(output), err
}

// return sourceIP, NetMask
func arpDetect(dev string) (net.IP, net.IP) {
	handle, err = pcap.OpenLive(dev, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	fmt.Println("before capture")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	fmt.Println("after capture")

	for packet := range packetSource.Packets() {
		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer == nil {
			continue
		}
		arp, ok := arpLayer.(*layers.ARP)
		if !ok {
			fmt.Println("aryLayer Parse Failed")
			continue
		}
		SourceIP := net.IP(arp.SourceProtAddress)
		DstIP := net.IP(arp.DstProtAddress)
		log.Printf("source ip is  %v, dst ip  is  %v", net.IP(arp.SourceProtAddress), net.IP(arp.DstProtAddress))
		if SourceIP.Equal(net.IPv4(0, 0, 0, 0)) || DstIP.Equal(net.IPv4(0, 0, 0, 0)) {
			fmt.Println("Got zero ip")
		}
		fmt.Println("Mask", SourceIP.DefaultMask())
		return SourceIP, net.IP(SourceIP.DefaultMask())
	}
	return net.IPv4(0, 0, 0, 0), net.IPv4(0, 0, 0, 0)
}

// func RunCommandWithTimeout(timeout int, command string, args ...string) (stdout, stderr string, isKilled bool) {
func RunCommandWithTimeout(timeout int, format string, a ...interface{}) (out string, isKilled bool) {
	var outBuf bytes.Buffer
	//cmd := exec.Command(command, args...)

	buffer := fmt.Sprintf(format, a...)
	cmd := exec.Command("/bin/bash", "-c", buffer)

	cmd.Stdout = &outBuf
	cmd.Stderr = &outBuf
	cmd.Start()
	done := make(chan error)
	go func() {
		done <- cmd.Wait()
	}()
	after := time.After(time.Duration(timeout) * time.Millisecond)
	select {
	case <-after:
		fmt.Println("after")
		cmd.Process.Signal(syscall.SIGINT)
		fmt.Println("Signal")
		time.Sleep(10 * time.Millisecond)
		fmt.Println("before kill")
		cmd.Process.Kill()
		fmt.Println("after kill")
		isKilled = true
	case <-done:
		isKilled = false
	}
	return outBuf.String(), isKilled
}

func arpScan(iface string) ([]string, error) {
	var list []string
	out, iskill := RunCommandWithTimeout(20000, "arp-scan -I ens33 -l")
	if iskill {
		return nil, errors.New("cmd timeout")
	}
	sc := bufio.NewScanner(strings.NewReader(out))

	regstr := `\d+\.\d+\.\d+\.\d+`
	reg, _ := regexp.Compile(regstr)
	for sc.Scan() {
		line := sc.Text()

		a := reg.Find([]byte(line))
		if a != nil {
			//	fmt.Println(string(a))
			b := string(a)
			//	fmt.Println(b)
			list = append(list, b)
		}
	}
	return list, nil

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
func mergeArr(a, b, c []string) []string {
	var arr []string
	for _, i := range a {
		arr = append(arr, i)
	}
	for _, j := range b {
		arr = append(arr, j)
	}
	for _, k := range a {
		arr = append(arr, k)
	}
	return arr
}

func getMask(devIP string) net.IPMask {
	ip_addr := net.ParseIP(devIP)
	var mask net.IPMask
	if ip_addr != nil {
		mask = ip_addr.DefaultMask()
		//fmt.Println("mask type:", reflect.TypeOf(mask))
		if mask != nil {
			//fmt.Println("default mask:", mask)
		} else {
			fmt.Println("Get default mask is failed")
		}
	} else {
		fmt.Println("Invalid IP address.")
	}
	return mask
}

// ConvertStrSlice2Map 将字符串 slice 转为 map[string]struct{}。
func ConvertStrSlice2Map(sl []string) map[string]struct{} {
	set := make(map[string]struct{}, len(sl))
	for _, v := range sl {
		set[v] = struct{}{}
	}
	return set
}

// InMap 判断字符串是否在 map 中。
func InMap(m map[string]struct{}, s string) bool {
	_, ok := m[s]
	return ok
}

func configIP1(maskI []string, ipSlice []string, c1 []byte, d1 []byte) (string, error) {
	var ip01 string
	ipMap := ConvertStrSlice2Map(ipSlice)
	IP001 := ipSlice[0]
	b1 := net.ParseIP(IP001).To4()
	ip1 := make(net.IP, net.IPv4len)
	ip1[0] = b1[0]
	ip1[1] = b1[1]
	value11 := maskI[0]
	fmt.Println(value11)
loop1:
	for value11 == "ffffff00" {
		for c1[0] > 0 {
			ip1[2] = b1[2]

			ip1[3] = c1[0]
			ip01 = ip1.String()
			fmt.Println(ip01)
			v := InMap(ipMap, ip01)
			if v == true {
				fmt.Println("continue")
				c1[0]--
			} else {
				fmt.Println("get new ip :", ip01)
				break loop1
			}
		}
	}
loop2:
	for value11 == "ffff0000" {
		for d1[0] > 0 {
			ip1[2] = d1[0]
			ip1[3] = c1[0]
			ip01 = ip1.String()
			bool := InMap(ipMap, ip01)
			if bool == true {
				fmt.Println("continue")
				d1[0]--
			} else {
				fmt.Println("get new ip2:", ip01)
				break loop2
			}
		}
	}
	if len(maskI) == 0 {
		return " ", errors.New("None mask")
	}
	return ip01, nil
}

/*
 */
func main() {
	//ip, mask := arpDetect("ens33")
	//str, err := DoCommand("timeout -k 1s 5s cat /dev/zero")
	list1, _ := arpScan("ens33")
	list2, _ := arpScan("ens33")
	list3, _ := arpScan("ens33")
	var maskList []string
	mergeSlice := mergeArr(list1, list2, list3)
	resultSlice := RemoveRepeatedElement(mergeSlice)
	//fmt.Println(resultSlice)
	for _, value1 := range resultSlice {
		maskValue := getMask(value1)
		maskList = append(maskList, net.IPMask(maskValue).String())
	}
	ipmask := RemoveRepeatedElement(maskList)
	fmt.Println(ipmask)
	var c = []byte{61}
	var d = []byte{254}
	ipAdd, err := configIP1(ipmask, resultSlice, c, d)
	//setIP := RemoveRepeatedElement(ipAdd)
	//ipAddress := minus(setIP, resultSlice)
	if err == nil {
		fmt.Println("new ip is : ", ipAdd)
	} else {
		fmt.Println("run error")
	}
}
