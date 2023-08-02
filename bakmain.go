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

//设置ip

func configIP(maskL []net.IPMask, ipSlice []string, c []byte, d []byte) ([]string, error) {
	var ip1 []string
	for _, value := range maskL {
		value11 := net.IPMask(value).String()
		if value11 == "ffffff00" {
			for index, _ := range ipSlice {
				eachItem1 := net.ParseIP(ipSlice[index]).To4()
				if c[0] == eachItem1[3] {
					fmt.Println("ip0000:", eachItem1[3])
					c[0] = c[0] - 1
					continue
				} else if c[0] != eachItem1[3] {
					fmt.Println("botbot: ", c[0])
				}
			}
			IP001 := ipSlice[0]
			b := net.ParseIP(IP001).To4()
			ip := make(net.IP, net.IPv4len)
			ip[0] = b[0]
			ip[1] = b[1]
			ip[2] = b[2]
			ip[3] = c[0]
			ip01 := ip.String()
			ip1 = append(ip1, ip01)
			fmt.Println("get ipaddr:", ip1)
		} else if value11 == "ffff0000" {
			IP002 := ipSlice[0]
			b := net.ParseIP(IP002).To4()
			ip := make(net.IP, net.IPv4len)
			ip[0] = b[0]
			ip[1] = b[1]
			for index, _ := range ipSlice {
				eachItem1 := net.ParseIP(ipSlice[index]).To4()
				if eachItem1[2] == d[0] {
					//		fmt.Println("ip00003:", eachItem1[2])
					d[0]--
				}
				if eachItem1[3] == c[0] {
					//	fmt.Println("ip00004:", eachItem1[3])
					c[0]--
				}
			}
			ip[2] = d[0]
			ip[3] = c[0]
			ip1 = append(ip1, ip.String())
			//fmt.Println("get ipaddr2:", ip1)
		} else {
			return nil, errors.New("None mask")
		}
	}
	return ip1, nil
}

// 去除a切片中 b切片的元素
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

func main() {
	//ip, mask := arpDetect("ens33")
	//str, err := DoCommand("timeout -k 1s 5s cat /dev/zero")
	list1, _ := arpScan("ens33")
	list2, _ := arpScan("ens33")
	list3, _ := arpScan("ens33")
	var maskList []net.IPMask
	mergeSlice := mergeArr(list1, list2, list3)
	resultSlice := RemoveRepeatedElement(mergeSlice)
	//fmt.Println(resultSlice)
	for _, value1 := range resultSlice {
		maskValue := getMask(value1)
		maskList = append(maskList, maskValue)
	}
	var c = []byte{61}
	var d = []byte{254}
	ipAdd, err := configIP(maskList, resultSlice, c, d)
	setIP := RemoveRepeatedElement(ipAdd)
	ipAddress := minus(setIP, resultSlice)
	if err == nil {
		fmt.Println("new ip is : ", ipAddress)
	} else {
		fmt.Println("run error")
	}
}
