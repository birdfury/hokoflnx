package drv_comm

import (
	"encoding/binary"
	"fmt"
	"local_server/netlink"
	"local_server/remote_server"
	"strings"
)

func handle_clone_info(data []byte) {
	ad, err := netlink.NewAttributeDecoder(data, binary.LittleEndian)
	if err != nil {
		return
	}
	info := remote_server.ProcessForkInfo{
		HostID: "00:0c:29:1c:9a:f2",
	}
	for ad.Next() {
		switch ad.Type() {
		//父进程
		case EDR_ATTR_PPid:
			info.PPid = ad.ByteOrder.Uint64(ad.AttrData())
		case EDR_ATTR_PProcessName:
			info.PProcessName = string(ad.AttrData())
			if strings.Contains(info.PProcessName, "command-not-fou") || strings.Contains(info.PProcessName, "systemd") {
				return
			}
		case EDR_ATTR_PStartTime:
			info.PStartTime = ad.ByteOrder.Uint64(ad.AttrData())
			//当前进程
		case EDR_ATTR_Pid:
			info.Pid = ad.ByteOrder.Uint64(ad.AttrData())
		case EDR_ATTR_ProcessName:
			info.ProcessName = string(ad.AttrData())
			if strings.Contains(info.ProcessName, "command-not-fou") {
				return
			}

		case EDR_ATTR_StartTime:
			info.StartTime = ad.ByteOrder.Uint64(ad.AttrData())
			//子进程
		case EDR_ATTR_CPid:
			info.CPid = ad.ByteOrder.Uint64(ad.AttrData())
			//UID SessionID
		case EDR_ATTR_Uid:
			info.Uid = ad.ByteOrder.Uint32(ad.AttrData())
		case EDR_ATTR_Sid:
			info.SessionID = ad.ByteOrder.Uint32(ad.AttrData())

		default:
			fmt.Println("process clone default")
			//其他的属性都不需要
		}
	}
	fmt.Println(info)
	//remote_server.UploadProcessFork(&info)

}
