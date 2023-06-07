package remote_server

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var RemoteConn *grpc.ClientConn
var RemoteClient RemoteServerClient

var streamProcessFork RemoteServer_UploadProcessForkClient
var streamProcessFork_ok bool

var streamProcessExecve RemoteServer_UploadProcessExecveClient
var streamProcessExecve_ok bool

var streamFileRead RemoteServer_UploadFileReadClient
var streamFileRead_ok bool

var streamFileWrite RemoteServer_UploadFileReadClient
var streamFileWrite_ok bool

var streamSocketConnect RemoteServer_UploadSocketConnectClient
var streamSocketConnect_ok bool

var streamSocketSend RemoteServer_UploadSocketSendClient
var streamSocketSend_ok bool

func RemoteServerConnect(addr string) error {
	RemoteConn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Printf("连接服务端失败: %s", err)
		return err
	}
	RemoteClient = NewRemoteServerClient(RemoteConn)

	streamProcessFork, err = RemoteClient.UploadProcessFork(context.Background())
	if err != nil {
		streamProcessFork_ok = false
		return err
	}
	streamProcessFork_ok = true

	streamProcessExecve, err = RemoteClient.UploadProcessExecve(context.Background())
	if err != nil {
		streamProcessExecve_ok = false
		return err
	}
	streamProcessExecve_ok = true

	streamFileRead, err = RemoteClient.UploadFileRead(context.Background())
	if err != nil {
		streamFileRead_ok = false
		return err
	}
	streamFileRead_ok = true

	streamSocketConnect, err = RemoteClient.UploadSocketConnect(context.Background())
	if err != nil {
		streamSocketConnect_ok = false
		return err
	}
	streamSocketConnect_ok = true

	streamSocketSend, err = RemoteClient.UploadSocketSend(context.Background())
	if err != nil {
		streamSocketSend_ok = false
		return err
	}
	streamSocketSend_ok = true

	return nil
}

func RemoteServerDisconnect() {
	streamProcessExecve.CloseAndRecv()
	streamProcessFork.CloseAndRecv()

	streamFileRead.CloseAndRecv()
	streamFileWrite.CloseAndRecv()

	streamSocketConnect.CloseAndRecv()
	streamSocketSend.CloseAndRecv()

	RemoteConn.Close()
}

//文件读取信息上传
//这里非阻塞，不判断返回值
//如果发送失败，将重新建立一次流连接,同样不管建立成功与否
func UploadFileRead(info *FileRwInfo) {
	var err error
	if !streamFileRead_ok {
		streamFileRead, err = RemoteClient.UploadFileRead(context.Background())
		if err != nil {
			fmt.Println("steam ReCreate faield")
			return
		}
	}
	streamFileRead_ok = true
	err = streamFileRead.Send(info)
	if err != nil {
		streamFileRead_ok = false
	}
}

//文件写入信息上传
//这里非阻塞，不判断返回值
//如果发送失败，将重新建立一次流连接,同样不管建立成功与否
func UploadFileWrite(info *FileRwInfo) {
	var err error
	if !streamFileWrite_ok {
		streamFileWrite, err = RemoteClient.UploadFileWrite(context.Background())
		if err != nil {
			fmt.Println("steam ReCreate faield")
			return
		}
	}
	streamFileWrite_ok = true
	err = streamFileWrite.Send(info)
	if err != nil {
		streamFileWrite_ok = false
	}
}

//Fork信息上传
//这里非阻塞，不判断返回值
//如果发送失败，将重新建立一次流连接,同样不管建立成功与否
func UploadProcessFork(info *ProcessForkInfo) {
	var err error
	if !streamProcessFork_ok {
		streamProcessFork, err = RemoteClient.UploadProcessFork(context.Background())
		if err != nil {
			return
		}
	}
	streamProcessFork_ok = true
	err = streamProcessFork.Send(info)
	if err != nil {
		streamProcessFork_ok = false
	}
}

//Execve信息上传
//这里非阻塞，不判断返回值
//如果发送失败，将重新建立一次流连接,同样不管建立成功与否
func UploadProcessExecve(info *ProcessExecveInfo) {
	var err error
	if !streamProcessExecve_ok {
		streamProcessExecve, err = RemoteClient.UploadProcessExecve(context.Background())
		if err != nil {
			return
		}
	}
	streamProcessExecve_ok = true
	err = streamProcessExecve.Send(info)
	if err != nil {
		streamProcessExecve_ok = false
	}
}

//Connect信息上传
//这里非阻塞，不判断返回值
//如果发送失败，将重新建立一次流连接,同样不管建立成功与否
func UploadSocketConnect(info *SocketConnInfo) {
	var err error
	if !streamSocketConnect_ok {
		streamSocketConnect, err = RemoteClient.UploadSocketConnect(context.Background())
		if err != nil {
			return
		}
	}
	streamSocketConnect_ok = true
	err = streamSocketConnect.Send(info)
	if err != nil {
		streamSocketConnect_ok = false

	}
}

//Send信息上传
//这里非阻塞，不判断返回值
//如果发送失败，将重新建立一次流连接,同样不管建立成功与否
func UploadSocketSend(info *SocketSendInfo) {
	var err error
	if !streamSocketSend_ok {
		streamSocketSend, err = RemoteClient.UploadSocketSend(context.Background())
		if err != nil {
			return
		}
	}
	streamSocketSend_ok = true
	err = streamSocketSend.Send(info)
	if err != nil {
		streamSocketSend_ok = false

	}
}
