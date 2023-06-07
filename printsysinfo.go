/*
package main
import  (
	"fmt"
	"os"
	"os/exec"
)
func main() {
	Command("ifconfig")
	Command("grep -o "inet *" | awk -F "inet" '{print$2}'|head -n 1")
	Command("ps aux| awk {print$1}")
}


func Command(cmd string)error{
	c := exec.CommandContext(cmd"bash","-c",cmd)
	output,err := c.CombinedOutput()
	f, _ := os.OpenFile("/home/walk/info.log", os.O_WRONLY|os.O_CREATE|os.O_SYNC|os.O_APPEND,0766)
    os.Stdout=f

	fmt.Println(string(output))
	return err
}
*/

package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	go func(cancelFunc context.CancelFunc) {
		time.Sleep(3 * time.Second)
		cancelFunc()
	}(cancel)
	Command(ctx, "ping www.baidu.com")
}

func Command(ctx context.Context, cmd string) error {
	// c := exec.CommandContext(ctx, "cmd", "/C", cmd)
	c := exec.CommandContext(ctx, "bash", "-c", cmd) // mac linux
	stdout, err := c.StdoutPipe()
	if err != nil {
		return err
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		reader := bufio.NewReader(stdout)
		for {
			// 其实这段去掉程序也会正常运行，只是我们就不知道到底什么时候Command被停止了，而且如果我们需要实时给web端展示输出的话，这里可以作为依据 取消展示
			select {
			// 检测到ctx.Done()之后停止读取
			case <-ctx.Done():
				if ctx.Err() != nil {
					fmt.Printf("程序出现错误: %q", ctx.Err())
				} else {
					fmt.Println("程序被终止")
				}
				return
			default:
				readString, err := reader.ReadString('\n')
				if err != nil || err == io.EOF {
					return
				}
				readString = strings.TrimLeft(readString, "$0")
				fmt.Print(readString)
			}
		}
	}(&wg)
	err = c.Start()
	wg.Wait()
	return err
}
