package main

import (
	"os"
	"os/signal"
	"time"

	"github.com/aporeto-inc/trireme/enforcer_impl"
)

func init() {

}
func main() {
	unix_sock_path := os.Args[0]
	contextID := os.Args[1]
	//Switch namespace before we execute any code

	enforcer_impl.NewEnforcer(contextID, unix_sock_path)
	//starting the RPC handler
	err := enforcer_impl.NewRPC_handler(unix_sock_path)
	time.Sleep(1000 * time.Second)
	if err != nil {
		os.Create("/tmp/panic")
		panic("Failed to create rpc_handler")
	}
	//e.Start()
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c

}
