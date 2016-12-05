package rpcWrapper

import (
	"net"
	"net/http"
	"net/rpc"
)

//Not mocking system libraries
//Will create actual rpc client server without using wrapper to test our implementations

func createServer(channel string) {
	type Server struct{}
	handler := new(Server)
	protocol := "unix"
	RegisterTypes()
	rpc.Register(handler)
	rpc.HandleHTTP()
	listen, _ := net.Listen(protocol, channel)
	go http.Serve(listen, nil)
	defer func() {
		listen.Close()
	}()
	c := make(chan int, 1)
	<-c
	return
}

func startClient(channel string) (*rpc.Client, error) {
	client, err := rpc.DialHTTP("unix", channel)
	return client, err
}

func asyncRpcclient(channel string, resp chan<- error, rpchdl *RPCWrapper) {
	err := rpchdl.NewRPCClient("12345", defaultchannel)
	resp <- err
}
