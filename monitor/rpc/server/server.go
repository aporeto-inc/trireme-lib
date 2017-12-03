package rpcserver

import (
	"fmt"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"strings"

	"go.uber.org/zap"
)

type rpcServer struct {
	root       bool
	rpcAddress string
	rpcServer  *rpc.Server
	listenSock net.Listener
}

// New provides a new RPCServer
func New(rpcAddress string, root bool) RPCServer {

	if rpcAddress == "" {
		return nil
	}
	return &rpcServer{
		root:       root,
		rpcAddress: rpcAddress,
		rpcServer:  rpc.NewServer(),
	}
}

// Register registers a receiver interface.
func (r *rpcServer) Register(rcvr interface{}) error {

	return r.rpcServer.Register(rcvr)
}

// Start starts the rpc server.
func (r *rpcServer) Start() (err error) {

	if _, err = os.Stat(r.rpcAddress); err == nil {
		if err = os.Remove(r.rpcAddress); err != nil {
			return fmt.Errorf("Failed to clean up rpc socket: %s", err.Error())
		}
	}

	if r.listenSock, err = net.Listen("unix", r.rpcAddress); err != nil {
		return fmt.Errorf("Failed to start RPC monitor: couldn't create binding: %s", err.Error())
	}

	if r.root {
		err = os.Chmod(r.rpcAddress, 0600)
	} else {
		err = os.Chmod(r.rpcAddress, 0766)
	}
	if err != nil {
		return err
	}

	// Launch a go func to accept connections
	go r.processRequests()

	return nil
}

// Stop stops the rpc server.
func (r *rpcServer) Stop() {

	if err := r.listenSock.Close(); err != nil {
		zap.L().Warn("Failed to stop rpc monitor", zap.Error(err))
	}

	if err := os.RemoveAll(r.rpcAddress); err != nil {
		zap.L().Warn("Failed to cleanup rpc monitor socket", zap.Error(err))
	}
}

// processRequests processes the RPC requests
func (r *rpcServer) processRequests() {

	for {
		conn, err := r.listenSock.Accept()
		if err == nil {

			go r.rpcServer.ServeCodec(jsonrpc.NewServerCodec(conn))

			continue
		}

		if !strings.Contains(err.Error(), "closed") {
			zap.L().Error("Error while handling RPC event", zap.Error(err))
		}

		break
	}
}
