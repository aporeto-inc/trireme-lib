package rpcwrapper

func asyncRpcclient(resp chan<- error, rpchdl *RPCWrapper) {
	err := rpchdl.NewRPCClient("12345", defaultchannel, "mysecret")
	resp <- err
}
