package enforcer

type RPC_handler struct{}

const (
	// Defaults used by HandleHTTP
	DefaultRPCPath   = "/_goRPC_"
	DefaultDebugPath = "/debug/rpc"
)

func (r *RPC_handler) ProcessMessage(req *enforcer_adaptor.Enforcer_request, resp *enforcer_adaptor.Enforcer_response) error {
	return nil
}


func NewRPC_handler(path string) error {
	rpc_hdl := new(RPC_handler)
	client, err := net.DialHTTP("unix",path)
	server.RegisterName("client", rpc_hdl)
	

	return nil
}