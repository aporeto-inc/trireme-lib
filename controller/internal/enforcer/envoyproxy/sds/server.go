package sds

import (
	"fmt"
	"net"
	"os"

	"context"

	"google.golang.org/grpc"

	v2 "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/auth"
	sds "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v2"
	"istio.io/istio/security/pkg/nodeagent/model"
)

// Options to create a SDS server to task to envoy
type Options struct {
	SocketPath string
}

// SecretDiscoveryStream is the same as the sds.SecretDiscoveryService_StreamSecretsServer
type SecretDiscoveryStream interface {
	Send(*v2.DiscoveryResponse) error
	Recv() (*v2.DiscoveryRequest, error)
	grpc.ServerStream
}

// Server to talk with envoy.
type Server struct {
	sdsGrpcServer   *grpc.Server
	sdsGrpcListener net.Listener

	errCh chan error
}

// NewServer creates a instance of a server.
func NewServer() Server {
	return Server{errCh: make(chan error)}
}

// CreateSdsService does the following
// 1. create grpc server.
// 2. create a listener on the Unix Domain Socket.
// 3.
func (s Server) CreateSdsService(options *Options) error { //nolint: unparam
	fmt.Println("ABHI, envoy-trireme create  SDS server")
	s.sdsGrpcServer = grpc.NewServer()
	s.register(s.sdsGrpcServer)
	if err := os.Remove(options.SocketPath); err != nil && !os.IsNotExist(err) {
		fmt.Println("ABHI, envoy-reireme, failed to remove the udspath", err)
		return err
	}
	fmt.Println("Start listening on UDS path: ", options.SocketPath)
	sdsGrpcListener, err := net.Listen("unix", options.SocketPath)
	if err != nil {
		fmt.Println("cannot listen on the socketpath", err)
		return err
	}
	// make sure the socket path can be accessed.
	if _, err := os.Stat(options.SocketPath); err != nil {
		fmt.Println("SDS uds file %q doesn't exist", options.SocketPath)
		return fmt.Errorf("sds uds file %q doesn't exist", options.SocketPath)
	}
	if err := os.Chmod(options.SocketPath, 0666); err != nil {
		fmt.Println("Failed to update %q permission", options.SocketPath)
		return fmt.Errorf("failed to update %q permission", options.SocketPath)
	}
	//var err error
	s.sdsGrpcListener = sdsGrpcListener

	fmt.Println("run the grpc server")
	s.Run()
	return nil
}

// Run starts the sdsGrpcServer to serve
func (s Server) Run() {
	go func() {
		if s.sdsGrpcListener != nil {
			if err := s.sdsGrpcServer.Serve(s.sdsGrpcListener); err != nil {
				fmt.Println("got error after serve", err)
				s.errCh <- err
			}
		}
		fmt.Println("the listener is nil, cannot start the server")
	}()
}

// Stop stops all the listeners and the grpc servers.
func (s Server) Stop() {
	if s.sdsGrpcListener != nil {
		s.sdsGrpcListener.Close()
	}
	if s.sdsGrpcServer != nil {
		s.sdsGrpcServer.Stop()
	}
}

// register adds the SDS handle to the grpc server
func (s Server) register(sdsGrpcServer *grpc.Server) {
	fmt.Println("\n\n ** Abhi envoy-trireme registering the secret discovery")
	sds.RegisterSecretDiscoveryServiceServer(sdsGrpcServer, s)
}

// now implement the interfaces of the SDS grpc server.
// type SecretDiscoveryServiceServer interface {
// 	DeltaSecrets(SecretDiscoveryService_DeltaSecretsServer) error
// 	StreamSecrets(SecretDiscoveryService_StreamSecretsServer) error
// 	FetchSecrets(context.Context, *v2.DiscoveryRequest) (*v2.DiscoveryResponse, error)
// }

// DeltaSecrets checks for the delta and sends the changes.
func (s Server) DeltaSecrets(stream sds.SecretDiscoveryService_DeltaSecretsServer) error {
	return nil
}

func startStreaming(stream SecretDiscoveryStream, discoveryReqCh chan *v2.DiscoveryRequest) {
	fmt.Println("In start streaming")
	defer close(discoveryReqCh)
	for {
		fmt.Println("\n wait for the stream to be received")
		req, err := stream.Recv()
		if err != nil {
			fmt.Println("Connection terminated with err: ", err)
			return
		}
		fmt.Println("\n\n **** $$$$$ received the msg, now send it the main function", req.Node.Id)
		discoveryReqCh <- req
	}
}

// StreamSecrets is the function invoked by the envoy in-order to pull the certs, this also sends the response back to the envoy.
// It does the following:
// 1. create a receiver thread to stream the requests.
// 2. parse the discovery request.
// 3. track the request.
// 4. call the Aporeto api to generate the secret
func (s Server) StreamSecrets(stream sds.SecretDiscoveryService_StreamSecretsServer) error {
	fmt.Println("IN stream secret")
	discoveryReqCh := make(chan *v2.DiscoveryRequest, 1)
	go startStreaming(stream, discoveryReqCh)

	for {
		// wait for the receiver thread to stream the request and send it to us over here.
		select {
		case req, ok := <-discoveryReqCh:
			fmt.Println("got the req to be processed by start streaming")
			// Now check the following:
			// 1. Return if stream is closed.
			// 2. Return if its invalid request.
			if !ok {
				fmt.Println("Receiver channel closed, which means the Receiver stream is closed")
				return fmt.Errorf("Receiver closed the channel")
			}
			// if req.Node == nil {
			// 	fmt.Println("unknow/invalid request from the envoy")
			// 	return fmt.Errorf("unknow/invalid request from the envoy")
			// }
			// the node will be present only only in the 1st message according to the xds protocol
			if req.Node != nil {
				fmt.Println("the 1st request came from envoy: ", req.Node.Id, req.Node.Cluster)
			}
			// now according to the Istio pilot SDS secret config we have 2 configs, this configs are pushed to envoy through Istio.
			// 1. SDSDefaultResourceName is the default name in sdsconfig, used for fetching normal key/cert.
			// 2. SDSRootResourceName is the sdsconfig name for root CA, used for fetching root cert.
			// therefore from the above we receive 2 requests, 1 for default and 2 for the ROOTCA

			// now check for the resourcename, it should atleast have one, else continue and stream the next request.
			// according to the defination this could be empty.
			if len(req.ResourceNames) == 0 {
				continue
			}
			fmt.Println("ABHI, envoy-trireme the req resource name is: ", req.ResourceNames)

			//secret := generateSecret(req)

			// TODO: now call the metadata-lib function to fetch the secrets.
			// TODO: once the secret is fetched create a discovery Response depending on the secret.

			// resp := &v2.DiscoveryResponse{
			// 	TypeUrl: "aporeto.io/sds_envoy_certs",
			// }
			// retSecret := auth.Secret{}
			// if secret.RootCert != nil {
			// 	retSecret.Type = getRootCert(secret)
			// } else {
			// 	retSecret.Type = getTLScerts(secret)
			// }
			// endSecret, err := types.MarshalAny(retSecret)
			// if err != nil {
			// 	fmt.Println("Cannot marshall the secret")
			// 	continue
			// }
			// resp.Resources = append(resp.Resources, endSecret)
		}
	}

}

// FetchSecrets gets the discovery request and call the Aporeto backend to fetch the certs.
// 1. parse the discovery request.
// 2. track the request.
// 3. call the Aporeto api to generate the secret
func (s Server) FetchSecrets(ctx context.Context, discReq *v2.DiscoveryRequest) (*v2.DiscoveryResponse, error) {
	return nil, nil
}

// generateSecret is the call which talks to the metadata API to fetch the certs.
func generateSecret(req *v2.DiscoveryRequest) *model.SecretItem {
	return nil
}

func getRootCert(secret *model.SecretItem) *auth.Secret_ValidationContext {
	return nil
}
func getTLScerts(secret *model.SecretItem) *auth.Secret_TlsCertificate {
	return nil
}
