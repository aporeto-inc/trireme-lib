package sds

import (
	"fmt"
	"net"

	"context"

	"google.golang.org/grpc"

	v2 "go.aporeto.io/trireme-lib/third_party/generated/envoyproxy/data-plane-api/envoy/api/v2"
	sds "go.aporeto.io/trireme-lib/third_party/generated/envoyproxy/data-plane-api/envoy/service/discovery/v2"
	"google.golang.org/grpc"
)

// Options to create a SDS server to task to envoy
type Options struct {
	SocketPath string
}

// Server to talk with envoy.
type Server struct {
	sdsGrpcServer   *grpc.Server
	sdsGrpcListener net.Listener
}

// CreateSdsService does the following
// 1. create grpc server.
// 2. create a listener on the Unix Domain Socket.
// 3.
func (s *Server) CreateSdsService(options *Options) error { //nolint: unparam
	fmt.Println("create  SDS server")
	s.sdsGrpcServer = grpc.NewServer()

	sdsGrpcListener, err := net.Listen("unix", options.SocketPath)
	if err != nil {
		fmt.Println("cannot listen on the socketpath", err)
		return err
	}
	s.sdsGrpcListener = sdsGrpcListener
	return nil
}

// register adds the SDS handle to the grpc server
func (s *Server) register(rpcs *grpc.Server) {
	fmt.Println("\n\n ** registering the secret discovery")
	sds.RegisterSecretDiscoveryServiceServer(rpcs, s)
}

// now implement the interfaces of the SDS grpc server.
// type SecretDiscoveryServiceServer interface {
// 	DeltaSecrets(SecretDiscoveryService_DeltaSecretsServer) error
// 	StreamSecrets(SecretDiscoveryService_StreamSecretsServer) error
// 	FetchSecrets(context.Context, *v2.DiscoveryRequest) (*v2.DiscoveryResponse, error)
// }

// DeltaSecrets checks for the delta and sends the changes.
func (s *Server) DeltaSecrets(stream sds.SecretDiscoveryService_DeltaSecretsServer) error {
	return nil
}

// StreamSecrets is the function invoked by the envoy in-order to pull the certs, this also sends the response back to the envoy.
// It does the following:
// 1. create a rece
func (s *Server) StreamSecrets(stream sds.SecretDiscoveryService_StreamSecretsServer) error {
	return nil
}

// FetchSecrets gets the discovery request and call the Aporeto backend to fetch the certs.
func (s *Server) FetchSecrets(ctx context.Context, discReq *v2.DiscoveryRequest) (*v2.DiscoveryResponse, error) {
	return nil, nil
}
