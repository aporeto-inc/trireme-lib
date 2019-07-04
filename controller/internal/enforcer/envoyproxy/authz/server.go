package authz

import (
	"context"
	"net"

	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.uber.org/zap"

	ext_authz_v2 "go.aporeto.io/trireme-lib/third_party/generated/envoyproxy/data-plane-api/envoy/service/auth/v2"
	envoy_type "go.aporeto.io/trireme-lib/third_party/generated/envoyproxy/data-plane-api/envoy/type"

	"github.com/gogo/googleapis/google/rpc"
	"google.golang.org/grpc"

	"go.aporeto.io/trireme-lib/policy"
)

const (
	// SocketPath is the unix socket path where the authz server will be listening on
	//SocketPath = "@aporeto_envoy_authz"
	SocketPath = "/tmp/aporeto_envoy_authz"
)

// Server struct
type Server struct {
	puID       string
	puInfo     *policy.PUInfo
	secrets    secrets.Secrets
	socketPath string
	server     *grpc.Server
}

// NewExtAuthzServer creates a new envoy ext_authz server
func NewExtAuthzServer(puID string, puInfo *policy.PUInfo, secrets secrets.Secrets) (*Server, error) {
	s := &Server{
		puID:       puID,
		puInfo:     puInfo,
		secrets:    secrets,
		socketPath: SocketPath,
		server:     grpc.NewServer(),
	}

	// register with gRPC
	ext_authz_v2.RegisterAuthorizationServer(s.server, s)
	for serviceName, info := range s.server.GetServiceInfo() {
		zap.L().Debug("ext_authz_server: service info", zap.String("service", serviceName), zap.Any("info", info))
	}

	// Create a custom listener
	addr, err := net.ResolveUnixAddr("unix", s.socketPath)
	if err != nil {
		return nil, err
	}
	nl, err := net.ListenUnix("unix", addr)
	if err != nil {
		return nil, err
	}

	// start and listen to the server
	go s.run(nl)

	return s, nil
}

func (s *Server) run(lis net.Listener) {
	zap.L().Debug("Starting to serve gRPC for ext_authz server", zap.String("puID", s.puID))
	if err := s.server.Serve(lis); err != nil {
		zap.L().Error("gRPC server for ext_authz failed", zap.String("puID", s.puID), zap.Error(err))
	}
	zap.L().Debug("stopped serving gRPC for ext_authz server", zap.String("puID", s.puID))
}

// Stop calls the function with the same name on the backing gRPC server
func (s *Server) Stop() {
	s.server.Stop()
}

// GracefulStop calls the function with the same name on the backing gRPC server
func (s *Server) GracefulStop() {
	s.server.GracefulStop()
}

// Check implements the AuthorizationServer interface
func (s *Server) Check(ctx context.Context, checkRequest *ext_authz_v2.CheckRequest) (*ext_authz_v2.CheckResponse, error) {
	zap.L().Debug("ext_authz.Check(): checkRequest", zap.String("puID", s.puID), zap.String("checkRequest", checkRequest.String()))

	attrs := checkRequest.GetAttributes()

	// extract our headers
	var aporetoKey, aporetoAuth string
	if attrs != nil {
		request := attrs.GetRequest()
		src := attrs.GetSource()
		dest := attrs.GetDestination()
		exts := attrs.GetContextExtensions()

		zap.L().Debug("ext_authz.Check(): attributes",
			zap.String("puID", s.puID),
			zap.Any("attrs", attrs),
			zap.Any("src", src),
			zap.Any("dest", dest),
			zap.Any("exts", exts),
		)

		if request != nil {
			httpReq := request.GetHttp()
			if httpReq != nil {
				httpReqHeaders := httpReq.GetHeaders()
				if httpReqHeaders != nil {
					zap.L().Debug("ext_authz.Check(): HTTP Request Headers", zap.String("puID", s.puID), zap.Any("httpReqHeaders", httpReqHeaders))
					aporetoKey, _ = httpReqHeaders["X-APORETO-KEY"]
					aporetoAuth, _ = httpReqHeaders["X-APORETO-AUTH"]
				} else {
					zap.L().Debug("ext_authz.Check(): missing HTTP request headers", zap.String("puID", s.puID))
				}
			} else {
				zap.L().Debug("ext_authz.Check(): missing HTTP request", zap.String("puID", s.puID))
			}
		} else {
			zap.L().Debug("ext_authz.Check(): missing request", zap.String("puID", s.puID))
		}
	} else {
		zap.L().Debug("ext_authz.Check(): missing attributes", zap.String("puID", s.puID))
	}

	// if the request is lacking our stuff, we send a 400 back
	if aporetoAuth == "" || aporetoKey == "" {
		return &ext_authz_v2.CheckResponse{
			Status: &rpc.Status{
				Code: int32(rpc.INVALID_ARGUMENT),
			},
			HttpResponse: &ext_authz_v2.CheckResponse_DeniedResponse{
				DeniedResponse: &ext_authz_v2.DeniedHttpResponse{
					Status: &envoy_type.HttpStatus{
						Code: envoy_type.StatusCode_BadRequest,
					},
					Body: "missing headers X-APORETO-KEY or X-APORETO-AUTH",
				},
			},
		}, nil
	}

	// otherwise we are just going to allow it for now
	// TODO: obviously :)
	return &ext_authz_v2.CheckResponse{
		Status: &rpc.Status{
			Code: int32(rpc.OK),
		},
		HttpResponse: &ext_authz_v2.CheckResponse_OkResponse{
			OkResponse: &ext_authz_v2.OkHttpResponse{
				// TODO: this is where we need to inject our identity for outgoing traffic
				//Headers:,
			},
		},
	}, nil
}
