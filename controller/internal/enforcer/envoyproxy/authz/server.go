package authz

import (
	"context"
	"fmt"
	"net"
	"time"

	"go.aporeto.io/trireme-lib/controller/pkg/pucontext"

	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/controller/pkg/servicetokens"
	"go.uber.org/zap"

	envoy_core "go.aporeto.io/trireme-lib/third_party/generated/envoyproxy/data-plane-api/envoy/api/v2/core"
	ext_authz_v2 "go.aporeto.io/trireme-lib/third_party/generated/envoyproxy/data-plane-api/envoy/service/auth/v2"
	envoy_type "go.aporeto.io/trireme-lib/third_party/generated/envoyproxy/data-plane-api/envoy/type"

	"github.com/gogo/googleapis/google/rpc"
	"google.golang.org/grpc"

	"go.aporeto.io/trireme-lib/policy"
)

const (
	// IngressSocketPath is the unix socket path where the authz server will be listening on for the ingress authz server
	//IngressSocketPath = "@aporeto_envoy_authz_ingress"
	IngressSocketPath = "127.0.0.1:1999"

	// EgressSocketPath is the unix socket path where the authz server will be listening on for the egress authz server
	EgressSocketPath = "127.0.0.1:1998"

	// defaultValidity of the issued JWT token
	defaultValidity = 60 * time.Second

	// aporetoKeyHeader is the HTTP header name for the key header
	aporetoKeyHeader = "x-aporeto-key"

	// aporetoAuthHeader is the HTTP header name for the auth header
	aporetoAuthHeader = "x-aporeto-auth"
)

// Direction is used to indicate if the authorization server is ingress or egress.
// NOTE: the type is currently set to uint8 and not bool because in Istio there are 3 types:
// - SIDECAR_INBOUND
// - SIDECAR_OUTBOUND
// - GATEWAY
// And we are not sure yet if we need an extra authz server for GATEWAY.
type Direction uint8

const (
	// UnknownDirection is only used to denote uninitialized variables
	UnknownDirection Direction = 0

	// IngressDirection refers to inbound / ingress traffic.
	// NOTE: for Istio use this in conjunction with SIDECAR_INBOUND
	IngressDirection Direction = 1

	// EgressDirection refers to outbound / egress traffic.
	// NOTE: for Istio use this in conjunction with SIDECAR_OUTBOUND
	EgressDirection Direction = 2
)

// String overwrites the string interface
func (d Direction) String() string {
	switch d {
	case UnknownDirection:
		return "UnknownDirection"
	case IngressDirection:
		return "IngressDirection"
	case EgressDirection:
		return "EgressDirection"
	default:
		return fmt.Sprintf("Unimplemented(%d)", d)
	}
}

// Server struct
type Server struct {
	puID       string
	puInfo     *policy.PUInfo
	secrets    secrets.Secrets
	socketPath string
	server     *grpc.Server
	direction  Direction
	verifier   *servicetokens.Verifier
}

// NewExtAuthzServer creates a new envoy ext_authz server
func NewExtAuthzServer(puID string, puInfo *policy.PUInfo, secrets secrets.Secrets, direction Direction) (*Server, error) {
	var socketPath string
	switch direction {
	case UnknownDirection:
		return nil, fmt.Errorf("direction must be set to ingress or egress")
	case IngressDirection:
		socketPath = IngressSocketPath
	case EgressDirection:
		socketPath = EgressSocketPath
	default:
		return nil, fmt.Errorf("direction must be set to ingress or egress")
	}
	if direction == UnknownDirection || direction > EgressDirection {
		return nil, fmt.Errorf("direction must be set to ingress or egress")
	}

	s := &Server{
		puID:       puID,
		puInfo:     puInfo,
		secrets:    secrets,
		socketPath: socketPath,
		server:     grpc.NewServer(),
		direction:  direction,
		verifier:   servicetokens.NewVerifier(secrets, nil),
	}

	// register with gRPC
	ext_authz_v2.RegisterAuthorizationServer(s.server, s)
	for serviceName, info := range s.server.GetServiceInfo() {
		zap.L().Debug("ext_authz_server: service info", zap.String("service", serviceName), zap.Any("info", info))
	}

	// TODO: figure out why an abstract unix socket path doesn't work
	// Create a custom listener
	//addr, err := net.ResolveUnixAddr("unix", s.socketPath)
	//if err != nil {
	//	return nil, err
	//}
	//nl, err := net.ListenUnix("unix", addr)
	addr, err := net.ResolveTCPAddr("tcp", s.socketPath)
	if err != nil {
		return nil, err
	}
	nl, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return nil, err
	}

	// start and listen to the server
	go s.run(nl)

	return s, nil
}

func (s *Server) run(lis net.Listener) {
	zap.L().Debug("Starting to serve gRPC for ext_authz server", zap.String("puID", s.puID), zap.String("direction", s.direction.String()))
	if err := s.server.Serve(lis); err != nil {
		zap.L().Error("gRPC server for ext_authz failed", zap.String("puID", s.puID), zap.Error(err), zap.String("direction", s.direction.String()))
	}
	zap.L().Debug("stopped serving gRPC for ext_authz server", zap.String("puID", s.puID), zap.String("direction", s.direction.String()))
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
	switch s.direction {
	case IngressDirection:
		return s.ingressCheck(ctx, checkRequest)
	case EgressDirection:
		return s.egressCheck(ctx, checkRequest)
	default:
		return nil, fmt.Errorf("direction: %s", s.direction)
	}
}

// ingressCheck implements the AuthorizationServer for ingress connections
func (s *Server) ingressCheck(ctx context.Context, checkRequest *ext_authz_v2.CheckRequest) (*ext_authz_v2.CheckResponse, error) {
	zap.L().Debug("ext_authz.ingressCheck(): checkRequest", zap.String("puID", s.puID), zap.String("checkRequest", checkRequest.String()))

	attrs := checkRequest.GetAttributes()

	// extract our headers
	var aporetoKey, aporetoAuth string
	if attrs != nil {
		request := attrs.GetRequest()
		src := attrs.GetSource()
		dest := attrs.GetDestination()
		exts := attrs.GetContextExtensions()

		zap.L().Debug("ext_authz.ingressCheck(): attributes",
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
					zap.L().Debug("ext_authz.ingressCheck(): HTTP Request Headers", zap.String("puID", s.puID), zap.Any("httpReqHeaders", httpReqHeaders))
					aporetoKey, _ = httpReqHeaders[aporetoKeyHeader]
					aporetoAuth, _ = httpReqHeaders[aporetoAuthHeader]
				} else {
					zap.L().Debug("ext_authz.ingressCheck(): missing HTTP request headers", zap.String("puID", s.puID))
				}
			} else {
				zap.L().Debug("ext_authz.ingressCheck(): missing HTTP request", zap.String("puID", s.puID))
			}
		} else {
			zap.L().Debug("ext_authz.ingressCheck(): missing request", zap.String("puID", s.puID))
		}
	} else {
		zap.L().Debug("ext_authz.ingressCheck(): missing attributes", zap.String("puID", s.puID))
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

	// now we can see if we can decode our claims
	srcid, scopes, profile, err := s.verifier.ParseToken(aporetoAuth, aporetoKey)
	if err != nil {
		zap.L().Debug("ext_authz.ingressCheck(): failed to parse Aporeto token", zap.String("puID", s.puID), zap.Error(err))
		return &ext_authz_v2.CheckResponse{
			Status: &rpc.Status{
				Code: int32(rpc.PERMISSION_DENIED),
			},
			HttpResponse: &ext_authz_v2.CheckResponse_DeniedResponse{
				DeniedResponse: &ext_authz_v2.DeniedHttpResponse{
					Status: &envoy_type.HttpStatus{
						Code: envoy_type.StatusCode_Forbidden,
					},
					Body: "failed to parse Aporeto token",
				},
			},
		}, nil
	}
	zap.L().Debug("ext_authz.ingressCheck(): parsed Aporeto token", zap.String("puID", s.puID), zap.String("srcid", srcid), zap.Strings("scopes", scopes), zap.Strings("profile", profile))

	// hack for quick policy checks
	pctx, err := pucontext.NewPU(s.puID, s.puInfo, defaultValidity)
	if err != nil {
		zap.L().Error("ext_authz.ingressCheck(): failed to create PU context", zap.String("puID", s.puID), zap.Error(err))
		return nil, err
	}
	_, netPolicyAction := pctx.SearchRcvRules(policy.NewTagStoreFromSlice(profile))
	if netPolicyAction.Action.Rejected() {
		zap.L().Debug("ext_authz.ingressCheck(): Access *NOT* authorized by network policy", zap.String("puID", s.puID))
		return &ext_authz_v2.CheckResponse{
			Status: &rpc.Status{
				Code: int32(rpc.PERMISSION_DENIED),
			},
			HttpResponse: &ext_authz_v2.CheckResponse_DeniedResponse{
				DeniedResponse: &ext_authz_v2.DeniedHttpResponse{
					Status: &envoy_type.HttpStatus{
						Code: envoy_type.StatusCode_Forbidden,
					},
					Body: "Access not authorized by network policy",
				},
			},
		}, nil
	}

	// otherwise we are just going to allow it for now
	zap.L().Debug("ext_authz.ingressCheck(): Access authorized by network policy", zap.String("puID", s.puID))
	return &ext_authz_v2.CheckResponse{
		Status: &rpc.Status{
			Code: int32(rpc.OK),
		},
		HttpResponse: &ext_authz_v2.CheckResponse_OkResponse{
			OkResponse: &ext_authz_v2.OkHttpResponse{},
		},
	}, nil
}

// egressCheck implements the AuthorizationServer for egress connections
func (s *Server) egressCheck(ctx context.Context, checkRequest *ext_authz_v2.CheckRequest) (*ext_authz_v2.CheckResponse, error) {
	zap.L().Debug("ext_authz.egressCheck(): checkRequest", zap.String("puID", s.puID), zap.String("checkRequest", checkRequest.String()))

	attrs := checkRequest.GetAttributes()
	if attrs == nil {
		return nil, fmt.Errorf("ext_authz egress: missing attributes")
	}
	src := attrs.GetSource()
	if src == nil {
		return nil, fmt.Errorf("ext_authz egress: missing source in attributes")
	}

	addr := src.GetAddress()
	if addr == nil {
		return nil, fmt.Errorf("ext_authz egress: missing address in source from attributes")
	}
	sockAddr := addr.GetSocketAddress()
	if sockAddr == nil {
		return nil, fmt.Errorf("ext_authz egress: missing socket address in source from attributes")
	}

	// build our identity token
	token, err := servicetokens.CreateAndSign(
		sockAddr.GetAddress(),
		s.puInfo.Runtime.Tags().Tags,
		[]string{},
		s.puID,
		defaultValidity,
		s.secrets.EncodingKey(),
	)
	if err != nil {
		zap.L().Error("ext_authz egress: cannot create token", zap.Error(err))
		return nil, fmt.Errorf("ext_authz egress: cannot create token: %v", err)
	}

	zap.L().Debug("ext_authz egress: injecting header", zap.String(aporetoKeyHeader, string(s.secrets.TransmittedKey())), zap.String(aporetoAuthHeader, token))
	// now create the response and inject our identity
	return &ext_authz_v2.CheckResponse{
		Status: &rpc.Status{
			Code: int32(rpc.OK),
		},
		HttpResponse: &ext_authz_v2.CheckResponse_OkResponse{
			OkResponse: &ext_authz_v2.OkHttpResponse{
				Headers: []*envoy_core.HeaderValueOption{
					&envoy_core.HeaderValueOption{
						Header: &envoy_core.HeaderValue{
							Key:   aporetoKeyHeader,
							Value: string(s.secrets.TransmittedKey()),
						},
					},
					&envoy_core.HeaderValueOption{
						Header: &envoy_core.HeaderValue{
							Key:   aporetoAuthHeader,
							Value: token,
						},
					},
				},
			},
		},
	}, nil
}
