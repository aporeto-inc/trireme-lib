package envoyproxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	envoy_core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	ext_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type"
	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/apiauth"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/serviceregistry"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/metadata"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/controller/pkg/servicetokens"
	"go.aporeto.io/trireme-lib/utils/cache"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	rpc "istio.io/gogo-genproto/googleapis/google/rpc"
)

const (
	// IngressSocketPath is the unix socket path where the authz server will be listening on for the ingress authz server
	//IngressSocketPath = "@aporeto_envoy_authz_ingress"
	IngressSocketPath = "127.0.0.1:1999"

	// EgressSocketPath is the unix socket path where the authz server will be listening on for the egress authz server
	EgressSocketPath = "127.0.0.1:1998"
	//EgressSocketPath = "@aporeto_envoy_authz_egress"

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

// AuthServer struct, the server to hold the envoy External Auth.
type AuthServer struct {
	puID       string
	puContexts cache.DataStore
	secrets    secrets.Secrets
	socketPath string
	server     *grpc.Server
	direction  Direction
	verifier   *servicetokens.Verifier
	collector  collector.EventCollector
	auth       *apiauth.Processor
	metadata   *metadata.Client
	sync.RWMutex
}

// Secrets implements the LockedSecrets
// func (e *AuthServer) Secrets() (secrets.Secrets, func()) {
// 	e.RLock()
// 	return e.secrets, e.RUnlock
// }

// NewExtAuthzServer creates a new envoy ext_authz server
func NewExtAuthzServer(puID string, puContexts cache.DataStore, collector collector.EventCollector, direction Direction,
	registry *serviceregistry.Registry, secrets secrets.Secrets, tokenIssuer common.ServiceTokenIssuer) (*AuthServer, error) {
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

	s := &AuthServer{
		puID:       puID,
		puContexts: puContexts,
		secrets:    secrets,
		socketPath: socketPath,
		server:     grpc.NewServer(),
		direction:  direction,
		auth:       apiauth.New(puID, registry, secrets),
		metadata:   metadata.NewClient(puID, registry, tokenIssuer),
		collector:  collector,
	}

	// register with gRPC
	ext_auth.RegisterAuthorizationServer(s.server, s)
	for serviceName, info := range s.server.GetServiceInfo() {
		zap.L().Debug("ext_authz_server: service info", zap.String("service", serviceName), zap.Any("info", info))
	}

	// TODO: figure out why an abstract unix socket path doesn't work
	// Create a custom listener
	// addr, err := net.ResolveUnixAddr("unix", s.socketPath)
	// if err != nil {
	// 	return nil, err
	// }
	//nl, err := net.ListenUnix("unix", addr)
	addr, err := net.ResolveTCPAddr("tcp", s.socketPath)
	if err != nil {
		return nil, err
	}
	nl, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return nil, err
	}
	// if err := os.Remove(s.socketPath); err != nil && !os.IsNotExist(err) {
	// 	fmt.Println("ABHI, envoy-reireme, failed to remove the udspath", err)
	// 	return nil, err
	// }
	// fmt.Println("Start listening on UDS path: ", addr)
	// nl, err := net.ListenUnix("unix", addr)
	// if err != nil {
	// 	fmt.Println("cannot listen on the socketpath", err)
	// 	return nil, err
	// }
	//make sure the socket path can be accessed.
	// if _, err := os.Stat(socketPath); err != nil {
	// 	fmt.Println("SDS uds file doesn't exist", socketPath)
	// 	return nil, fmt.Errorf("sds uds file %q doesn't exist", socketPath)
	// }
	// if err := os.Chmod(socketPath, 0666); err != nil {
	// 	fmt.Println("Failed to update permission", socketPath)
	// 	return nil, fmt.Errorf("failed to update %q permission", socketPath)
	// }
	// start and listen to the server
	fmt.Println("\n\n Auth Server started the server on: ", nl.Addr())
	go s.run(nl)

	return s, nil
}

func (s *AuthServer) run(lis net.Listener) {
	zap.L().Debug("Starting to serve gRPC for ext_authz server", zap.String("puID", s.puID), zap.String("direction", s.direction.String()))
	if err := s.server.Serve(lis); err != nil {
		zap.L().Error("gRPC server for ext_authz failed", zap.String("puID", s.puID), zap.Error(err), zap.String("direction", s.direction.String()))
	}
	zap.L().Debug("stopped serving gRPC for ext_authz server", zap.String("puID", s.puID), zap.String("direction", s.direction.String()))
}

// Stop calls the function with the same name on the backing gRPC server
func (s *AuthServer) Stop() {
	s.server.Stop()
}

// GracefulStop calls the function with the same name on the backing gRPC server
func (s *AuthServer) GracefulStop() {
	s.server.GracefulStop()
}

// Check implements the AuthorizationServer interface
func (s *AuthServer) Check(ctx context.Context, checkRequest *ext_auth.CheckRequest) (*ext_auth.CheckResponse, error) {
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
func (s *AuthServer) ingressCheck(ctx context.Context, checkRequest *ext_auth.CheckRequest) (*ext_auth.CheckResponse, error) {
	// TODO: needs to be removed before we merge: this exposes secret data, and must never be in real logs - even in the debug case
	zap.L().Debug("ext_authz ingress: checkRequest", zap.String("puID", s.puID), zap.String("checkRequest", checkRequest.String()))

	// get the PU context
	// TODO: check with marcus, not sure if we want a LOCK here, as this can be accessed now by the
	// 1. Envoy auth server.
	// 2. by enforcer policy update.
	// pctxRaw, err := s.puContexts.Get(s.puID)
	// if err != nil {
	// 	zap.L().Error("ext_authz ingress: failed to get PU context", zap.String("puID", s.puID), zap.Error(err))
	// 	return createDeniedCheckResponse(rpc.INTERNAL, envoy_type.StatusCode_InternalServerError, "failed to get PU context"), nil
	// }
	// pctx, ok := pctxRaw.(*pucontext.PUContext)
	// if !ok {
	// 	zap.L().Error("ext_authz ingress: PU context has the wrong type", zap.String("puID", s.puID), zap.String("puContextType", fmt.Sprintf("%T", pctxRaw)))
	// 	return createDeniedCheckResponse(rpc.INTERNAL, envoy_type.StatusCode_InternalServerError, "PU context has the wrong type"), nil
	// }
	// now extract the attributes and call the API auth to decode and check all the claims in request.
	var sourceIP, destIP, aporetoAuth, aporetoKey string
	var source, dest *ext_auth.AttributeContext_Peer
	var httpReq *ext_auth.AttributeContext_HttpRequest
	var destPort, srcPort int
	var urlStr, method string
	attrs := checkRequest.GetAttributes()
	if attrs != nil {
		source = attrs.GetSource()
		dest = attrs.GetDestination()

		if source != nil {
			if addr := source.GetAddress(); addr != nil {
				if sockAddr := addr.GetSocketAddress(); sockAddr != nil {
					sourceIP = sockAddr.GetAddress()
					srcPort = int(sockAddr.GetPortValue())
				}
			}
		}
		if dest != nil {
			if destAddr := dest.GetAddress(); destAddr != nil {
				if destSockAddr := destAddr.GetSocketAddress(); destSockAddr != nil {
					destIP = destSockAddr.GetAddress()
					destPort = int(destSockAddr.GetPortValue())
				}
			}
		}

		if request := attrs.GetRequest(); request != nil {
			httpReq = request.GetHttp()
			if httpReq != nil {
				httpReqHeaders := httpReq.GetHeaders()
				aporetoAuth, _ = httpReqHeaders[aporetoAuthHeader]
				aporetoKey, _ = httpReqHeaders[aporetoKeyHeader]
				fmt.Println("httpReqheader is :", httpReqHeaders, "aporeto key is:", aporetoKey)
				urlStr = httpReq.GetPath()
				method = httpReq.GetMethod()

			}
		}
	}
	fmt.Println("in auth check, source addr: ", sourceIP, "source, dest: ", source.GetAddress().GetSocketAddress().GetAddress(), dest.GetAddress().GetSocketAddress().GetAddress())
	fmt.Println("dset port: ", destPort, "src port: ", srcPort)
	requestCookie := &http.Cookie{Name: aporetoAuthHeader, Value: aporetoAuth} // nolint errcheck
	hdr := make(http.Header)
	//URL := url.URL{}
	//hdr.Add()
	hdr.Add(aporetoAuthHeader, aporetoAuth) //string(p.secrets.TransmittedKey()))
	hdr.Add(aporetoKeyHeader, aporetoKey)   //resp.Token)

	// Create the new target URL based on the method+path parameter that we had.
	URL, err := url.ParseRequestURI(method + urlStr)
	if err != nil {
		fmt.Println("Cannot parse the URI")
		return nil, nil
	}

	request := &apiauth.Request{
		OriginalDestination: &net.TCPAddr{IP: net.ParseIP(destIP), Port: destPort},
		SourceAddress:       &net.TCPAddr{IP: net.ParseIP(sourceIP), Port: srcPort},
		Header:              hdr,
		URL:                 URL,
		Method:              method,
		RequestURI:          "",
		Cookie:              requestCookie,
		TLS:                 nil,
	}

	response, err := s.auth.NetworkRequest(context.Background(), request)

	if response.Action.Rejected() {
		zap.L().Debug("ext_authz ingress: Access *NOT* authorized by network policy", zap.String("puID", s.puID))
		//flow.DropReason = "access not authorized by network policy"
		return createDeniedCheckResponse(rpc.PERMISSION_DENIED, envoy_type.StatusCode_Forbidden, "Access not authorized by network policy"), nil
	}

	zap.L().Debug("ext_authz ingress: Access authorized by network policy", zap.String("puID", s.puID))
	return &ext_auth.CheckResponse{
		Status: &rpc.Status{
			Code: int32(rpc.OK),
		},
		HttpResponse: &ext_auth.CheckResponse_OkResponse{
			OkResponse: &ext_auth.OkHttpResponse{},
		},
	}, nil
	//return nil, nil
}

// egressCheck implements the AuthorizationServer for egress connections
func (s *AuthServer) egressCheck(ctx context.Context, checkRequest *ext_auth.CheckRequest) (*ext_auth.CheckResponse, error) {
	var sourceIP, destIP string
	var source, dest *ext_auth.AttributeContext_Peer
	var httpReq *ext_auth.AttributeContext_HttpRequest
	var destPort, srcPort int
	var urlStr, method string
	attrs := checkRequest.GetAttributes()
	if attrs != nil {
		source = attrs.GetSource()
		dest = attrs.GetDestination()

		if source != nil {
			if addr := source.GetAddress(); addr != nil {
				if sockAddr := addr.GetSocketAddress(); sockAddr != nil {
					sourceIP = sockAddr.GetAddress()
					srcPort = int(sockAddr.GetPortValue())
				}
			}
		}
		if dest != nil {
			if destAddr := dest.GetAddress(); destAddr != nil {
				if destSockAddr := destAddr.GetSocketAddress(); destSockAddr != nil {
					destIP = destSockAddr.GetAddress()
					destPort = int(destSockAddr.GetPortValue())
				}
			}
		}

		if request := attrs.GetRequest(); request != nil {
			httpReq = request.GetHttp()
			urlStr = httpReq.GetPath()
			method = httpReq.GetMethod()
		}
	}
	// Create the new target URL based on the path parameter that we have from envoy.
	URL, err := url.ParseRequestURI(urlStr)
	if err != nil {
		fmt.Println("Cannot parse the URI")
		return nil, nil
	}

	authRequest := &apiauth.Request{
		OriginalDestination: &net.TCPAddr{IP: net.ParseIP(destIP), Port: destPort},
		SourceAddress:       &net.TCPAddr{IP: net.ParseIP(sourceIP), Port: srcPort},
		URL:                 URL,
		Method:              method,
		RequestURI:          "",
	}
	resp, err := s.auth.ApplicationRequest(authRequest)
	if err != nil {
	}

	if resp.Action.Rejected() {
		zap.L().Debug("ext_authz ingress: Access *NOT* authorized by network policy", zap.String("puID", s.puID))
		//flow.DropReason = "access not authorized by network policy"
		return createDeniedCheckResponse(rpc.PERMISSION_DENIED, envoy_type.StatusCode_Forbidden, "Access not authorized by network policy"), nil
	}
	// now create the response and inject our identity
	zap.L().Debug("ext_authz egress: injecting header", zap.String("puID", s.puID))
	// build our identity token
	fmt.Println("\n\n **** ABHI ext-auth Egress check, need add key and token")
	//var secrets secrets.Secrets
	//var unlockSecrets func()
	var transmittedKey []byte
	if s.secrets != nil {
		transmittedKey = s.secrets.TransmittedKey()
		//defer unlockSecrets()
	} else {
		fmt.Println("the secrerts are nil")
	}
	//transmittedKey := s.secrets.TransmittedKey()

	//flow.Action = policy.Accept
	return &ext_auth.CheckResponse{
		Status: &rpc.Status{
			Code: int32(rpc.OK),
		},
		HttpResponse: &ext_auth.CheckResponse_OkResponse{
			OkResponse: &ext_auth.OkHttpResponse{
				Headers: []*envoy_core.HeaderValueOption{
					&envoy_core.HeaderValueOption{
						Header: &envoy_core.HeaderValue{
							Key:   aporetoKeyHeader,
							Value: string(transmittedKey),
						},
					},
					&envoy_core.HeaderValueOption{
						Header: &envoy_core.HeaderValue{
							Key:   aporetoAuthHeader,
							Value: resp.Token,
						},
					},
				},
			},
		},
	}, nil
	//return nil, nil
}

func createDeniedCheckResponse(rpcCode rpc.Code, httpCode envoy_type.StatusCode, body string) *ext_auth.CheckResponse {
	return &ext_auth.CheckResponse{
		Status: &rpc.Status{
			Code: int32(rpcCode),
		},
		HttpResponse: &ext_auth.CheckResponse_DeniedResponse{
			DeniedResponse: &ext_auth.DeniedHttpResponse{
				Status: &envoy_type.HttpStatus{
					Code: httpCode,
				},
				Body: body,
			},
		},
	}
}
