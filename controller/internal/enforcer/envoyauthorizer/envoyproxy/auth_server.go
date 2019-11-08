package envoyproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/flowstats"
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

// Secrets implements locked secrets
// func (s *AuthServer) Secrets() secrets.Secrets {
// 	s.RLock()
// 	defer s.RUnlock()
// 	return s.secrets
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
		zap.L().Info("ext_authz_server: service info", zap.String("service", serviceName), zap.Any("info", info))
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
	zap.L().Debug("ext_authz_server: Auth Server started the server on: ", zap.Any(" addr: ", nl.Addr()), zap.String("puID: ", puID))
	go s.run(nl)

	return s, nil
}

// UpdateSecrets updates the secrets
// Whenever the Envoy makes a request for certificate, the certs and keys are fetched from
// the Proxy.
func (s *AuthServer) UpdateSecrets(cert *tls.Certificate, caPool *x509.CertPool, secrets secrets.Secrets, certPEM, keyPEM string) {
	s.Lock()
	defer s.Unlock()
	s.secrets = secrets

	// TODO: once the dimitris commit goes in, we need update the apiAuth secrets.

}

func (s *AuthServer) run(lis net.Listener) {
	zap.L().Debug("Starting to serve gRPC for ext_authz server", zap.String("puID", s.puID), zap.String("direction", s.direction.String()))
	if err := s.server.Serve(lis); err != nil {
		zap.L().Error("gRPC server for ext_authz failed", zap.String("puID", s.puID), zap.Error(err), zap.String("direction", s.direction.String()))
	}
	zap.L().Info("stopped serving gRPC for ext_authz server", zap.String("puID", s.puID), zap.String("direction", s.direction.String()))
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
	zap.L().Debug(" Envoy check, DIR: ", zap.Uint8("dir: ", uint8(s.direction)))
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
	zap.L().Info("ext_authz ingress: checkRequest", zap.String("puID", s.puID), zap.String("checkRequest", checkRequest.String()))

	// now extract the attributes and call the API auth to decode and check all the claims in request.
	var sourceIP, destIP, aporetoAuth, aporetoKey string
	var source, dest *ext_auth.AttributeContext_Peer
	var httpReq *ext_auth.AttributeContext_HttpRequest
	var destPort, srcPort int
	var urlStr, method, scheme string
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
				zap.L().Debug("ext_authz ingress: ", zap.Any("httpReqHeaders: ", httpReqHeaders), zap.String("aporetoKey: ", aporetoKey))
				urlStr = httpReq.GetPath()
				method = httpReq.GetMethod()
				scheme = httpReq.GetScheme()

			}
		}
	}
	zap.L().Debug("ext_authz ingress:", zap.String("source addr: ", sourceIP), zap.String("source, dest: ", source.GetAddress().GetSocketAddress().GetAddress()), zap.String("dest addr: ", dest.GetAddress().GetSocketAddress().GetAddress()))
	zap.L().Debug("ext_authz ingress:", zap.Any("destPort: ", destPort), zap.Any("srcPort: ", srcPort), zap.String("scheme: ", scheme))

	requestCookie := &http.Cookie{Name: aporetoAuthHeader, Value: aporetoAuth} // nolint errcheck
	hdr := make(http.Header)

	zap.L().Debug("ext_authz ingress:", zap.String("Aporeto-Auth: ", aporetoAuth), zap.String("Aporeto-key: ", aporetoKey))
	hdr.Add(aporetoAuthHeader, aporetoAuth) //string(p.secrets.TransmittedKey()))
	hdr.Add(aporetoKeyHeader, aporetoKey)   //resp.Token)

	// Create the new target URL based on the method+path parameter that we had.
	URL, err := url.ParseRequestURI("http:" + method + urlStr)
	if err != nil {
		zap.L().Error("ext_authz ingress: Cannot parse the URI", zap.Error(err))
		return nil, err
	}
	zap.L().Debug("ext_authz ingress:", zap.String("URL: ", URL.String()))
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
	var userID string
	if response != nil && len(response.UserAttributes) > 0 {
		userData := &collector.UserRecord{
			Namespace: response.Namespace,
			Claims:    response.UserAttributes,
		}
		s.collector.CollectUserEvent(userData)
		userID = userData.ID
	}

	state := flowstats.NewNetworkConnectionState(s.puID, userID, request, response)
	defer s.collector.CollectFlowEvent(state.Stats)

	if err != nil {
		if response == nil {
			zap.L().Error("ext_authz ingress: auth.Networkrequest response is nil")
			return createDeniedCheckResponse(rpc.PERMISSION_DENIED, envoy_type.StatusCode_Forbidden, "No aporeto service installed"), nil
		}
		return createDeniedCheckResponse(rpc.PERMISSION_DENIED, envoy_type.StatusCode_Forbidden, "Access not authorized by network policy"), nil
	}
	if response.Action.Rejected() {
		zap.L().Error("ext_authz ingress: Access *NOT* authorized by network policy", zap.String("puID", s.puID))
		//flow.DropReason = "access not authorized by network policy"
		return createDeniedCheckResponse(rpc.PERMISSION_DENIED, envoy_type.StatusCode_Forbidden, "Access not authorized by network policy"), nil
	}
	zap.L().Info("ext_authz ingress: Request accepted for", zap.String("dst: ", destIP), zap.String("src: ", sourceIP))
	zap.L().Debug("ext_authz ingress: Access authorized by network policy", zap.String("puID", s.puID))
	return &ext_auth.CheckResponse{
		Status: &rpc.Status{
			Code: int32(rpc.OK),
		},
		HttpResponse: &ext_auth.CheckResponse_OkResponse{
			OkResponse: &ext_auth.OkHttpResponse{},
		},
	}, nil
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
		zap.L().Error("ext_authz egress: Cannot parse the URI", zap.Error(err))
		return nil, err
	}

	authRequest := &apiauth.Request{
		OriginalDestination: &net.TCPAddr{IP: net.ParseIP(destIP), Port: destPort},
		SourceAddress:       &net.TCPAddr{IP: net.ParseIP(sourceIP), Port: srcPort},
		URL:                 URL,
		Method:              method,
		RequestURI:          "",
	}
	r := new(http.Request)
	r.RemoteAddr = sourceIP
	resp, err := s.auth.ApplicationRequest(authRequest)
	if err != nil {
		if resp.PUContext != nil {
			state := flowstats.NewAppConnectionState(s.puID, r, authRequest, resp)
			state.Stats.Action = resp.Action
			state.Stats.PolicyID = resp.NetworkPolicyID
			s.collector.CollectFlowEvent(state.Stats)
		}
		zap.L().Debug("ext_authz egress: Access *NOT* authorized by network policy", zap.String("puID", s.puID))
		//flow.DropReason = "access not authorized by network policy"
		return createDeniedCheckResponse(rpc.PERMISSION_DENIED, envoy_type.StatusCode_Forbidden, "Access not authorized by network policy"), err
	}
	// record the flow stats
	state := flowstats.NewAppConnectionState(s.puID, r, authRequest, resp)
	// If the flow is external, then collect the stats here as the policy decision has already been made.
	if resp.External {
		defer s.collector.CollectFlowEvent(state.Stats)
	}
	if resp.Action.Rejected() {
		zap.L().Debug("ext_authz egress: Access *NOT* authorized by network policy", zap.String("puID", s.puID))
		//flow.DropReason = "access not authorized by network policy"
		return createDeniedCheckResponse(rpc.PERMISSION_DENIED, envoy_type.StatusCode_Forbidden, "Access not authorized by network policy"), nil
	}
	// now create the response and inject our identity
	zap.L().Debug("ext_authz egress: injecting header", zap.String("puID", s.puID))
	// build our identity token
	var transmittedKey []byte
	if s.secrets != nil {
		transmittedKey = s.secrets.TransmittedKey()
	} else {
		zap.L().Error("ext_authz egress:the secrerts are nil")
	}
	zap.L().Info("ext_authz egress: Request accepted for ", zap.String("dst: ", destIP))
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
