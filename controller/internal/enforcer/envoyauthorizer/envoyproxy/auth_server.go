package envoyproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
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
	fmt.Println("\n\n Auth Server started the server on: ", nl.Addr(), puID)
	go s.run(nl)

	return s, nil
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
	zap.L().Info("\n\n **** Envoy check, DIR: ", zap.Uint8("dir: ", uint8(s.direction)))
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
				fmt.Println("httpReqheader is :", httpReqHeaders, "aporeto key is:", aporetoKey)
				urlStr = httpReq.GetPath()
				method = httpReq.GetMethod()
				scheme = httpReq.GetScheme()

			}
		}
	}
	fmt.Println("in auth check, source addr: ", sourceIP, "source, dest: ", source.GetAddress().GetSocketAddress().GetAddress(), dest.GetAddress().GetSocketAddress().GetAddress())
	fmt.Println("\n\n dset port: ", destPort, "src port: ", srcPort)
	requestCookie := &http.Cookie{Name: aporetoAuthHeader, Value: aporetoAuth} // nolint errcheck
	hdr := make(http.Header)
	//URL := url.URL{}
	//hdr.Add()
	fmt.Println("\n\n Aporeto-Auth: ", aporetoAuth, "\n\n Aporeto-key: ", aporetoKey)
	hdr.Add(aporetoAuthHeader, aporetoAuth) //string(p.secrets.TransmittedKey()))
	hdr.Add(aporetoKeyHeader, aporetoKey)   //resp.Token)

	// Create the new target URL based on the method+path parameter that we had.
	fmt.Println("\n\n the method , scheme and urlStr is: ", method, scheme, urlStr)
	fmt.Println("\n\n now calling the parseURI for: ", "http:"+method+urlStr)
	URL, err := ParseRequestURI("http:" + method + urlStr)
	if err != nil {
		fmt.Println("Cannot parse the URI", err)
		return nil, nil
	}
	fmt.Println("\n\n  after the parseRequestURI: ", URL)
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
	if err != nil {
		if response == nil {
			fmt.Println("\n\n response nil")
			return createDeniedCheckResponse(rpc.PERMISSION_DENIED, envoy_type.StatusCode_Forbidden, "No aporeto service installed"), nil
		}
		return createDeniedCheckResponse(rpc.PERMISSION_DENIED, envoy_type.StatusCode_Forbidden, "Access not authorized by network policy"), nil
	}
	fmt.Println("\n\n After auth check with rejected action: ", response.Action.Rejected())
	if response.Action.Rejected() {
		zap.L().Debug("ext_authz ingress: Access *NOT* authorized by network policy", zap.String("puID", s.puID))
		//flow.DropReason = "access not authorized by network policy"
		return createDeniedCheckResponse(rpc.PERMISSION_DENIED, envoy_type.StatusCode_Forbidden, "Access not authorized by network policy"), nil
	}
	fmt.Println("\n request accepted")
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

// ParseRequestURI ...
func ParseRequestURI(rawurl string) (*url.URL, error) {
	url, err := parse(rawurl, true)
	if err != nil {
		return nil, fmt.Errorf("parse", rawurl, err)
	}
	return url, nil
}
func stringContainsCTLByte(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < ' ' || b == 0x7f {
			return true
		}
	}
	return false
}
func getscheme(rawurl string) (scheme, path string, err error) {
	for i := 0; i < len(rawurl); i++ {
		c := rawurl[i]
		switch {
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z':
		// do nothing
		case '0' <= c && c <= '9' || c == '+' || c == '-' || c == '.':
			if i == 0 {
				return "", rawurl, nil
			}
		case c == ':':
			if i == 0 {
				return "", "", errors.New("missing protocol scheme")
			}
			return rawurl[:i], rawurl[i+1:], nil
		default:
			// we have encountered an invalid character,
			// so there is no valid scheme
			return "", rawurl, nil
		}
	}
	return "", rawurl, nil
}
func split(s string, c string, cutc bool) (string, string) {
	i := strings.Index(s, c)
	if i < 0 {
		return s, ""
	}
	if cutc {
		return s[:i], s[i+len(c):]
	}
	return s[:i], s[i:]
}
func parseAuthority(authority string) (user *url.Userinfo, host string, err error) {

	return nil, "", nil
}
func parse(rawurl string, viaRequest bool) (*url.URL, error) {
	var rest string
	var err error

	if stringContainsCTLByte(rawurl) {
		return nil, errors.New("net/url: invalid control character in URL")
	}
	fmt.Println("\n\n in parse URL-1111")
	if rawurl == "" && viaRequest {
		return nil, errors.New("empty url")
	}
	url := new(url.URL)

	if rawurl == "*" {
		url.Path = "*"
		return url, nil
	}
	fmt.Println("\n\n in parse URL-2222")
	// Split off possible leading "http:", "mailto:", etc.
	// Cannot contain escaped characters.
	if url.Scheme, rest, err = getscheme(rawurl); err != nil {
		return nil, err
	}
	url.Scheme = strings.ToLower(url.Scheme)
	fmt.Println("\n\n in parse URL-3333")
	if strings.HasSuffix(rest, "?") && strings.Count(rest, "?") == 1 {
		url.ForceQuery = true
		rest = rest[:len(rest)-1]
	} else {
		rest, url.RawQuery = split(rest, "?", true)
	}
	fmt.Println("\n\n in parse URL-4444")
	if !strings.HasPrefix(rest, "/") {
		if url.Scheme != "" {
			// We consider rootless paths per RFC 3986 as opaque.
			url.Opaque = rest
			return url, nil
		}
		if viaRequest {
			return nil, errors.New("invalid URI for request")
		}
		fmt.Println("\n\n in parse URL-5555")
		// Avoid confusion with malformed schemes, like cache_object:foo/bar.
		// See golang.org/issue/16822.
		//
		// RFC 3986, §3.3:
		// In addition, a URI reference (Section 4.1) may be a relative-path reference,
		// in which case the first path segment cannot contain a colon (":") character.
		colon := strings.Index(rest, ":")
		slash := strings.Index(rest, "/")
		if colon >= 0 && (slash < 0 || colon < slash) {
			// First path segment has colon. Not allowed in relative URL.
			return nil, errors.New("first path segment in URL cannot contain colon")
		}
	}
	fmt.Println("\n\n in parse URL-6666")
	if (url.Scheme != "" || !viaRequest && !strings.HasPrefix(rest, "///")) && strings.HasPrefix(rest, "//") {
		var authority string
		authority, rest = split(rest[2:], "/", false)
		url.User, url.Host, err = parseAuthority(authority)
		if err != nil {
			return nil, err
		}
	}
	fmt.Println("\n\n in parse URL-7777")
	// Set Path and, optionally, RawPath.
	// RawPath is a hint of the encoding of Path. We don't want to set it if
	// the default escaping of Path is equivalent, to help make sure that people
	// don't rely on it in general.
	fmt.Println("setting path : ", rest)
	// if err := url.setPath(rest); err != nil {
	// 	return nil, err
	// }
	return url, nil
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

	fmt.Println("\n\n **** ABHI ext-auth Egress check, need add key and token", "\n transmitted-key: ", string(transmittedKey), "\n resp.token: ", resp.Token)
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
