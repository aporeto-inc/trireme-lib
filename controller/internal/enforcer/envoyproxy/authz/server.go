package authz

import (
	"context"
	"fmt"
	"net"
	"time"

	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/controller/pkg/servicetokens"
	"go.aporeto.io/trireme-lib/utils/cache"
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
	puContexts cache.DataStore
	secrets    secrets.LockedSecrets
	socketPath string
	server     *grpc.Server
	direction  Direction
	verifier   *servicetokens.Verifier
	collector  collector.EventCollector
}

// NewExtAuthzServer creates a new envoy ext_authz server
func NewExtAuthzServer(puID string, puContexts cache.DataStore, collector collector.EventCollector, verifier *servicetokens.Verifier, secrets secrets.LockedSecrets, direction Direction) (*Server, error) {
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
		puContexts: puContexts,
		secrets:    secrets,
		socketPath: socketPath,
		server:     grpc.NewServer(),
		direction:  direction,
		verifier:   verifier,
		collector:  collector,
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
	// TODO: needs to be removed before we merge: this exposes secret data, and must never be in real logs - even in the debug case
	zap.L().Debug("ext_authz ingress: checkRequest", zap.String("puID", s.puID))

	// get the PU context
	pctxRaw, err := s.puContexts.Get(s.puID)
	if err != nil {
		zap.L().Error("ext_authz ingress: failed to get PU context", zap.String("puID", s.puID), zap.Error(err))
		return createDeniedCheckResponse(rpc.INTERNAL, envoy_type.StatusCode_InternalServerError, "failed to get PU context"), nil
	}
	pctx, ok := pctxRaw.(*pucontext.PUContext)
	if !ok {
		zap.L().Error("ext_authz ingress: PU context has the wrong type", zap.String("puID", s.puID), zap.String("puContextType", fmt.Sprintf("%T", pctxRaw)))
		return createDeniedCheckResponse(rpc.INTERNAL, envoy_type.StatusCode_InternalServerError, "PU context has the wrong type"), nil
	}

	// extract our headers
	var aporetoKey, aporetoAuth, sourceAdress string
	var source, dest *ext_authz_v2.AttributeContext_Peer
	var httpReq *ext_authz_v2.AttributeContext_HttpRequest
	attrs := checkRequest.GetAttributes()
	if attrs != nil {
		source = attrs.GetSource()
		dest = attrs.GetDestination()

		if source != nil {
			if addr := source.GetAddress(); addr != nil {
				if sockAddr := addr.GetSocketAddress(); sockAddr != nil {
					sourceAdress = sockAddr.GetAddress()
				}
			}
		}

		if request := attrs.GetRequest(); request != nil {
			httpReq = request.GetHttp()
			if httpReq != nil {
				httpReqHeaders := httpReq.GetHeaders()
				if httpReqHeaders != nil {
					aporetoKey, _ = httpReqHeaders[aporetoKeyHeader]
					aporetoAuth, _ = httpReqHeaders[aporetoAuthHeader]
				}
			}
		}
	}

	flow := newIngressFlowRecord(s.puID, pctx, source, dest, httpReq)
	defer func() {
		zap.L().Debug("ext_authz ingress: collecting flow event", zap.String("puID", s.puID), zap.Any("flow", flow))
		s.collector.CollectFlowEvent(flow)
	}()

	// if the request is lacking our stuff, we send a 400 back
	if aporetoAuth == "" || aporetoKey == "" {
		zap.L().Warn("ext_authz ingress: request missing Aporeto HTTP headers: x-aporeto-key and/or x-aporeto-auth", zap.String("puID", s.puID), zap.String("sourceAddress", sourceAdress))
		flow.DropReason = "missing Aporeto HTTP headers"
		return createDeniedCheckResponse(rpc.INVALID_ARGUMENT, envoy_type.StatusCode_BadRequest, "missing headers X-APORETO-KEY or X-APORETO-AUTH"), nil
	}

	// now we can see if we can decode our claims
	srcid, scopes, profile, err := s.verifier.ParseToken(aporetoAuth, aporetoKey)
	if err != nil {
		zap.L().Debug("ext_authz ingress: failed to parse Aporeto token", zap.String("puID", s.puID), zap.Error(err))
		flow.DropReason = "failed to parse Aporeto token"
		return createDeniedCheckResponse(rpc.PERMISSION_DENIED, envoy_type.StatusCode_Forbidden, "failed to parse Aporeto token"), nil
	}
	zap.L().Debug("ext_authz ingress: parsed Aporeto token", zap.String("puID", s.puID), zap.String("srcid", srcid), zap.Strings("scopes", scopes), zap.Strings("profile", profile))
	flow.Source.ID = srcid

	observedPolicy, netPolicy := pctx.SearchRcvRules(policy.NewTagStoreFromSlice(profile))
	flow.Action = netPolicy.Action
	flow.PolicyID = netPolicy.PolicyID
	flow.ObservedAction = observedPolicy.Action
	flow.ObservedPolicyID = observedPolicy.PolicyID

	if netPolicy.Action.Rejected() {
		zap.L().Debug("ext_authz ingress: Access *NOT* authorized by network policy", zap.String("puID", s.puID))
		flow.DropReason = "access not authorized by network policy"
		return createDeniedCheckResponse(rpc.PERMISSION_DENIED, envoy_type.StatusCode_Forbidden, "Access not authorized by network policy"), nil
	}

	// otherwise we are just going to allow it for now
	zap.L().Debug("ext_authz ingress: Access authorized by network policy", zap.String("puID", s.puID))
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
	zap.L().Debug("ext_authz egress: checkRequest", zap.String("puID", s.puID), zap.String("checkRequest", checkRequest.String()))

	// get the PU context
	pctxRaw, err := s.puContexts.Get(s.puID)
	if err != nil {
		zap.L().Error("ext_authz egress: failed to get PU context", zap.String("puID", s.puID), zap.Error(err))
		return createDeniedCheckResponse(rpc.INTERNAL, envoy_type.StatusCode_InternalServerError, "failed to get PU context"), nil
	}
	pctx, ok := pctxRaw.(*pucontext.PUContext)
	if !ok {
		zap.L().Error("ext_authz egress: PU context has the wrong type", zap.String("puID", s.puID), zap.String("puContextType", fmt.Sprintf("%T", pctxRaw)))
		return createDeniedCheckResponse(rpc.INTERNAL, envoy_type.StatusCode_InternalServerError, "PU context has the wrong type"), nil
	}

	var sourceAdress string
	var source, dest *ext_authz_v2.AttributeContext_Peer
	var httpReq *ext_authz_v2.AttributeContext_HttpRequest
	attrs := checkRequest.GetAttributes()
	if attrs != nil {
		source = attrs.GetSource()
		dest = attrs.GetDestination()

		if source != nil {
			if addr := source.GetAddress(); addr != nil {
				if sockAddr := addr.GetSocketAddress(); sockAddr != nil {
					sourceAdress = sockAddr.GetAddress()
				}
			}
		}

		if request := attrs.GetRequest(); request != nil {
			httpReq = request.GetHttp()
		}
	}

	flow := newEgressFlowRecord(s.puID, pctx, source, dest, httpReq)
	// TODO: only collect the flow when this is an external event
	//defer func() {
	//	zap.L().Debug("ext_authz egress: collecting flow event", zap.String("puID", s.puID), zap.Any("flow", flow))
	//	s.collector.CollectFlowEvent(flow)
	//}()

	observedPolicy, netPolicy := pctx.SearchTxtRules(policy.NewTagStoreFromSlice(pctx.Identity().Tags), false)
	flow.Action = netPolicy.Action
	flow.PolicyID = netPolicy.PolicyID
	flow.ObservedAction = observedPolicy.Action
	flow.ObservedPolicyID = observedPolicy.PolicyID

	// TODO: we can actually already deny the outgoing request here based on policy

	// build our identity token
	secrets, unlockSecrets := s.secrets.Secrets()
	defer unlockSecrets()
	transmittedKey := secrets.TransmittedKey()
	token, err := servicetokens.CreateAndSign(
		sourceAdress,
		pctx.Identity().Tags,
		pctx.Scopes(),
		pctx.ManagementID(),
		defaultValidity,
		secrets.EncodingKey(),
	)
	if err != nil {
		zap.L().Error("ext_authz egress: cannot create token", zap.Error(err))
		flow.DropReason = "cannot create Aporeto token"
		return createDeniedCheckResponse(rpc.INTERNAL, envoy_type.StatusCode_InternalServerError, "cannot create Aporeto token"), nil
	}

	// now create the response and inject our identity
	zap.L().Debug("ext_authz egress: injecting header", zap.String("puID", s.puID))
	flow.Action = policy.Accept
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
							Value: string(transmittedKey),
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

func createDeniedCheckResponse(rpcCode rpc.Code, httpCode envoy_type.StatusCode, body string) *ext_authz_v2.CheckResponse {
	return &ext_authz_v2.CheckResponse{
		Status: &rpc.Status{
			Code: int32(rpcCode),
		},
		HttpResponse: &ext_authz_v2.CheckResponse_DeniedResponse{
			DeniedResponse: &ext_authz_v2.DeniedHttpResponse{
				Status: &envoy_type.HttpStatus{
					Code: httpCode,
				},
				Body: body,
			},
		},
	}
}

// newIngressFlowRecord will create the initial flow record for ingress connections
func newIngressFlowRecord(puID string, pu *pucontext.PUContext, src, dest *ext_authz_v2.AttributeContext_Peer, req *ext_authz_v2.AttributeContext_HttpRequest) *collector.FlowRecord {
	var uri, method, destIP, srcIP, serviceID string
	var destPort, srcPort int

	if src != nil {
		if srcAddr := src.GetAddress(); srcAddr != nil {
			if srcSockAddr := srcAddr.GetSocketAddress(); srcSockAddr != nil {
				srcIP = srcSockAddr.GetAddress()
				srcPort = int(srcSockAddr.GetPortValue())
			}
		}
	}

	if dest != nil {
		serviceID = dest.GetService()
		if destAddr := dest.GetAddress(); destAddr != nil {
			if destSockAddr := destAddr.GetSocketAddress(); destSockAddr != nil {
				destIP = destSockAddr.GetAddress()
				destPort = int(destSockAddr.GetPortValue())
			}
		}
	}

	if req != nil {
		method = req.GetMethod()
		uri = method + " " + req.GetPath()
	}

	return &collector.FlowRecord{
		ContextID: puID,
		Destination: &collector.EndPoint{
			ID:         pu.ManagementID(),
			Type:       collector.EnpointTypePU,
			IP:         destIP,
			Port:       uint16(destPort),
			HTTPMethod: method,
			URI:        uri,
		},
		Source: &collector.EndPoint{
			ID:         collector.DefaultEndPoint,
			Type:       collector.EnpointTypePU, // TODO: should actually be collector.EndPointTypeExternalIP
			IP:         srcIP,
			Port:       uint16(srcPort),
			HTTPMethod: method,
			URI:        uri,
		},
		Action:      policy.Reject,
		L4Protocol:  packet.IPProtocolTCP,
		ServiceType: policy.ServiceHTTP,
		PolicyID:    "default",
		ServiceID:   serviceID,
		Tags:        pu.Annotations(),
		Namespace:   pu.ManagementNamespace(),
		Count:       1,
	}
}

// newEgressFlowRecord will create the initial flow record for egress connections
func newEgressFlowRecord(puID string, pu *pucontext.PUContext, src, dest *ext_authz_v2.AttributeContext_Peer, req *ext_authz_v2.AttributeContext_HttpRequest) *collector.FlowRecord {
	var serviceID, destIP, srcIP, method, uri string
	var destPort, srcPort int

	srcIP = "0.0.0.0/0"

	if src != nil {
		serviceID = src.GetService()
		if srcAddr := src.GetAddress(); srcAddr != nil {
			if srcSockAddr := srcAddr.GetSocketAddress(); srcSockAddr != nil {
				srcIP = srcSockAddr.GetAddress()
				srcPort = int(srcSockAddr.GetPortValue())
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

	if req != nil {
		method = req.GetMethod()
		uri = method + " " + req.GetPath()
	}

	return &collector.FlowRecord{
		ContextID: puID,
		Destination: &collector.EndPoint{
			ID:         collector.DefaultEndPoint,
			Type:       collector.EndPointTypeExternalIP,
			IP:         destIP,
			Port:       uint16(destPort),
			HTTPMethod: method,
			URI:        uri,
		},
		Source: &collector.EndPoint{
			ID:         pu.ManagementID(),
			Type:       collector.EnpointTypePU,
			IP:         srcIP,
			Port:       uint16(srcPort),
			HTTPMethod: method,
			URI:        uri,
		},
		Action:      policy.Reject,
		L4Protocol:  packet.IPProtocolTCP,
		ServiceType: policy.ServiceHTTP,
		ServiceID:   serviceID,
		Tags:        pu.Annotations(),
		Namespace:   pu.ManagementNamespace(),
		PolicyID:    "default",
		Count:       1,
	}
}
