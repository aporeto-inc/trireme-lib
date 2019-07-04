package main

import (
	"context"
	"log"
	"time"

	"go.aporeto.io/trireme-lib/controller/internal/enforcer/envoyproxy/authz"

	"google.golang.org/grpc"

	"github.com/gogo/protobuf/types"
	envoy_core "go.aporeto.io/trireme-lib/third_party/generated/envoyproxy/data-plane-api/envoy/api/v2/core"
	ext_authz_v2 "go.aporeto.io/trireme-lib/third_party/generated/envoyproxy/data-plane-api/envoy/service/auth/v2"
)

func main() {
	conn, err := grpc.Dial(authz.SocketPath, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("fail to dial: %v", err)
	}
	defer conn.Close()

	c := ext_authz_v2.NewAuthorizationClient(conn)

	bgCtx := context.Background()
	ctx, cancel := context.WithTimeout(bgCtx, time.Second*5)
	defer cancel()
	resp, err := c.Check(ctx, &ext_authz_v2.CheckRequest{
		Attributes: &ext_authz_v2.AttributeContext{
			Source: &ext_authz_v2.AttributeContext_Peer{
				Address: &envoy_core.Address{
					Address: &envoy_core.Address_SocketAddress{
						SocketAddress: &envoy_core.SocketAddress{
							Protocol: envoy_core.TCP,
							Address:  "src_addr",
							PortSpecifier: &envoy_core.SocketAddress_PortValue{
								PortValue: uint32(59682),
							},
						},
					},
				},
			},
			Destination: &ext_authz_v2.AttributeContext_Peer{
				Address: &envoy_core.Address{
					Address: &envoy_core.Address_SocketAddress{
						SocketAddress: &envoy_core.SocketAddress{
							Protocol: envoy_core.TCP,
							Address:  "dest_addr",
							PortSpecifier: &envoy_core.SocketAddress_PortValue{
								PortValue: uint32(80),
							},
						},
					},
				},
				Service: "dest-service",
				Labels: map[string]string{
					"a": "b",
				},
				Principal: "spiffe-bs",
			},
			Request: &ext_authz_v2.AttributeContext_Request{
				Time: types.TimestampNow(),
				Http: &ext_authz_v2.AttributeContext_HttpRequest{
					Id:     "id",
					Method: "GET",
					Headers: map[string]string{
						"X-APORETO-KEY":  "key",
						"X-APORETO-AUTH": "auth",
					},
					Path:   "/important",
					Host:   "labbeduddel",
					Scheme: "http",
				},
			},
		},
	})
	if err != nil {
		log.Fatalf("failed to call check: %v", err)
	}

	log.Printf("%#v\n", resp)
}
