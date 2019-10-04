package cri

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"google.golang.org/grpc"
	criruntimev1alpha2 "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
)

const (
	criDockerShimEndpoint = "/var/run/dockershim.sock"
	criContainerdEndpoint = "/run/containerd/containerd.sock"
	criCrioEndpoint       = "/var/run/crio/crio.sock"
)

func detectCRIRuntimeEndpoint() (string, error) {

	testPath := func(path string) (string, error) {
		_, err := os.Stat(path)
		if err == nil {
			return "unix://" + path, nil
		}
		return "", fmt.Errorf("%s not a socket", path)
	}
	runtimes := []string{criDockerShimEndpoint, criContainerdEndpoint, criCrioEndpoint}

	for _, path := range runtimes {
		if addr, err := testPath(path); err == nil {
			return addr, nil
		}
	}

	return "", fmt.Errorf("auto detection of CRI runtime endpoints failed, tested common locations %s", strings.Join(runtimes, ", "))
}

// NewCRIRuntimeServiceClient takes a CRI socket path and tries to establish a grpc connection to the CRI runtime service.
// On success it is returning an ExtendedRuntimeService interface which is an extended CRI runtime service interface.
func NewCRIRuntimeServiceClient(criRuntimeEndpoint string) (ExtendedRuntimeService, error) {
	var err error
	addr := criRuntimeEndpoint
	if addr == "" {
		addr, err = detectCRIRuntimeEndpoint()
		if err != nil {
			return nil, err
		}
	}
	if strings.HasPrefix(addr, "tcp:") {
		return nil, fmt.Errorf("tcp endpoints are not supported")
	}
	if !strings.HasPrefix(addr, "unix:") {
		addr = "unix://" + addr
	}
	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}
	addr = path.Clean(u.Path)

	if strings.Contains(addr, "frakti") {
		return nil, fmt.Errorf("frakti runtime is not supported")
	}

	timeout := time.Second * 5
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var connection *grpc.ClientConn
	connection, err = grpc.DialContext(
		ctx,
		addr,
		// unix socket connection, disable transport security
		grpc.WithInsecure(),
		grpc.WithDialer(func(a string, t time.Duration) (net.Conn, error) {
			return net.DialTimeout("unix", a, t)
		}),
		// we do everything like the kubelet: we bump this up to 16MB
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(16777216)),
	)
	if err != nil {
		// if the context was canceled or the deadline exceeded, try again with GRPC_GO_REQUIRE_HANDSHAKE=off
		if err == context.Canceled || err == context.DeadlineExceeded {
			if err := os.Setenv("GRPC_GO_REQUIRE_HANDSHAKE", "off"); err != nil {
				return nil, fmt.Errorf("connection to CRI runtime failed, and cannot set GRPC_GO_REQUIRE_HANDSHAKE=off")
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			connection, err = grpc.DialContext(
				ctx,
				addr,
				// unix socket connection, disable transport security
				grpc.WithInsecure(),
				grpc.WithDialer(func(a string, t time.Duration) (net.Conn, error) {
					return net.DialTimeout("unix", a, t)
				}),
				// we do everything like the kubelet: we bump this up to 16MB
				grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(16777216)),
			)
			if err != nil {
				return nil, fmt.Errorf("connection to CRI runtime failed, even with GRPC_GO_REQUIRE_HANDSHAKE=off: %s", err.Error())
			}
		}
		return nil, fmt.Errorf("connection to CRI runtime failed: %s", err.Error())
	}

	svc, err := NewCRIExtendedRuntimeServiceWrapper(
		time.Second*5,
		criruntimev1alpha2.NewRuntimeServiceClient(connection),
	)
	if err != nil {
		return nil, fmt.Errorf("faile to create extended runtime service wrapper: %s", err.Error())
	}

	return svc, nil
}
