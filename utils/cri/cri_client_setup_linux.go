// +build linux

package cri

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"

	"go.aporeto.io/enforcerd/internal/utils"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	criruntimev1alpha2 "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
)

// These are defined like this by Kubernetes. The kubelet will search for them exactly like this.
const (
	criDockerShimEndpoint = "/var/run/dockershim.sock"
	criContainerdEndpoint = "/run/containerd/containerd.sock"
	criCrioEndpoint       = "/var/run/crio/crio.sock"
)

var (
	nopFunc = func(path string) string { return path }

	// the following function was earlier utils.GetPathOnHostViaProcRoot but bow that we have proper mounts
	// we will make it a NOP operation.
	getHostPath = nopFunc
)

// ParseStringFlag parses a flag from a given command
func ParseStringFlag(cmd string, flagRegexp string) *string {
	flags := ParseStringFlags(cmd, flagRegexp)
	if len(flags) > 0 {
		return &flags[0]
	}
	return nil
}

// flagTemplate captures CLI flags (i.e., 'cmd --some-flag=value', 'cmd --some-flag value', 'cmd --some-flag=valA --some-flag=valB')
const flagTemplate = `(?:%s)(?:=|\s+)(\S+)`

// ParseStringFlags parses a list of flags from a given command
func ParseStringFlags(cmd string, flagRegexp string) []string {
	var res []string
	expression := fmt.Sprintf(flagTemplate, flagRegexp)
	matches := regexp.MustCompile(expression).FindAllStringSubmatch(cmd, -1)
	for _, tokens := range matches {
		if len(tokens) > 1 {
			res = append(res, strings.Trim(tokens[1], `"'`))
		}
	}
	return res
}

// BuildProcessRegex returns a regex that should match processes with a name matching the given process regular
// expression
// Remark: procExpression can be a regular expression
func BuildProcessRegex(procExpression string) *regexp.Regexp {
	// Expressions that should be matched by a given procname are:
	// procname -flag1 -flag2
	// /bin/procname -flag1 -flag2
	// /procname -flag1 -flag2
	//
	// Expressions that should NOT be matched are:
	// notprocname -flag1 -flag2
	// /bin/notprocname -flag1 -flag2
	// /bin/procname/notprocname -flag1 -flag2
	// notprocname -flag1 procname
	// notprocname -flag1 -procname
	return regexp.MustCompile(fmt.Sprintf(`^(\S*/)?(%s)( |$)`, procExpression))
}

// KubeletProcessRegex is the kubelet process regex used to find the kubelet process
// Sometimes it is not the kubelet binary that is used in the system (e.g. Openshift4) but k8s' all-in-one binary: https://github.com/kubernetes/kubernetes/tree/master/cluster/images/hyperkube
// The following is an example of a kubelet cmdline in Openshift4:
// /usr/bin/hyperkube kubelet --config=/etc/kubernetes/kubelet.conf --bootstrap-kubeconfig=/etc/kubernete s/kubeconfig --rotate-certificates --kubeconfig=/var/lib/kubelet/kubeconfig --container-runtime=remote --container-runtime-endpoint=/var/run/crio/crio.s ock --allow-privileged --node-labels=node-role.kubernetes.io/master --minimum-container-ttl-duration=6m0s --client-ca-file=/etc/kubernetes/ca.crt --clou d-provider=aws --anonymous-auth=false --register-with-taints=node-role.kubernetes.io/master=:NoSchedule
var KubeletProcessRegex = BuildProcessRegex("(hyperkube )?kubelet")

// CriSocket returns the CRI socket path used by kubelet
func CriSocket() (string, error) { //nolint
	procs, err := utils.Processes()
	if err != nil {
		return "", fmt.Errorf("failed to list processes: %v", err)
	}
	for _, proc := range procs {
		if KubeletProcessRegex.MatchString(proc.Cmdline) {
			if sock := ParseStringFlag(proc.Cmdline, "--container-runtime-endpoint"); sock != nil {
				return strings.TrimPrefix(*sock, "unix://"), nil
			}
		}
	}
	return "", nil
}

// DetectCRIRuntimeEndpoint checks if the unix socket path are present for CRI
func DetectCRIRuntimeEndpoint() (string, Type, error) {
	var retErr error
	isUDSocket := func(path string) (string, error) {
		fileInfo, err := os.Stat(path)
		if err != nil {
			return "", fmt.Errorf("%s not a socket", path)
		}
		if !(fileInfo.Mode()&os.ModeSocket == os.ModeSocket) {
			return "", fmt.Errorf("%s not a socket", path)
		}
		return "unix://" + path, nil

	}
	runtimes := []string{criDockerShimEndpoint, criContainerdEndpoint, criCrioEndpoint}
	existingCriSockets := []string{}

	for _, p := range runtimes {
		path := getHostPath(p)
		if addr, err := isUDSocket(path); err == nil {
			zap.L().Debug("cri: detected CRI runtime service socket address", zap.String("socketPathAddress", addr))
			existingCriSockets = append(existingCriSockets, addr)
		} else {
			retErr = err
			zap.L().Debug("cri: socket path unavailable/inaccessible", zap.String("socketPath", path), zap.Error(err))
		}
	}
	zap.L().Debug("The CRI sockets found are:", zap.Strings("paths", existingCriSockets))
	if len(existingCriSockets) > 1 {
		// this should ideally not happen but if it happens then get the kubelet cmdLine CRI
		// now check for the kubelet runtime
		sockaddr, err := CriSocket()
		if err != nil {
			return sockaddr, getCRISocketAddrType(sockaddr), fmt.Errorf("Multiple detection of CRI runtime endpoints, failed to get socketPath from kubelet")
		}
		// If there is no CRI EP on kubelet that means docker is the default, because kubelet's default CRI is docker.
		if sockaddr == "" {
			return getHostPath(criDockerShimEndpoint), TypeDocker, nil
		}
		return sockaddr, getCRISocketAddrType(sockaddr), nil
	} else if len(existingCriSockets) == 1 {
		return existingCriSockets[0], getCRISocketAddrType(existingCriSockets[0]), nil
	}
	// no CRI endpoint present on the system/node, this can happen during restarts
	return "", TypeNone, fmt.Errorf("auto detection of CRI runtime endpoints failed, tested common locations %s, %s", strings.Join(runtimes, ", "), retErr)
}

func getCRISocketAddrType(sockaddr string) Type {
	if strings.Contains(sockaddr, "crio") {
		return TypeCRIO
	}
	if strings.Contains(sockaddr, "containerd") {
		return TypeContainerD
	}
	if strings.Contains(sockaddr, "docker") {
		return TypeDocker
	}
	return TypeNone
}

func getCRISocketAddr(criRuntimeEndpoint string) (string, error) {
	var err error
	addr := criRuntimeEndpoint
	if addr == "" {
		addr, _, err = DetectCRIRuntimeEndpoint()
		if err != nil {
			return "", err
		}
	}
	if strings.HasPrefix(addr, "tcp:") {
		return "", fmt.Errorf("tcp endpoints are not supported")
	}
	if !strings.HasPrefix(addr, "unix:") {
		addr = "unix://" + addr
	}
	addr = path.Clean(addr)

	if strings.Contains(addr, "frakti") {
		return "", fmt.Errorf("frakti runtime is not supported")
	}

	u, err := url.Parse(addr)
	if err != nil {
		return "", err
	}
	if u.Scheme != "unix" {
		return "", fmt.Errorf("only unix sockets are supported")
	}

	// NOTE: convoluted, but makes unix socket paths and abstract unix socket socket URLs in gRPC connotation both work.
	// The trouble is that u.Path is only set for "proper" unix socket, and the rest is in u.Opaque
	// This strips "unix:" from the URL again as well as any following potential "//",
	// leaving a single '/' if this was a 'unix:///var/run/...' address
	return strings.TrimPrefix(strings.TrimPrefix(addr, "unix:"), "//"), nil
}

func connectCRISocket(ctx context.Context, addr string) (*grpc.ClientConn, error) {
	var err error
	var connection *grpc.ClientConn

	ctx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()

	connection, err = grpc.DialContext(
		ctx,
		addr,
		// we want to wait for an initial connection
		grpc.WithBlock(),
		// we do everything like the kubelet: we bump this up to 16MB
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxMsgSize)),
		// unix socket connection, disable transport security
		grpc.WithInsecure(),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", addr)
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("connection to CRI runtime service failed: %s", err.Error())
	}
	return connection, nil
}

// NewCRIRuntimeServiceClient takes a CRI socket path and tries to establish a grpc connection to the CRI runtime service.
// On success it is returning an ExtendedRuntimeService interface which is an extended CRI runtime service interface.
func NewCRIRuntimeServiceClient(ctx context.Context, criRuntimeEndpoint string) (ExtendedRuntimeService, error) {
	// build the socket path URL
	addr, err := getCRISocketAddr(criRuntimeEndpoint)
	if err != nil {
		return nil, fmt.Errorf("cri: failed to get socket address: %s", err)
	}

	// establish the CRI connection
	// once this connection has been established
	// gRPC will take care of reconnections, etc.
	// connections are very much hands-off after that point
	connection, err := connectCRISocket(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("cri: failed to connect to CRI socket: %s", err)
	}

	// finally create the extended wrapper
	svc, err := NewCRIExtendedRuntimeServiceWrapper(
		ctx,
		callTimeout,
		criruntimev1alpha2.NewRuntimeServiceClient(connection),
	)
	if err != nil {
		return nil, fmt.Errorf("faile to create extended runtime service wrapper: %s", err.Error())
	}

	// and return with it
	return svc, nil
}
