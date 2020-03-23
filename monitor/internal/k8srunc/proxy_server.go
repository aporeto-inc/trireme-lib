package k8sruncmonitor

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/mheese/runc-wrapper/protos"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/monitor/config"
	"go.aporeto.io/trireme-lib/monitor/extractors"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/cri"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/opencontainers/runc/libcontainer"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

const (
	// RuncProxySocket is used by the Aporeto Kubernetes monitor
	RuncProxySocket = "/var/run/aporeto.runc.sock"
)

var _ protos.RuncProxyServer = &RuncProxyServer{}

// RuncProxyServer implements the interception server part of the runc wrapper
type RuncProxyServer struct {
	server            *grpc.Server
	c                 *kubernetes.Clientset
	rs                cri.ExtendedRuntimeService
	metadataExtractor extractors.PodMetadataExtractor
	handler           *config.ProcessorConfig
	stopped           bool
}

// NewRuncProxyServer instantiates a gRPC server which can serve the RuncProxy service
func NewRuncProxyServer(handler *config.ProcessorConfig, rs cri.ExtendedRuntimeService, c *kubernetes.Clientset, metadataExtractor extractors.PodMetadataExtractor) *RuncProxyServer {
	s := &RuncProxyServer{
		server:            grpc.NewServer(),
		handler:           handler,
		rs:                rs,
		c:                 c,
		metadataExtractor: metadataExtractor,
	}

	protos.RegisterRuncProxyServer(s.server, s)

	// Register reflection service on gRPC server.
	reflection.Register(s.server)

	return s
}

// Stop stops the server gRPC server gracefully. It stops the server from
// accepting new connections and RPCs and blocks until all the pending RPCs are
// finished.
func (s *RuncProxyServer) Stop() {
	s.stopped = true
	s.server.GracefulStop()
}

// ListenAndServe runs the server
func (s *RuncProxyServer) ListenAndServe() error {
	// Cleanup previous created socket if exists.
	os.RemoveAll(RuncProxySocket)

	// Create the runc server unix socket listener used to communicate with
	// runc wrapper.
	l, err := net.Listen("unix", RuncProxySocket)
	if err != nil {
		return err
	}
	// Ensure socket has root-only permissions
	if err := os.Chmod(RuncProxySocket, 0600); err != nil {
		return err
	}
	if err = s.server.Serve(l); !s.stopped {
		return err
	}

	return nil
}

// ContainerCreated is not supported with this server
func (s *RuncProxyServer) ContainerCreated(context.Context, *protos.CreateRequest) (*protos.CreateResponse, error) {
	return nil, fmt.Errorf("method ContainerCreated not supported on this server")
}

// ContainerCreatedPost is called after a successful call to 'runc create'
func (s *RuncProxyServer) ContainerCreatedPost(ctx context.Context, req *protos.CreatePostRequest) (*protos.CreatePostResponse, error) {
	var err error
	ret := &protos.CreatePostResponse{
		Failed:  false,
		Message: "",
	}
	containerID := req.GetContainerID()
	flags := req.GetFlags()
	zap.L().Info("k8srunc: runc create: ContainerCreatedPost", zap.String("containerID", containerID), zap.Any("flags", flags))

	// load the OCI container first and get its state
	root := "/run/runc"
	if rootFlag, ok := flags["--root"]; ok {
		root = rootFlag
	}
	f, err := libcontainer.New("/proc/1/root" + root)
	if err != nil {
		zap.L().Error("k8srunc: runc create: failed to create libcontainer factory", zap.String("containerID", containerID), zap.Error(err))
		return ret, nil
	}
	c, err := f.Load(containerID)
	if err != nil {
		zap.L().Error("k8srunc: runc create: failed to load container", zap.String("containerID", containerID), zap.Error(err))
		return ret, nil
	}
	st, err := c.OCIState()
	if err != nil {
		zap.L().Error("k8srunc: runc create: failed to get OCI state", zap.String("containerID", containerID), zap.Error(err))
		return ret, nil
	}

	// get our Kubernetes markers
	name, ok := st.Annotations["io.kubernetes.pod.name"]
	if !ok {
		zap.L().Error("k8srunc: runc create: failed to get pod name", zap.String("containerID", containerID))
		return ret, nil
	}
	namespace, ok := st.Annotations["io.kubernetes.pod.namespace"]
	if !ok {
		zap.L().Error("k8srunc: runc create: failed to get pod namespace", zap.String("containerID", containerID))
		return ret, nil
	}
	uid, ok := st.Annotations["io.kubernetes.pod.uid"]
	if !ok {
		zap.L().Error("k8srunc: runc create: failed to get pod UID", zap.String("containerID", containerID))
		return ret, nil
	}
	// "io.kubernetes.container.name": "POD",
	// this decides if this is a sandbox or not
	containerName, ok := st.Annotations["io.kubernetes.container.name"]
	if !ok {
		zap.L().Error("k8srunc: runc create: failed to get container name of pod", zap.String("containerID", containerID))
		return ret, nil
	}
	if containerName != "POD" {
		zap.L().Debug("k8srunc: runc create: container is not a sandbox. Nothing to do here", zap.String("containerID", containerID))
		return ret, nil
	}
	zap.L().Debug("k8srunc: runc create: container is sandbox", zap.String("containerID", containerID), zap.String("name", name), zap.String("namespace", namespace), zap.String("uid", uid))

	// Kubernetes API call to get the API pod object
	// TODO: we might be okay to get everything done without an API call
	pod, err := s.c.CoreV1().Pods(namespace).Get(name, metav1.GetOptions{})
	if err != nil {
		zap.L().Error("k8srunc: runc create: failed to get pod from Kubernetes API", zap.String("containerID", containerID), zap.String("name", name), zap.String("namespace", namespace), zap.String("uid", uid), zap.Error(err))
		return ret, nil
	}

	pu, err := s.metadataExtractor(ctx, pod, true)
	if err != nil {
		zap.L().Error("k8srunc: runc create: failed to extract metadata", zap.String("containerID", containerID), zap.String("name", name), zap.String("namespace", namespace), zap.String("uid", uid), zap.Error(err))
		return ret, nil
	}

	//todo: net_cls programming for host network

	if err := s.handler.Policy.HandlePUEvent(ctx, uid, common.EventStart, pu); err != nil {
		zap.L().Error("k8srunc: runc create: failed to start PU", zap.String("containerID", containerID), zap.String("name", name), zap.String("namespace", namespace), zap.String("uid", uid), zap.Error(err))
		return ret, nil
	}

	return ret, nil
}

// ContainerDeletedPost is called after a successful call to 'runc delete'
func (s *RuncProxyServer) ContainerDeletedPost(ctx context.Context, req *protos.DeletePostRequest) (*protos.DeletePostResponse, error) {
	var err error
	ret := &protos.DeletePostResponse{
		Failed:  false,
		Message: "",
	}

	containerID := req.GetContainerID()
	flags := req.GetFlags()
	zap.L().Debug("k8srunc: runc delete: ContainerDeletedPost", zap.String("containerID", containerID), zap.Any("flags", flags))

	// load the OCI container first and get its state
	root := "/run/runc"
	if rootFlag, ok := flags["--root"]; ok {
		root = rootFlag
	}
	f, err := libcontainer.New("/proc/1/root" + root)
	if err != nil {
		zap.L().Error("k8srunc: runc delete: failed to create libcontainer factory", zap.String("containerID", containerID), zap.Error(err))
		return ret, nil
	}
	c, err := f.Load(containerID)
	if err != nil {
		zap.L().Error("k8srunc: runc delete: failed to load container", zap.String("containerID", containerID), zap.Error(err))
		return ret, nil
	}
	st, err := c.OCIState()
	if err != nil {
		zap.L().Error("k8srunc: runc delete: failed to get OCI state", zap.String("containerID", containerID), zap.Error(err))
		return ret, nil
	}

	// get our Kubernetes markers
	name, ok := st.Annotations["io.kubernetes.pod.name"]
	if !ok {
		zap.L().Error("k8srunc: runc delete: failed to get pod name", zap.String("containerID", containerID))
		return ret, nil
	}
	namespace, ok := st.Annotations["io.kubernetes.pod.namespace"]
	if !ok {
		zap.L().Error("k8srunc: runc delete: failed to get pod namespace", zap.String("containerID", containerID))
		return ret, nil
	}
	uid, ok := st.Annotations["io.kubernetes.pod.uid"]
	if !ok {
		zap.L().Error("k8srunc: runc delete: failed to get pod UID", zap.String("containerID", containerID))
		return ret, nil
	}
	// "io.kubernetes.container.name": "POD",
	// this decides if this is a sandbox or not
	containerName, ok := st.Annotations["io.kubernetes.container.name"]
	if !ok {
		zap.L().Error("k8srunc: runc delete: failed to get container name of pod", zap.String("containerID", containerID))
		return ret, nil
	}
	if containerName != "POD" {
		zap.L().Debug("k8srunc: runc delete: container is not a sandbox. Nothing to do here", zap.String("containerID", containerID))
		return ret, nil
	}
	zap.L().Debug("k8srunc: runc delete: container is sandbox", zap.String("containerID", containerID), zap.String("name", name), zap.String("namespace", namespace), zap.String("uid", uid))

	if err := s.handler.Policy.HandlePUEvent(ctx, uid, common.EventDestroy, policy.NewPURuntimeWithDefaults()); err != nil {
		zap.L().Error("k8srunc: runc delete: failed to start PU", zap.String("containerID", containerID), zap.String("name", name), zap.String("namespace", namespace), zap.String("uid", uid), zap.Error(err))
		return ret, nil
	}
	return ret, nil
}
