package server

import (
	"context"
	"fmt"
	"sync"

	"time"

	"github.com/golang/protobuf/ptypes/empty"
	"go.aporeto.io/enforcerd/internal/extractors/containermetadata"
	"go.aporeto.io/enforcerd/trireme-lib/common"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/counters"
	monitorpb "go.aporeto.io/enforcerd/trireme-lib/monitor/api/spec/protos"
	"go.aporeto.io/enforcerd/trireme-lib/monitor/constants"
	"go.aporeto.io/enforcerd/trireme-lib/monitor/external"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

var _ Controls = &Server{}

var _ external.ReceiverRegistration = &Server{}

var _ monitorpb.CNIServer = &Server{}
var _ monitorpb.RunCServer = &Server{}

// Controls is the controlling interface for starting/stopping the server
type Controls interface {
	Start(context.Context) error
	Stop() error
}

// Server is the grpcMonitorServer server
type Server struct {
	ctx                             context.Context
	enforcerID                      string
	stop                            chan struct{}
	enforcerStop                    chan struct{}
	socketAddress                   string
	socketType                      int
	running                         bool
	monitors                        map[string]external.ReceiveEvents
	monitorsLock                    sync.RWMutex
	runcProxyStarted                bool
	cniInstalled                    bool
	notifyProcessRuncProxyStartedCh chan struct{}
	notifyProcessCniInstalledCh     chan struct{}
	extMonitorStartedLock           sync.RWMutex
	waitStopGrp                     sync.WaitGroup
	apoRuncWaitGrp                  *sync.WaitGroup
}

const (
	socketTypeUnix = iota
	socketTypeTCP  // nolint: varcheck
	socketTypeWindowsNamedPipe
)

// NewMonitorServer creates a gRPC server for the twistlock defender integration
func NewMonitorServer(
	socketAddress string,
	stopchan chan struct{},
	enforcerID string,
	runcWaitGrp *sync.WaitGroup,
) *Server {
	return &Server{
		enforcerID:                      enforcerID,
		stop:                            make(chan struct{}),
		enforcerStop:                    stopchan,
		socketAddress:                   socketAddress,
		socketType:                      socketTypeUnix,
		running:                         false,
		monitors:                        make(map[string]external.ReceiveEvents),
		notifyProcessRuncProxyStartedCh: make(chan struct{}),
		notifyProcessCniInstalledCh:     make(chan struct{}),
		waitStopGrp:                     sync.WaitGroup{},
		apoRuncWaitGrp:                  runcWaitGrp,
	}
}

// Start the grpcMonitorServer gRPC server
func (s *Server) Start(ctx context.Context) (err error) {

	s.ctx = ctx

	errChan := make(chan error)
	zap.L().Info("Starting the gRPC Monitor server, listening on", zap.String("address", s.socketAddress))

	if err := cleanupPipe(s.socketAddress); err != nil {
		zap.L().Fatal("unable to cleanup the old gRPC Monitor server socket address", zap.String("address", s.socketAddress), zap.Error(err))
	}

	// create the listener
	lis, err := makePipe(s.socketAddress)
	if err != nil {
		zap.L().Fatal("Failed to create the listener socket", zap.String("address", s.socketAddress), zap.Error(err))
	}

	var opts []grpc.ServerOption

	// TODO - TLS certs for the gRPC connection ??
	// if tls {
	// 	creds, err := credentials.NewServerTLSFromFile(tls.certFile, tls.keyFile)
	// 	if err != nil {
	// 		zap.L().Fatal("Failed to load TLS credentials %v", zap.Error(err))
	// 	}
	//
	// 	opts = []grpc.ServerOption{grpc.Creds(creds)}
	// }

	grpcServer := grpc.NewServer(opts...)

	// now register the runc and CNI servers.
	monitorpb.RegisterCNIServer(grpcServer, s)
	monitorpb.RegisterRunCServer(grpcServer, s)
	zap.L().Debug("Starting the gRPC Monitor' server loop")

	go s.processExtMonitorStarted(ctx)

	// run blocking call in a separate goroutine, report errors via channel
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			zap.L().Error("failed to start the gRPC Monitor' server", zap.Error(err))
			errChan <- err
		}
		zap.L().Debug("Exiting gRPC Monitor' server go func")

		// the listener should be closed by this time, remove it
		if s.socketType == socketTypeUnix || s.socketType == socketTypeWindowsNamedPipe {
			if err := cleanupPipe(s.socketAddress); err != nil {
				zap.L().Error("unable to cleanup the gRPC Monitor' server socket address", zap.String("address", s.socketAddress), zap.Error(err))
				errChan <- err
			}
		}
	}()
	// add the waitGrp to make sure that the GRPC shuts down graceFully.
	s.waitStopGrp.Add(1)

	// Start() is non-blocking, but we block in the go routine
	// until either OS signal, or server fatal error
	go func() {

		s.running = true
		zap.L().Debug("the gRPC Monitor' server loop is running")

		// terminate gracefully
		defer func() {
			zap.L().Debug("Stopping the gRPC Monitor' server loop and listener socket")
			grpcServer.GracefulStop()
			// now we are sure that the connections have been drained completely.
			s.waitStopGrp.Done()
			s.running = false
		}()

		for {
			select {
			case <-s.stop:
				zap.L().Debug("gRPC Monitor' server channel loop: got a stop notification on the stop channel")
				return
			case err := <-errChan:
				zap.L().Fatal("gRPC Monitor' server channel loop: got an error notification on the error channel", zap.Error(err))
			case <-ctx.Done():
				return
			}
		}
	}()

	return nil
}

// Stop stops the Monitor' gRPC server (does not stop enforcer)
func (s *Server) Stop() error {
	if s.running {
		zap.L().Debug("gRPC Server: notified the graceful stop")
		close(s.stop)
	}
	// add the wait for to make sure the GRPC gracefulStop drains all the connections.
	s.waitStopGrp.Wait()
	return nil
}

// RuncProxyStarted gets sent by the defender once when the defender has started the runc-proxy.
func (s *Server) RuncProxyStarted(context.Context, *empty.Empty) (*empty.Empty, error) {
	zap.L().Info("grpc: runc-proxy has started")
	s.extMonitorStartedLock.Lock()
	s.runcProxyStarted = true
	s.extMonitorStartedLock.Unlock()
	s.notifyProcessRuncProxyStartedCh <- struct{}{}
	return &empty.Empty{}, nil
}

// isRuncProxyStarted returns the internal state of RuncProxyStarted as a copy
func (s *Server) isRuncProxyStarted() bool {
	s.extMonitorStartedLock.RLock()
	defer s.extMonitorStartedLock.RUnlock()
	return s.runcProxyStarted
}

// CniPluginInstalled gets sent by the defender once when the defender has started the runc-proxy.
func (s *Server) CniPluginInstalled(context.Context, *empty.Empty) (*empty.Empty, error) {
	zap.L().Info("grpc: cni Plugin is installed")
	s.extMonitorStartedLock.Lock()
	s.cniInstalled = true
	s.extMonitorStartedLock.Unlock()
	s.notifyProcessCniInstalledCh <- struct{}{}
	return &empty.Empty{}, nil
}

// isCniInstalled returns the internal state of RuncProxyStarted as a copy
func (s *Server) isCniInstalled() bool {
	s.extMonitorStartedLock.RLock()
	defer s.extMonitorStartedLock.RUnlock()
	return s.cniInstalled
}

func (s *Server) processExtMonitorStarted(ctx context.Context) {
	m := make(map[string]struct{})
	for {
		// signal only when runc/cni has not yet started
		if !s.isRuncProxyStarted() && !s.isCniInstalled() {
			s.apoRuncWaitGrp.Done()
		}
		// wait for a notification: this will be sent for two cases:
		// - RuncProxyStarted was called
		// - a new monitor registers with the grpc servcer
		select {
		case <-ctx.Done():
			return
		case <-s.notifyProcessRuncProxyStartedCh:
			// continue here
		case <-s.notifyProcessCniInstalledCh:
		}
		if s.isRuncProxyStarted() || s.isCniInstalled() {
			s.monitorsLock.RLock()
			// iterate over all currently registered monitors
			// and if they haven't gotten the SenderReady() yet
			// we will send it to them
			for name, monitor := range s.monitors {
				if _, ok := m[name]; ok {
					continue
				}
				monitor.SenderReady()
				m[name] = struct{}{}
			}
			s.monitorsLock.RUnlock()
		}
	}
}

const maxProcessingTime = time.Second * 5

func calProcessingTime(onStart time.Time, containerID string) {
	processingTime := time.Since(onStart)
	if processingTime > (maxProcessingTime) {
		counters.IncrementCounter(counters.ErrSegmentServerContainerEventExceedsProcessingTime)
		zap.L().Warn(
			"grpc: ContainerEvent: processing of container event took longer than allowed processing time",
			zap.String("id", containerID),
			zap.Duration("processingTime", processingTime),
			zap.Duration("maxProcessingTime", maxProcessingTime),
		)
	} else {
		zap.L().Debug(
			"grpc: ContainerEvent: processing of container event was within allowed time frame",
			zap.String("id", containerID),
			zap.Duration("processingTime", processingTime),
			zap.Duration("maxProcessingTime", maxProcessingTime),
		)
	}
}

// CNIContainerEvent handles container event requests
func (s *Server) CNIContainerEvent(ctx context.Context, req *monitorpb.CNIContainerEventRequest) (*monitorpb.ContainerEventResponse, error) {
	zap.L().Debug("grpc: CNI ContainerEvent received", zap.Any("request", req), zap.Any("type", req.Type))

	// calculate the time that this function takes and log accordingly
	onStart := time.Now()
	defer func() {
		calProcessingTime(onStart, req.ContainerID)
	}()
	containerArgs := containermetadata.NewCniArguments(req)
	// now send the container event to the monitor
	return s.sendContainerEvent(ctx, containerArgs)
}

// RunCContainerEvent handles container event requests
func (s *Server) RunCContainerEvent(ctx context.Context, req *monitorpb.RunCContainerEventRequest) (*monitorpb.ContainerEventResponse, error) {
	zap.L().Debug("grpc: runc ContainerEvent received", zap.Strings("commandLine", req.GetCommandLine()))

	if !s.isRuncProxyStarted() {
		zap.L().Warn("grpc: receiving ContainerEvent, but have not received RuncProxyStarted event yet. Compensating...")
		s.RuncProxyStarted(ctx, &empty.Empty{}) // nolint
		return &monitorpb.ContainerEventResponse{
			ErrorMessage: "received ContainerEvent before RuncProxyStarted event",
		}, nil
	}

	// parse the runc command-line first
	containerArgs, err := containermetadata.ParseRuncArguments(req.GetCommandLine())
	if err != nil {
		zap.L().Error("grpc: ContainerEvent: failed to parse runc commandline")
		return &monitorpb.ContainerEventResponse{
			ErrorMessage: fmt.Sprintf("failed to parse runc commandline: %s", err),
		}, nil
	}
	// calculate the time that this function takes and log accordingly
	onStart := time.Now()
	defer func() {
		calProcessingTime(onStart, containerArgs.ID())
	}()
	// now send the container event to the monitor
	return s.sendContainerEvent(ctx, containerArgs)
}

func (s *Server) sendContainerEvent(ctx context.Context, containerArgs containermetadata.ContainerArgs) (*monitorpb.ContainerEventResponse, error) {
	var kmd containermetadata.CommonKubernetesContainerMetadata
	var md containermetadata.CommonContainerMetadata
	var err error
	// now 1st check if the netnsPath is given, if given then its a CNI event and process it 1st
	// if the netnsPath is not given then we fallback to the default mechanism for extraction.
	// if we can identify that we have this container
	if len(containerArgs.NetNsPath()) > 0 && len(containerArgs.PodName()) > 0 && len(containerArgs.PodNamespace()) > 0 {
		// create the cni containerMetadata
		kmd = containermetadata.NewCniContainerMetadata(containerArgs)
	} else if containermetadata.AutoDetect().Has(containerArgs) {

		// then extract the common container metadata
		md, kmd, err = containermetadata.AutoDetect().Extract(containerArgs)
		if err != nil {
			return &monitorpb.ContainerEventResponse{
				ErrorMessage: fmt.Sprintf("failed to parse runc commandline: %s", err),
			}, nil
		}

		// as we are only interested in Kubernetes containers at the moment
		// simply log if this is a non-Kubernetes event
		if md != nil && kmd == nil {
			zap.L().Debug(
				"grpc: ContainerEvent: container event does not belong to a Kubernetes container",
				zap.String("md.ID()", md.ID()),
				zap.String("md.Root()", md.Root()),
				zap.String("md.Kind()", md.Kind().String()),
				zap.String("md.Runtime()", md.Runtime().String()),
				zap.Int("md.PID()", md.PID()),
				zap.Bool("md.SystemdCgroups()", md.SystemdCgroups()),
			)
			return &monitorpb.ContainerEventResponse{}, nil
		}
	}

	// and now send an event to the K8s monitor
	if kmd != nil {
		zap.L().Debug(
			"grpc: ContainerEvent: container event belongs to a Kubernetes container",
			zap.String("kmd.ID()", kmd.ID()),
			zap.String("kmd.Root()", kmd.Root()),
			zap.String("kmd.Kind()", kmd.Kind().String()),
			zap.String("kmd.Runtime()", kmd.Runtime().String()),
			zap.Int("kmd.PID()", kmd.PID()),
			zap.Bool("kmd.SystemdCgroups()", kmd.SystemdCgroups()),
			zap.String("kmd.PodName()", kmd.PodName()),
			zap.String("kmd.NetNsPath()", kmd.NetNSPath()),
			zap.String("kmd.PodNamespace()", kmd.PodNamespace()),
			zap.String("kmd.PodUID()", kmd.PodUID()),
			zap.String("kmd.PodSandboxID()", kmd.PodSandboxID()),
		)

		s.monitorsLock.RLock()
		defer s.monitorsLock.RUnlock()
		monitor, ok := s.monitors[constants.K8sMonitorRegistrationName]
		if !ok {
			zap.L().Debug("grpc: K8s monitor is not registered yet. Skipping processing of event.")
			return &monitorpb.ContainerEventResponse{
				ErrorMessage: "K8s monitor is not initialized yet",
			}, nil
		}

		switch containerArgs.Action() {
		case containermetadata.StartAction:
			// the start action MUST be synchronous at all costs
			monitor.Event(ctx, common.EventStart, kmd) // nolint: errcheck
		case containermetadata.DeleteAction:
			// the delete event SHOULD be synchronous
			// however, we can unblock the caller and respect the context if it is not
			ch := make(chan struct{})
			go func() {
				monitor.Event(context.Background(), common.EventDestroy, kmd) // nolint: errcheck
				close(ch)
			}()
			select {
			case <-ctx.Done():
				zap.L().Warn("grpc: ContainerEvent: failed to process delete event within the context constraints",
					zap.String("kmd.ID()", kmd.ID()),
					zap.String("kmd.PodName()", kmd.PodName()),
					zap.String("kmd.PodNamespace()", kmd.PodNamespace()),
					zap.String("kmd.PodUID()", kmd.PodUID()),
					zap.String("kmd.NetNsPath()", kmd.NetNSPath()),
					zap.Error(ctx.Err()),
				)
			case <-ch:
				// success, nothing more needs to be done
			}
		default:
			zap.L().Debug("grpc: unsupported action by the K8s monitor", zap.String("action", containerArgs.Action().String()))
			return &monitorpb.ContainerEventResponse{
				ErrorMessage: "unexpected action received: " + containerArgs.Action().String(),
			}, nil
		}

		return &monitorpb.ContainerEventResponse{}, nil
	}

	// log an error if we can't find it because we should always be able to find it, and this is an error in the extractor
	zap.L().Error("grpc: ContainerEvent: container not found", zap.String("containerID", containerArgs.ID()), zap.String("action", containerArgs.Action().String()))
	return &monitorpb.ContainerEventResponse{
		ErrorMessage: "container not found",
	}, nil
}

// SenderName must return a globally unique name of the implementor.
func (s *Server) SenderName() string {
	return constants.MonitorExtSenderName
}

// Register will register the given `monitor` for receiving events under `name`.
// Multiple calls to this function for the same `name` must update the internal
// state of the implementor to now send events to the newly regitered monitor of this
// name. Only one registration of a monitor of the same name is allowed.
func (s *Server) Register(name string, monitor external.ReceiveEvents) error {
	s.monitorsLock.Lock()
	defer s.monitorsLock.Unlock()
	s.monitors[name] = monitor
	s.notifyProcessRuncProxyStartedCh <- struct{}{}
	return nil
}
