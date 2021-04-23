package cri

import (
	"context"
	"fmt"
	"time"

	criruntimev1alpha2 "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
)

// NewCRIExtendedRuntimeServiceWrapper creates an ExtendedRuntimeService from a v1alpha2 runtime service client
// NOTE: the passed context is used for every subsequent call on the interface as the parent context with a timeout
// as passed through the argument. If the parent context gets canceled, this client becomes useless.
func NewCRIExtendedRuntimeServiceWrapper(ctx context.Context, timeout time.Duration, client criruntimev1alpha2.RuntimeServiceClient) (ExtendedRuntimeService, error) {
	if client == nil {
		return nil, fmt.Errorf("client cannot be nil")
	}
	if timeout == time.Duration(0) {
		return nil, fmt.Errorf("timeout cannot be 0")
	}
	return &extendedServiceRuntimeWrapper{
		ctx:     ctx,
		timeout: timeout,
		rs:      client,
	}, nil
}

type extendedServiceRuntimeWrapper struct {
	// well, this is stupid:
	// the criapi.RuntimeService should take a context as first argument everywhere
	// as it doesn't, the only sensible way is to be able to pass it from here
	// however, be careful with this: if that passed context gets canceled, nothing will work anymore
	ctx     context.Context
	timeout time.Duration
	rs      criruntimev1alpha2.RuntimeServiceClient
}

// Version returns the runtime name, runtime version and runtime API version
func (w *extendedServiceRuntimeWrapper) Version(apiVersion string) (*criruntimev1alpha2.VersionResponse, error) {
	ctx, cancel := context.WithTimeout(w.ctx, w.timeout)
	defer cancel()
	return w.rs.Version(ctx, &criruntimev1alpha2.VersionRequest{Version: apiVersion})
}

// CreateContainer creates a new container in specified PodSandbox.
func (w *extendedServiceRuntimeWrapper) CreateContainer(podSandboxID string, config *criruntimev1alpha2.ContainerConfig, sandboxConfig *criruntimev1alpha2.PodSandboxConfig) (string, error) {
	ctx, cancel := context.WithTimeout(w.ctx, w.timeout)
	defer cancel()
	resp, err := w.rs.CreateContainer(ctx, &criruntimev1alpha2.CreateContainerRequest{
		PodSandboxId:  podSandboxID,
		Config:        config,
		SandboxConfig: sandboxConfig,
	})
	if err != nil {
		return "", err
	}
	return resp.GetContainerId(), nil
}

// StartContainer starts the container.
func (w *extendedServiceRuntimeWrapper) StartContainer(containerID string) error {
	ctx, cancel := context.WithTimeout(w.ctx, w.timeout)
	defer cancel()
	_, err := w.rs.StartContainer(ctx, &criruntimev1alpha2.StartContainerRequest{
		ContainerId: containerID,
	})
	return err
}

// StopContainer stops a running container with a grace period (i.e., timeout).
func (w *extendedServiceRuntimeWrapper) StopContainer(containerID string, timeout int64) error {
	ctx, cancel := context.WithTimeout(w.ctx, w.timeout)
	defer cancel()
	_, err := w.rs.StopContainer(ctx, &criruntimev1alpha2.StopContainerRequest{
		ContainerId: containerID,
		Timeout:     timeout,
	})
	return err
}

// RemoveContainer removes the container.
func (w *extendedServiceRuntimeWrapper) RemoveContainer(containerID string) error {
	ctx, cancel := context.WithTimeout(w.ctx, w.timeout)
	defer cancel()
	_, err := w.rs.RemoveContainer(ctx, &criruntimev1alpha2.RemoveContainerRequest{
		ContainerId: containerID,
	})
	return err
}

// ListContainers lists all containers by filters.
func (w *extendedServiceRuntimeWrapper) ListContainers(filter *criruntimev1alpha2.ContainerFilter) ([]*criruntimev1alpha2.Container, error) {
	ctx, cancel := context.WithTimeout(w.ctx, w.timeout)
	defer cancel()
	resp, err := w.rs.ListContainers(ctx, &criruntimev1alpha2.ListContainersRequest{
		Filter: filter,
	})
	if err != nil {
		return nil, err
	}
	return resp.GetContainers(), nil
}

// ContainerStatus returns the status of the container.
func (w *extendedServiceRuntimeWrapper) ContainerStatus(containerID string) (*criruntimev1alpha2.ContainerStatus, error) {
	ctx, cancel := context.WithTimeout(w.ctx, w.timeout)
	defer cancel()
	resp, err := w.rs.ContainerStatus(ctx, &criruntimev1alpha2.ContainerStatusRequest{
		ContainerId: containerID,
		Verbose:     false,
	})
	if err != nil {
		return nil, err
	}
	return resp.GetStatus(), nil
}

// ContainerStatusVerbose returns the status of the container.
func (w *extendedServiceRuntimeWrapper) ContainerStatusVerbose(containerID string) (*criruntimev1alpha2.ContainerStatus, map[string]string, error) {
	ctx, cancel := context.WithTimeout(w.ctx, w.timeout)
	defer cancel()
	resp, err := w.rs.ContainerStatus(ctx, &criruntimev1alpha2.ContainerStatusRequest{
		ContainerId: containerID,
		Verbose:     true,
	})
	if err != nil {
		return nil, nil, err
	}
	return resp.GetStatus(), resp.GetInfo(), nil
}

// UpdateContainerResources updates the cgroup resources for the container.
func (w *extendedServiceRuntimeWrapper) UpdateContainerResources(containerID string, resources *criruntimev1alpha2.LinuxContainerResources) error {
	ctx, cancel := context.WithTimeout(w.ctx, w.timeout)
	defer cancel()
	_, err := w.rs.UpdateContainerResources(ctx, &criruntimev1alpha2.UpdateContainerResourcesRequest{
		ContainerId: containerID,
		Linux:       resources,
	})
	return err
}

// ExecSync executes a command in the container, and returns the stdout output.
// If command exits with a non-zero exit code, an error is returned.
func (w *extendedServiceRuntimeWrapper) ExecSync(containerID string, cmd []string, timeout time.Duration) (stdout []byte, stderr []byte, err error) {
	ctx, cancel := context.WithTimeout(w.ctx, w.timeout)
	defer cancel()
	resp, err := w.rs.ExecSync(ctx, &criruntimev1alpha2.ExecSyncRequest{
		ContainerId: containerID,
		Cmd:         cmd,
		Timeout:     int64(timeout.Seconds()),
	})
	if err != nil {
		return nil, nil, err
	}
	if resp.GetExitCode() != int32(0) {
		return resp.GetStdout(), resp.GetStderr(), fmt.Errorf("exit code: %d", resp.GetExitCode())
	}
	return resp.GetStdout(), resp.GetStderr(), nil
}

// Exec prepares a streaming endpoint to execute a command in the container, and returns the address.
func (w *extendedServiceRuntimeWrapper) Exec(req *criruntimev1alpha2.ExecRequest) (*criruntimev1alpha2.ExecResponse, error) {
	ctx, cancel := context.WithTimeout(w.ctx, w.timeout)
	defer cancel()
	return w.rs.Exec(ctx, req)
}

// Attach prepares a streaming endpoint to attach to a running container, and returns the address.
func (w *extendedServiceRuntimeWrapper) Attach(req *criruntimev1alpha2.AttachRequest) (*criruntimev1alpha2.AttachResponse, error) {
	ctx, cancel := context.WithTimeout(w.ctx, w.timeout)
	defer cancel()
	return w.rs.Attach(ctx, req)
}

// ReopenContainerLog asks runtime to reopen the stdout/stderr log file
// for the container. If it returns error, new container log file MUST NOT
// be created.
func (w *extendedServiceRuntimeWrapper) ReopenContainerLog(containerID string) error {
	ctx, cancel := context.WithTimeout(w.ctx, w.timeout)
	defer cancel()
	_, err := w.rs.ReopenContainerLog(ctx, &criruntimev1alpha2.ReopenContainerLogRequest{
		ContainerId: containerID,
	})
	return err
}

// RunPodSandbox creates and starts a pod-level sandbox. Runtimes should ensure
// the sandbox is in ready state.
func (w *extendedServiceRuntimeWrapper) RunPodSandbox(config *criruntimev1alpha2.PodSandboxConfig, runtimeHandler string) (string, error) {
	ctx, cancel := context.WithTimeout(w.ctx, w.timeout)
	defer cancel()
	resp, err := w.rs.RunPodSandbox(ctx, &criruntimev1alpha2.RunPodSandboxRequest{
		Config:         config,
		RuntimeHandler: runtimeHandler,
	})
	if err != nil {
		return "", err
	}
	return resp.GetPodSandboxId(), nil
}

// StopPodSandbox stops the sandbox. If there are any running containers in the
// sandbox, they should be force terminated.
func (w *extendedServiceRuntimeWrapper) StopPodSandbox(podSandboxID string) error {
	ctx, cancel := context.WithTimeout(w.ctx, w.timeout)
	defer cancel()
	_, err := w.rs.StopPodSandbox(ctx, &criruntimev1alpha2.StopPodSandboxRequest{
		PodSandboxId: podSandboxID,
	})
	return err
}

// RemovePodSandbox removes the sandbox. If there are running containers in the
// sandbox, they should be forcibly removed.
func (w *extendedServiceRuntimeWrapper) RemovePodSandbox(podSandboxID string) error {
	ctx, cancel := context.WithTimeout(w.ctx, w.timeout)
	defer cancel()
	_, err := w.rs.RemovePodSandbox(ctx, &criruntimev1alpha2.RemovePodSandboxRequest{
		PodSandboxId: podSandboxID,
	})
	return err
}

// PodSandboxStatus returns the Status of the PodSandbox.
func (w *extendedServiceRuntimeWrapper) PodSandboxStatus(podSandboxID string) (*criruntimev1alpha2.PodSandboxStatus, error) {
	ctx, cancel := context.WithTimeout(w.ctx, w.timeout)
	defer cancel()
	resp, err := w.rs.PodSandboxStatus(ctx, &criruntimev1alpha2.PodSandboxStatusRequest{
		PodSandboxId: podSandboxID,
		Verbose:      false,
	})
	if err != nil {
		return nil, err
	}
	return resp.GetStatus(), nil
}

// PodSandboxStatusVerbose returns the Status of the PodSandbox.
func (w *extendedServiceRuntimeWrapper) PodSandboxStatusVerbose(podSandboxID string) (*criruntimev1alpha2.PodSandboxStatus, map[string]string, error) {
	ctx, cancel := context.WithTimeout(w.ctx, w.timeout)
	defer cancel()
	resp, err := w.rs.PodSandboxStatus(ctx, &criruntimev1alpha2.PodSandboxStatusRequest{
		PodSandboxId: podSandboxID,
		Verbose:      true,
	})
	if err != nil {
		return nil, nil, err
	}
	return resp.GetStatus(), resp.GetInfo(), nil
}

// ListPodSandbox returns a list of Sandbox.
func (w *extendedServiceRuntimeWrapper) ListPodSandbox(filter *criruntimev1alpha2.PodSandboxFilter) ([]*criruntimev1alpha2.PodSandbox, error) {
	ctx, cancel := context.WithTimeout(w.ctx, w.timeout)
	defer cancel()
	resp, err := w.rs.ListPodSandbox(ctx, &criruntimev1alpha2.ListPodSandboxRequest{
		Filter: filter,
	})
	if err != nil {
		return nil, err
	}
	return resp.GetItems(), nil
}

// PortForward prepares a streaming endpoint to forward ports from a PodSandbox, and returns the address.
func (w *extendedServiceRuntimeWrapper) PortForward(req *criruntimev1alpha2.PortForwardRequest) (*criruntimev1alpha2.PortForwardResponse, error) {
	ctx, cancel := context.WithTimeout(w.ctx, w.timeout)
	defer cancel()
	return w.rs.PortForward(ctx, req)
}

// ContainerStats returns stats of the container. If the container does not
// exist, the call returns an error.
func (w *extendedServiceRuntimeWrapper) ContainerStats(containerID string) (*criruntimev1alpha2.ContainerStats, error) {
	ctx, cancel := context.WithTimeout(w.ctx, w.timeout)
	defer cancel()
	resp, err := w.rs.ContainerStats(ctx, &criruntimev1alpha2.ContainerStatsRequest{
		ContainerId: containerID,
	})
	if err != nil {
		return nil, err
	}
	return resp.GetStats(), nil
}

// ListContainerStats returns stats of all running containers.
func (w *extendedServiceRuntimeWrapper) ListContainerStats(filter *criruntimev1alpha2.ContainerStatsFilter) ([]*criruntimev1alpha2.ContainerStats, error) {
	ctx, cancel := context.WithTimeout(w.ctx, w.timeout)
	defer cancel()
	resp, err := w.rs.ListContainerStats(ctx, &criruntimev1alpha2.ListContainerStatsRequest{
		Filter: filter,
	})
	if err != nil {
		return nil, err
	}
	return resp.GetStats(), nil
}

// UpdateRuntimeConfig updates runtime configuration if specified
func (w *extendedServiceRuntimeWrapper) UpdateRuntimeConfig(runtimeConfig *criruntimev1alpha2.RuntimeConfig) error {
	ctx, cancel := context.WithTimeout(w.ctx, w.timeout)
	defer cancel()
	_, err := w.rs.UpdateRuntimeConfig(ctx, &criruntimev1alpha2.UpdateRuntimeConfigRequest{
		RuntimeConfig: runtimeConfig,
	})
	return err
}

// Status returns the status of the runtime.
func (w *extendedServiceRuntimeWrapper) Status() (*criruntimev1alpha2.RuntimeStatus, error) {
	ctx, cancel := context.WithTimeout(w.ctx, w.timeout)
	defer cancel()
	resp, err := w.rs.Status(ctx, &criruntimev1alpha2.StatusRequest{
		Verbose: false,
	})
	if err != nil {
		return nil, err
	}
	return resp.GetStatus(), nil
}

// Status returns the status of the runtime.
func (w *extendedServiceRuntimeWrapper) StatusVerbose() (*criruntimev1alpha2.RuntimeStatus, map[string]string, error) {
	ctx, cancel := context.WithTimeout(w.ctx, w.timeout)
	defer cancel()
	resp, err := w.rs.Status(ctx, &criruntimev1alpha2.StatusRequest{
		Verbose: true,
	})
	if err != nil {
		return nil, nil, err
	}
	return resp.GetStatus(), resp.GetInfo(), nil
}
