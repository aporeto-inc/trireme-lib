package cri

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"go.aporeto.io/enforcerd/trireme-lib/utils/cri/mockcri"
	criruntimev1alpha2 "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
)

func TestNewCRIExtendedRuntimeServiceWrapper(t *testing.T) {
	type args struct {
		ctx     context.Context
		timeout time.Duration
		client  criruntimev1alpha2.RuntimeServiceClient
	}
	tests := []struct {
		name    string
		args    args
		want    ExtendedRuntimeService
		wantErr bool
	}{
		{
			name: "client is nil",
			args: args{
				ctx:     context.Background(),
				timeout: connectTimeout,
				client:  nil,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "timeout is 0",
			args: args{
				ctx:     context.Background(),
				timeout: 0,
				client:  criruntimev1alpha2.NewRuntimeServiceClient(nil),
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "success",
			args: args{
				ctx:     context.Background(),
				timeout: connectTimeout,
				client:  criruntimev1alpha2.NewRuntimeServiceClient(nil),
			},
			want: &extendedServiceRuntimeWrapper{
				ctx:     context.Background(),
				timeout: connectTimeout,
				rs:      criruntimev1alpha2.NewRuntimeServiceClient(nil),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewCRIExtendedRuntimeServiceWrapper(tt.args.ctx, tt.args.timeout, tt.args.client)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewCRIExtendedRuntimeServiceWrapper() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewCRIExtendedRuntimeServiceWrapper() = %v, want %v", got, tt.want)
			}
		})
	}
}

func newUnitTestCRIExtendedRuntimeServiceWrapper(t *testing.T) (*gomock.Controller, *mockcri.MockRuntimeServiceClient, context.CancelFunc, ExtendedRuntimeService) {
	ctrl := gomock.NewController(t)
	client := mockcri.NewMockRuntimeServiceClient(ctrl)
	ctx, cancel := context.WithCancel(context.Background())
	w, err := NewCRIExtendedRuntimeServiceWrapper(ctx, connectTimeout, client)
	if err != nil {
		panic(err)
	}
	return ctrl, client, cancel, w
}

type prepareFunc func(*testing.T, *mockcri.MockRuntimeServiceClient)

var errMock = errors.New("mocked error has occurred")

func Test_extendedServiceRuntimeWrapper_Version(t *testing.T) {
	type args struct {
		apiVersion string
	}
	tests := []struct {
		name    string
		args    args
		prepare prepareFunc
		want    *criruntimev1alpha2.VersionResponse
		wantErr bool
	}{
		{
			name: "error",
			args: args{
				apiVersion: "version",
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().Version(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.VersionRequest{Version: "version"}),
				).Times(1).Return(nil, errMock)
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "success",
			args: args{
				apiVersion: "version",
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().Version(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.VersionRequest{Version: "version"}),
				).Times(1).Return(&criruntimev1alpha2.VersionResponse{}, nil)
			},
			want:    &criruntimev1alpha2.VersionResponse{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// the same in every test
			ctrl, client, cancel, w := newUnitTestCRIExtendedRuntimeServiceWrapper(t)
			defer cancel()
			defer ctrl.Finish()
			if tt.prepare != nil {
				tt.prepare(t, client)
			}
			got, err := w.Version(tt.args.apiVersion)
			if (err != nil) != tt.wantErr {
				t.Errorf("extendedServiceRuntimeWrapper.Version() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extendedServiceRuntimeWrapper.Version() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_extendedServiceRuntimeWrapper_CreateContainer(t *testing.T) {
	type args struct {
		podSandboxID  string
		config        *criruntimev1alpha2.ContainerConfig
		sandboxConfig *criruntimev1alpha2.PodSandboxConfig
	}
	tests := []struct {
		name    string
		args    args
		prepare prepareFunc
		want    string
		wantErr bool
	}{
		{
			name: "error",
			args: args{
				podSandboxID:  "sandboxID",
				config:        &criruntimev1alpha2.ContainerConfig{},
				sandboxConfig: &criruntimev1alpha2.PodSandboxConfig{},
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().CreateContainer(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.CreateContainerRequest{
						PodSandboxId:  "sandboxID",
						Config:        &criruntimev1alpha2.ContainerConfig{},
						SandboxConfig: &criruntimev1alpha2.PodSandboxConfig{},
					}),
				).Times(1).Return(nil, errMock)
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "success",
			args: args{
				podSandboxID:  "sandboxID",
				config:        &criruntimev1alpha2.ContainerConfig{},
				sandboxConfig: &criruntimev1alpha2.PodSandboxConfig{},
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().CreateContainer(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.CreateContainerRequest{
						PodSandboxId:  "sandboxID",
						Config:        &criruntimev1alpha2.ContainerConfig{},
						SandboxConfig: &criruntimev1alpha2.PodSandboxConfig{},
					}),
				).Times(1).Return(&criruntimev1alpha2.CreateContainerResponse{
					ContainerId: "containerID",
				}, nil)
			},
			want:    "containerID",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// the same in every test
			ctrl, client, cancel, w := newUnitTestCRIExtendedRuntimeServiceWrapper(t)
			defer cancel()
			defer ctrl.Finish()
			if tt.prepare != nil {
				tt.prepare(t, client)
			}
			got, err := w.CreateContainer(tt.args.podSandboxID, tt.args.config, tt.args.sandboxConfig)
			if (err != nil) != tt.wantErr {
				t.Errorf("extendedServiceRuntimeWrapper.CreateContainer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("extendedServiceRuntimeWrapper.CreateContainer() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_extendedServiceRuntimeWrapper_StartContainer(t *testing.T) {
	type args struct {
		containerID string
	}
	tests := []struct {
		name    string
		args    args
		prepare prepareFunc
		wantErr bool
	}{
		{
			name: "error",
			args: args{
				containerID: "containerID",
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().StartContainer(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.StartContainerRequest{
						ContainerId: "containerID",
					}),
				).Times(1).Return(nil, errMock)
			},
			wantErr: true,
		},
		{
			name: "error",
			args: args{
				containerID: "containerID",
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().StartContainer(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.StartContainerRequest{
						ContainerId: "containerID",
					}),
				).Times(1).Return(&criruntimev1alpha2.StartContainerResponse{}, nil)
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// the same in every test
			ctrl, client, cancel, w := newUnitTestCRIExtendedRuntimeServiceWrapper(t)
			defer cancel()
			defer ctrl.Finish()
			if tt.prepare != nil {
				tt.prepare(t, client)
			}
			if err := w.StartContainer(tt.args.containerID); (err != nil) != tt.wantErr {
				t.Errorf("extendedServiceRuntimeWrapper.StartContainer() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_extendedServiceRuntimeWrapper_StopContainer(t *testing.T) {
	type args struct {
		containerID string
		timeout     int64
	}
	tests := []struct {
		name    string
		prepare prepareFunc
		args    args
		wantErr bool
	}{
		{
			name: "error",
			args: args{
				containerID: "containerID",
				timeout:     42,
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().StopContainer(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.StopContainerRequest{
						ContainerId: "containerID",
						Timeout:     42,
					}),
				).Times(1).Return(nil, errMock)
			},
			wantErr: true,
		},
		{
			name: "error",
			args: args{
				containerID: "containerID",
				timeout:     42,
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().StopContainer(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.StopContainerRequest{
						ContainerId: "containerID",
						Timeout:     42,
					}),
				).Times(1).Return(&criruntimev1alpha2.StopContainerResponse{}, nil)
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// the same in every test
			ctrl, client, cancel, w := newUnitTestCRIExtendedRuntimeServiceWrapper(t)
			defer cancel()
			defer ctrl.Finish()
			if tt.prepare != nil {
				tt.prepare(t, client)
			}
			if err := w.StopContainer(tt.args.containerID, tt.args.timeout); (err != nil) != tt.wantErr {
				t.Errorf("extendedServiceRuntimeWrapper.StopContainer() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_extendedServiceRuntimeWrapper_RemoveContainer(t *testing.T) {
	type args struct {
		containerID string
	}
	tests := []struct {
		name    string
		prepare prepareFunc
		args    args
		wantErr bool
	}{
		{
			name: "error",
			args: args{
				containerID: "containerID",
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().RemoveContainer(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.RemoveContainerRequest{
						ContainerId: "containerID",
					}),
				).Times(1).Return(nil, errMock)
			},
			wantErr: true,
		},
		{
			name: "success",
			args: args{
				containerID: "containerID",
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().RemoveContainer(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.RemoveContainerRequest{
						ContainerId: "containerID",
					}),
				).Times(1).Return(&criruntimev1alpha2.RemoveContainerResponse{}, nil)
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// the same in every test
			ctrl, client, cancel, w := newUnitTestCRIExtendedRuntimeServiceWrapper(t)
			defer cancel()
			defer ctrl.Finish()
			if tt.prepare != nil {
				tt.prepare(t, client)
			}
			if err := w.RemoveContainer(tt.args.containerID); (err != nil) != tt.wantErr {
				t.Errorf("extendedServiceRuntimeWrapper.RemoveContainer() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_extendedServiceRuntimeWrapper_ListContainers(t *testing.T) {
	type args struct {
		filter *criruntimev1alpha2.ContainerFilter
	}
	tests := []struct {
		name    string
		prepare prepareFunc
		args    args
		want    []*criruntimev1alpha2.Container
		wantErr bool
	}{
		{
			name: "error",
			args: args{
				filter: &criruntimev1alpha2.ContainerFilter{
					LabelSelector: map[string]string{
						"a": "b",
					},
				},
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().ListContainers(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.ListContainersRequest{
						Filter: &criruntimev1alpha2.ContainerFilter{
							LabelSelector: map[string]string{
								"a": "b",
							},
						},
					}),
				).Times(1).Return(nil, errMock)
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "success",
			args: args{
				filter: &criruntimev1alpha2.ContainerFilter{
					LabelSelector: map[string]string{
						"a": "b",
					},
				},
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().ListContainers(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.ListContainersRequest{
						Filter: &criruntimev1alpha2.ContainerFilter{
							LabelSelector: map[string]string{
								"a": "b",
							},
						},
					}),
				).Times(1).Return(&criruntimev1alpha2.ListContainersResponse{
					Containers: []*criruntimev1alpha2.Container{
						{
							Id: "one",
							Labels: map[string]string{
								"a": "b",
							},
						},
						{
							Id: "two",
							Labels: map[string]string{
								"a": "b",
							},
						},
					},
				}, nil)
			},
			want: []*criruntimev1alpha2.Container{
				{
					Id: "one",
					Labels: map[string]string{
						"a": "b",
					},
				},
				{
					Id: "two",
					Labels: map[string]string{
						"a": "b",
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// the same in every test
			ctrl, client, cancel, w := newUnitTestCRIExtendedRuntimeServiceWrapper(t)
			defer cancel()
			defer ctrl.Finish()
			if tt.prepare != nil {
				tt.prepare(t, client)
			}
			got, err := w.ListContainers(tt.args.filter)
			if (err != nil) != tt.wantErr {
				t.Errorf("extendedServiceRuntimeWrapper.ListContainers() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extendedServiceRuntimeWrapper.ListContainers() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_extendedServiceRuntimeWrapper_ContainerStatus(t *testing.T) {
	type args struct {
		containerID string
	}
	tests := []struct {
		name    string
		prepare prepareFunc
		args    args
		want    *criruntimev1alpha2.ContainerStatus
		wantErr bool
	}{
		{
			name: "error",
			args: args{
				containerID: "containerID",
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().ContainerStatus(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.ContainerStatusRequest{
						ContainerId: "containerID",
						Verbose:     false,
					}),
				).Times(1).Return(nil, errMock)
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "success",
			args: args{
				containerID: "containerID",
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().ContainerStatus(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.ContainerStatusRequest{
						ContainerId: "containerID",
						Verbose:     false,
					}),
				).Times(1).Return(&criruntimev1alpha2.ContainerStatusResponse{
					Status: &criruntimev1alpha2.ContainerStatus{
						Id:    "containerID",
						State: criruntimev1alpha2.ContainerState_CONTAINER_RUNNING,
					},
				}, nil)
			},
			want: &criruntimev1alpha2.ContainerStatus{
				Id:    "containerID",
				State: criruntimev1alpha2.ContainerState_CONTAINER_RUNNING,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// the same in every test
			ctrl, client, cancel, w := newUnitTestCRIExtendedRuntimeServiceWrapper(t)
			defer cancel()
			defer ctrl.Finish()
			if tt.prepare != nil {
				tt.prepare(t, client)
			}
			got, err := w.ContainerStatus(tt.args.containerID)
			if (err != nil) != tt.wantErr {
				t.Errorf("extendedServiceRuntimeWrapper.ContainerStatus() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extendedServiceRuntimeWrapper.ContainerStatus() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_extendedServiceRuntimeWrapper_ContainerStatusVerbose(t *testing.T) {

	type args struct {
		containerID string
	}
	tests := []struct {
		name    string
		prepare prepareFunc
		args    args
		want    *criruntimev1alpha2.ContainerStatus
		want1   map[string]string
		wantErr bool
	}{
		{
			name: "error",
			args: args{
				containerID: "containerID",
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().ContainerStatus(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.ContainerStatusRequest{
						ContainerId: "containerID",
						Verbose:     true,
					}),
				).Times(1).Return(nil, errMock)
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "success",
			args: args{
				containerID: "containerID",
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().ContainerStatus(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.ContainerStatusRequest{
						ContainerId: "containerID",
						Verbose:     true,
					}),
				).Times(1).Return(&criruntimev1alpha2.ContainerStatusResponse{
					Status: &criruntimev1alpha2.ContainerStatus{
						Id:    "containerID",
						State: criruntimev1alpha2.ContainerState_CONTAINER_RUNNING,
					},
				}, nil)
			},
			want: &criruntimev1alpha2.ContainerStatus{
				Id:    "containerID",
				State: criruntimev1alpha2.ContainerState_CONTAINER_RUNNING,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// the same in every test
			ctrl, client, cancel, w := newUnitTestCRIExtendedRuntimeServiceWrapper(t)
			defer cancel()
			defer ctrl.Finish()
			if tt.prepare != nil {
				tt.prepare(t, client)
			}
			got, got1, err := w.ContainerStatusVerbose(tt.args.containerID)
			if (err != nil) != tt.wantErr {
				t.Errorf("extendedServiceRuntimeWrapper.ContainerStatusVerbose() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extendedServiceRuntimeWrapper.ContainerStatusVerbose() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("extendedServiceRuntimeWrapper.ContainerStatusVerbose() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func Test_extendedServiceRuntimeWrapper_UpdateContainerResources(t *testing.T) {

	type args struct {
		containerID string
		resources   *criruntimev1alpha2.LinuxContainerResources
	}
	tests := []struct {
		name    string
		prepare prepareFunc
		args    args
		wantErr bool
	}{
		{
			name: "error",
			args: args{
				containerID: "containerID",
				resources: &criruntimev1alpha2.LinuxContainerResources{
					CpuPeriod: 42,
				},
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().UpdateContainerResources(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.UpdateContainerResourcesRequest{
						ContainerId: "containerID",
						Linux: &criruntimev1alpha2.LinuxContainerResources{
							CpuPeriod: 42,
						},
					}),
				).Times(1).Return(nil, errMock)
			},
			wantErr: true,
		},
		{
			name: "success",
			args: args{
				containerID: "containerID",
				resources: &criruntimev1alpha2.LinuxContainerResources{
					CpuPeriod: 42,
				},
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().UpdateContainerResources(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.UpdateContainerResourcesRequest{
						ContainerId: "containerID",
						Linux: &criruntimev1alpha2.LinuxContainerResources{
							CpuPeriod: 42,
						},
					}),
				).Times(1).Return(&criruntimev1alpha2.UpdateContainerResourcesResponse{}, nil)
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// the same in every test
			ctrl, client, cancel, w := newUnitTestCRIExtendedRuntimeServiceWrapper(t)
			defer cancel()
			defer ctrl.Finish()
			if tt.prepare != nil {
				tt.prepare(t, client)
			}
			if err := w.UpdateContainerResources(tt.args.containerID, tt.args.resources); (err != nil) != tt.wantErr {
				t.Errorf("extendedServiceRuntimeWrapper.UpdateContainerResources() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_extendedServiceRuntimeWrapper_ExecSync(t *testing.T) {

	type args struct {
		containerID string
		cmd         []string
		timeout     time.Duration
	}
	tests := []struct {
		name       string
		prepare    prepareFunc
		args       args
		wantStdout []byte
		wantStderr []byte
		wantErr    bool
	}{
		{
			name: "error",
			args: args{
				containerID: "containerID",
				cmd:         []string{"/bin/bash", "-c", "echo hello world"},
				timeout:     time.Minute * 1,
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().ExecSync(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.ExecSyncRequest{
						ContainerId: "containerID",
						Cmd:         []string{"/bin/bash", "-c", "echo hello world"},
						Timeout:     int64((time.Minute * 1).Seconds()),
					}),
				).Times(1).Return(nil, errMock)
			},
			wantStdout: nil,
			wantStderr: nil,
			wantErr:    true,
		},
		{
			name: "command execution failed",
			args: args{
				containerID: "containerID",
				cmd:         []string{"/bin/bash", "-c", "echo hello world"},
				timeout:     time.Minute * 1,
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().ExecSync(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.ExecSyncRequest{
						ContainerId: "containerID",
						Cmd:         []string{"/bin/bash", "-c", "echo hello world"},
						Timeout:     int64((time.Minute * 1).Seconds()),
					}),
				).Times(1).Return(&criruntimev1alpha2.ExecSyncResponse{
					Stdout:   []byte("stdout"),
					Stderr:   []byte("stderr"),
					ExitCode: 42,
				}, nil)
			},
			wantStdout: []byte("stdout"),
			wantStderr: []byte("stderr"),
			wantErr:    true,
		},
		{
			name: "success",
			args: args{
				containerID: "containerID",
				cmd:         []string{"/bin/bash", "-c", "echo hello world"},
				timeout:     time.Minute * 1,
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().ExecSync(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.ExecSyncRequest{
						ContainerId: "containerID",
						Cmd:         []string{"/bin/bash", "-c", "echo hello world"},
						Timeout:     int64((time.Minute * 1).Seconds()),
					}),
				).Times(1).Return(&criruntimev1alpha2.ExecSyncResponse{
					Stdout:   []byte("stdout"),
					Stderr:   []byte("stderr"),
					ExitCode: 0,
				}, nil)
			},
			wantStdout: []byte("stdout"),
			wantStderr: []byte("stderr"),
			wantErr:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// the same in every test
			ctrl, client, cancel, w := newUnitTestCRIExtendedRuntimeServiceWrapper(t)
			defer cancel()
			defer ctrl.Finish()
			if tt.prepare != nil {
				tt.prepare(t, client)
			}
			gotStdout, gotStderr, err := w.ExecSync(tt.args.containerID, tt.args.cmd, tt.args.timeout)
			if (err != nil) != tt.wantErr {
				t.Errorf("extendedServiceRuntimeWrapper.ExecSync() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotStdout, tt.wantStdout) {
				t.Errorf("extendedServiceRuntimeWrapper.ExecSync() gotStdout = %v, want %v", gotStdout, tt.wantStdout)
			}
			if !reflect.DeepEqual(gotStderr, tt.wantStderr) {
				t.Errorf("extendedServiceRuntimeWrapper.ExecSync() gotStderr = %v, want %v", gotStderr, tt.wantStderr)
			}
		})
	}
}

func Test_extendedServiceRuntimeWrapper_Exec(t *testing.T) {
	type args struct {
		req *criruntimev1alpha2.ExecRequest
	}
	tests := []struct {
		name    string
		prepare prepareFunc
		args    args
		want    *criruntimev1alpha2.ExecResponse
		wantErr bool
	}{
		{
			name: "error",
			args: args{
				req: &criruntimev1alpha2.ExecRequest{
					ContainerId: "containerID",
					Cmd:         []string{"/bin/bash", "-c", "echo hello world"},
				},
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().Exec(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.ExecRequest{
						ContainerId: "containerID",
						Cmd:         []string{"/bin/bash", "-c", "echo hello world"},
					}),
				).Times(1).Return(nil, errMock)
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "success",
			args: args{
				req: &criruntimev1alpha2.ExecRequest{
					ContainerId: "containerID",
					Cmd:         []string{"/bin/bash", "-c", "echo hello world"},
				},
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().Exec(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.ExecRequest{
						ContainerId: "containerID",
						Cmd:         []string{"/bin/bash", "-c", "echo hello world"},
					}),
				).Times(1).Return(&criruntimev1alpha2.ExecResponse{
					Url: "pick up status of exec request here",
				}, nil)
			},
			want: &criruntimev1alpha2.ExecResponse{
				Url: "pick up status of exec request here",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// the same in every test
			ctrl, client, cancel, w := newUnitTestCRIExtendedRuntimeServiceWrapper(t)
			defer cancel()
			defer ctrl.Finish()
			if tt.prepare != nil {
				tt.prepare(t, client)
			}
			got, err := w.Exec(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("extendedServiceRuntimeWrapper.Exec() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extendedServiceRuntimeWrapper.Exec() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_extendedServiceRuntimeWrapper_Attach(t *testing.T) {
	type args struct {
		req *criruntimev1alpha2.AttachRequest
	}
	tests := []struct {
		name    string
		prepare prepareFunc
		args    args
		want    *criruntimev1alpha2.AttachResponse
		wantErr bool
	}{
		{
			name: "error",
			args: args{
				req: &criruntimev1alpha2.AttachRequest{
					ContainerId: "containerID",
					Stdout:      true,
				},
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().Attach(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.AttachRequest{
						ContainerId: "containerID",
						Stdout:      true,
					}),
				).Times(1).Return(nil, errMock)
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "success",
			args: args{
				req: &criruntimev1alpha2.AttachRequest{
					ContainerId: "containerID",
					Stdout:      true,
				},
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().Attach(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.AttachRequest{
						ContainerId: "containerID",
						Stdout:      true,
					}),
				).Times(1).Return(&criruntimev1alpha2.AttachResponse{
					Url: "pick up status of attach request here",
				}, nil)
			},
			want: &criruntimev1alpha2.AttachResponse{
				Url: "pick up status of attach request here",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// the same in every test
			ctrl, client, cancel, w := newUnitTestCRIExtendedRuntimeServiceWrapper(t)
			defer cancel()
			defer ctrl.Finish()
			if tt.prepare != nil {
				tt.prepare(t, client)
			}
			got, err := w.Attach(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("extendedServiceRuntimeWrapper.Attach() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extendedServiceRuntimeWrapper.Attach() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_extendedServiceRuntimeWrapper_ReopenContainerLog(t *testing.T) {
	type args struct {
		containerID string
	}
	tests := []struct {
		name    string
		prepare prepareFunc
		args    args
		wantErr bool
	}{
		{
			name: "error",
			args: args{
				containerID: "containerID",
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().ReopenContainerLog(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.ReopenContainerLogRequest{
						ContainerId: "containerID",
					}),
				).Times(1).Return(nil, errMock)
			},
			wantErr: true,
		},
		{
			name: "success",
			args: args{
				containerID: "containerID",
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().ReopenContainerLog(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.ReopenContainerLogRequest{
						ContainerId: "containerID",
					}),
				).Times(1).Return(&criruntimev1alpha2.ReopenContainerLogResponse{}, nil)
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// the same in every test
			ctrl, client, cancel, w := newUnitTestCRIExtendedRuntimeServiceWrapper(t)
			defer cancel()
			defer ctrl.Finish()
			if tt.prepare != nil {
				tt.prepare(t, client)
			}
			if err := w.ReopenContainerLog(tt.args.containerID); (err != nil) != tt.wantErr {
				t.Errorf("extendedServiceRuntimeWrapper.ReopenContainerLog() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_extendedServiceRuntimeWrapper_RunPodSandbox(t *testing.T) {
	type args struct {
		config         *criruntimev1alpha2.PodSandboxConfig
		runtimeHandler string
	}
	tests := []struct {
		name    string
		prepare prepareFunc
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "error",
			args: args{
				config: &criruntimev1alpha2.PodSandboxConfig{
					Metadata: &criruntimev1alpha2.PodSandboxMetadata{
						Name:      "pod-name",
						Namespace: "default",
						Uid:       "b924b248-6395-4415-8603-4f3562e44418",
						Attempt:   0,
					},
					Hostname: "sandboxHostname",
				},
				runtimeHandler: "runtimeHandler",
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().RunPodSandbox(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.RunPodSandboxRequest{
						RuntimeHandler: "runtimeHandler",
						Config: &criruntimev1alpha2.PodSandboxConfig{
							Metadata: &criruntimev1alpha2.PodSandboxMetadata{
								Name:      "pod-name",
								Namespace: "default",
								Uid:       "b924b248-6395-4415-8603-4f3562e44418",
								Attempt:   0,
							},
							Hostname: "sandboxHostname",
						},
					}),
				).Times(1).Return(nil, errMock)
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "success",
			args: args{
				config: &criruntimev1alpha2.PodSandboxConfig{
					Metadata: &criruntimev1alpha2.PodSandboxMetadata{
						Name:      "pod-name",
						Namespace: "default",
						Uid:       "b924b248-6395-4415-8603-4f3562e44418",
						Attempt:   0,
					},
					Hostname: "sandboxHostname",
				},
				runtimeHandler: "runtimeHandler",
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().RunPodSandbox(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.RunPodSandboxRequest{
						RuntimeHandler: "runtimeHandler",
						Config: &criruntimev1alpha2.PodSandboxConfig{
							Metadata: &criruntimev1alpha2.PodSandboxMetadata{
								Name:      "pod-name",
								Namespace: "default",
								Uid:       "b924b248-6395-4415-8603-4f3562e44418",
								Attempt:   0,
							},
							Hostname: "sandboxHostname",
						},
					}),
				).Times(1).Return(&criruntimev1alpha2.RunPodSandboxResponse{
					PodSandboxId: "podSandboxID",
				}, nil)
			},
			want:    "podSandboxID",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// the same in every test
			ctrl, client, cancel, w := newUnitTestCRIExtendedRuntimeServiceWrapper(t)
			defer cancel()
			defer ctrl.Finish()
			if tt.prepare != nil {
				tt.prepare(t, client)
			}
			got, err := w.RunPodSandbox(tt.args.config, tt.args.runtimeHandler)
			if (err != nil) != tt.wantErr {
				t.Errorf("extendedServiceRuntimeWrapper.RunPodSandbox() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("extendedServiceRuntimeWrapper.RunPodSandbox() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_extendedServiceRuntimeWrapper_StopPodSandbox(t *testing.T) {
	type args struct {
		podSandboxID string
	}
	tests := []struct {
		name    string
		prepare prepareFunc
		args    args
		wantErr bool
	}{
		{
			name: "error",
			args: args{
				podSandboxID: "podSandboxID",
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().StopPodSandbox(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.StopPodSandboxRequest{
						PodSandboxId: "podSandboxID",
					}),
				).Times(1).Return(nil, errMock)
			},
			wantErr: true,
		},
		{
			name: "success",
			args: args{
				podSandboxID: "podSandboxID",
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().StopPodSandbox(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.StopPodSandboxRequest{
						PodSandboxId: "podSandboxID",
					}),
				).Times(1).Return(&criruntimev1alpha2.StopPodSandboxResponse{}, nil)
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// the same in every test
			ctrl, client, cancel, w := newUnitTestCRIExtendedRuntimeServiceWrapper(t)
			defer cancel()
			defer ctrl.Finish()
			if tt.prepare != nil {
				tt.prepare(t, client)
			}
			if err := w.StopPodSandbox(tt.args.podSandboxID); (err != nil) != tt.wantErr {
				t.Errorf("extendedServiceRuntimeWrapper.StopPodSandbox() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_extendedServiceRuntimeWrapper_RemovePodSandbox(t *testing.T) {
	type args struct {
		podSandboxID string
	}
	tests := []struct {
		name    string
		prepare prepareFunc
		args    args
		wantErr bool
	}{
		{
			name: "error",
			args: args{
				podSandboxID: "podSandboxID",
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().RemovePodSandbox(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.RemovePodSandboxRequest{
						PodSandboxId: "podSandboxID",
					}),
				).Times(1).Return(nil, errMock)
			},
			wantErr: true,
		},
		{
			name: "error",
			args: args{
				podSandboxID: "podSandboxID",
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().RemovePodSandbox(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.RemovePodSandboxRequest{
						PodSandboxId: "podSandboxID",
					}),
				).Times(1).Return(&criruntimev1alpha2.RemovePodSandboxResponse{}, nil)
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// the same in every test
			ctrl, client, cancel, w := newUnitTestCRIExtendedRuntimeServiceWrapper(t)
			defer cancel()
			defer ctrl.Finish()
			if tt.prepare != nil {
				tt.prepare(t, client)
			}
			if err := w.RemovePodSandbox(tt.args.podSandboxID); (err != nil) != tt.wantErr {
				t.Errorf("extendedServiceRuntimeWrapper.RemovePodSandbox() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_extendedServiceRuntimeWrapper_PodSandboxStatus(t *testing.T) {
	type args struct {
		podSandboxID string
	}
	tests := []struct {
		name    string
		prepare prepareFunc
		args    args
		want    *criruntimev1alpha2.PodSandboxStatus
		wantErr bool
	}{
		{
			name: "error",
			args: args{
				podSandboxID: "podSandboxID",
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().PodSandboxStatus(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.PodSandboxStatusRequest{
						PodSandboxId: "podSandboxID",
						Verbose:      false,
					}),
				).Times(1).Return(nil, errMock)
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "success",
			args: args{
				podSandboxID: "podSandboxID",
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().PodSandboxStatus(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.PodSandboxStatusRequest{
						PodSandboxId: "podSandboxID",
						Verbose:      false,
					}),
				).Times(1).Return(&criruntimev1alpha2.PodSandboxStatusResponse{
					Status: &criruntimev1alpha2.PodSandboxStatus{
						Id:    "podSandboxID",
						State: criruntimev1alpha2.PodSandboxState_SANDBOX_READY,
					},
				}, nil)
			},
			want: &criruntimev1alpha2.PodSandboxStatus{
				Id:    "podSandboxID",
				State: criruntimev1alpha2.PodSandboxState_SANDBOX_READY,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// the same in every test
			ctrl, client, cancel, w := newUnitTestCRIExtendedRuntimeServiceWrapper(t)
			defer cancel()
			defer ctrl.Finish()
			if tt.prepare != nil {
				tt.prepare(t, client)
			}
			got, err := w.PodSandboxStatus(tt.args.podSandboxID)
			if (err != nil) != tt.wantErr {
				t.Errorf("extendedServiceRuntimeWrapper.PodSandboxStatus() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extendedServiceRuntimeWrapper.PodSandboxStatus() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_extendedServiceRuntimeWrapper_PodSandboxStatusVerbose(t *testing.T) {

	type args struct {
		podSandboxID string
	}
	tests := []struct {
		name    string
		prepare prepareFunc
		args    args
		want    *criruntimev1alpha2.PodSandboxStatus
		want1   map[string]string
		wantErr bool
	}{
		{
			name: "error",
			args: args{
				podSandboxID: "podSandboxID",
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().PodSandboxStatus(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.PodSandboxStatusRequest{
						PodSandboxId: "podSandboxID",
						Verbose:      true,
					}),
				).Times(1).Return(nil, errMock)
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "success",
			args: args{
				podSandboxID: "podSandboxID",
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().PodSandboxStatus(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.PodSandboxStatusRequest{
						PodSandboxId: "podSandboxID",
						Verbose:      true,
					}),
				).Times(1).Return(&criruntimev1alpha2.PodSandboxStatusResponse{
					Status: &criruntimev1alpha2.PodSandboxStatus{
						Id:    "podSandboxID",
						State: criruntimev1alpha2.PodSandboxState_SANDBOX_READY,
					},
				}, nil)
			},
			want: &criruntimev1alpha2.PodSandboxStatus{
				Id:    "podSandboxID",
				State: criruntimev1alpha2.PodSandboxState_SANDBOX_READY,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// the same in every test
			ctrl, client, cancel, w := newUnitTestCRIExtendedRuntimeServiceWrapper(t)
			defer cancel()
			defer ctrl.Finish()
			if tt.prepare != nil {
				tt.prepare(t, client)
			}
			got, got1, err := w.PodSandboxStatusVerbose(tt.args.podSandboxID)
			if (err != nil) != tt.wantErr {
				t.Errorf("extendedServiceRuntimeWrapper.PodSandboxStatusVerbose() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extendedServiceRuntimeWrapper.PodSandboxStatusVerbose() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("extendedServiceRuntimeWrapper.PodSandboxStatusVerbose() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func Test_extendedServiceRuntimeWrapper_ListPodSandbox(t *testing.T) {
	type args struct {
		filter *criruntimev1alpha2.PodSandboxFilter
	}
	tests := []struct {
		name    string
		prepare prepareFunc
		args    args
		want    []*criruntimev1alpha2.PodSandbox
		wantErr bool
	}{
		{
			name: "error",
			args: args{
				filter: &criruntimev1alpha2.PodSandboxFilter{
					LabelSelector: map[string]string{
						"a": "b",
					},
				},
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().ListPodSandbox(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.ListPodSandboxRequest{
						Filter: &criruntimev1alpha2.PodSandboxFilter{
							LabelSelector: map[string]string{
								"a": "b",
							},
						},
					}),
				).Times(1).Return(nil, errMock)
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "success",
			args: args{
				filter: &criruntimev1alpha2.PodSandboxFilter{
					LabelSelector: map[string]string{
						"a": "b",
					},
				},
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().ListPodSandbox(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.ListPodSandboxRequest{
						Filter: &criruntimev1alpha2.PodSandboxFilter{
							LabelSelector: map[string]string{
								"a": "b",
							},
						},
					}),
				).Times(1).Return(&criruntimev1alpha2.ListPodSandboxResponse{
					Items: []*criruntimev1alpha2.PodSandbox{
						{
							Id:    "one",
							State: criruntimev1alpha2.PodSandboxState_SANDBOX_READY,
						},
						{
							Id:    "two",
							State: criruntimev1alpha2.PodSandboxState_SANDBOX_NOTREADY,
						},
					},
				}, nil)
			},
			want: []*criruntimev1alpha2.PodSandbox{
				{
					Id:    "one",
					State: criruntimev1alpha2.PodSandboxState_SANDBOX_READY,
				},
				{
					Id:    "two",
					State: criruntimev1alpha2.PodSandboxState_SANDBOX_NOTREADY,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// the same in every test
			ctrl, client, cancel, w := newUnitTestCRIExtendedRuntimeServiceWrapper(t)
			defer cancel()
			defer ctrl.Finish()
			if tt.prepare != nil {
				tt.prepare(t, client)
			}
			got, err := w.ListPodSandbox(tt.args.filter)
			if (err != nil) != tt.wantErr {
				t.Errorf("extendedServiceRuntimeWrapper.ListPodSandbox() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extendedServiceRuntimeWrapper.ListPodSandbox() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_extendedServiceRuntimeWrapper_PortForward(t *testing.T) {
	type args struct {
		req *criruntimev1alpha2.PortForwardRequest
	}
	tests := []struct {
		name    string
		prepare prepareFunc
		args    args
		want    *criruntimev1alpha2.PortForwardResponse
		wantErr bool
	}{
		{
			name: "error",
			args: args{
				req: &criruntimev1alpha2.PortForwardRequest{
					PodSandboxId: "podSandboxID",
					Port:         []int32{42},
				},
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().PortForward(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.PortForwardRequest{
						PodSandboxId: "podSandboxID",
						Port:         []int32{42},
					}),
				).Times(1).Return(nil, errMock)
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "success",
			args: args{
				req: &criruntimev1alpha2.PortForwardRequest{
					PodSandboxId: "podSandboxID",
					Port:         []int32{42},
				},
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().PortForward(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.PortForwardRequest{
						PodSandboxId: "podSandboxID",
						Port:         []int32{42},
					}),
				).Times(1).Return(&criruntimev1alpha2.PortForwardResponse{
					Url: "pick up port forward request here",
				}, nil)
			},
			want: &criruntimev1alpha2.PortForwardResponse{
				Url: "pick up port forward request here",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// the same in every test
			ctrl, client, cancel, w := newUnitTestCRIExtendedRuntimeServiceWrapper(t)
			defer cancel()
			defer ctrl.Finish()
			if tt.prepare != nil {
				tt.prepare(t, client)
			}
			got, err := w.PortForward(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("extendedServiceRuntimeWrapper.PortForward() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extendedServiceRuntimeWrapper.PortForward() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_extendedServiceRuntimeWrapper_ContainerStats(t *testing.T) {
	type args struct {
		containerID string
	}
	tests := []struct {
		name    string
		prepare prepareFunc
		args    args
		want    *criruntimev1alpha2.ContainerStats
		wantErr bool
	}{
		{
			name: "error",
			args: args{
				containerID: "containerID",
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().ContainerStats(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.ContainerStatsRequest{
						ContainerId: "containerID",
					}),
				).Times(1).Return(nil, errMock)
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "success",
			args: args{
				containerID: "containerID",
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().ContainerStats(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.ContainerStatsRequest{
						ContainerId: "containerID",
					}),
				).Times(1).Return(&criruntimev1alpha2.ContainerStatsResponse{
					Stats: &criruntimev1alpha2.ContainerStats{
						Attributes: &criruntimev1alpha2.ContainerAttributes{
							Id: "containerID",
						},
					},
				}, nil)
			},
			want: &criruntimev1alpha2.ContainerStats{
				Attributes: &criruntimev1alpha2.ContainerAttributes{
					Id: "containerID",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// the same in every test
			ctrl, client, cancel, w := newUnitTestCRIExtendedRuntimeServiceWrapper(t)
			defer cancel()
			defer ctrl.Finish()
			if tt.prepare != nil {
				tt.prepare(t, client)
			}
			got, err := w.ContainerStats(tt.args.containerID)
			if (err != nil) != tt.wantErr {
				t.Errorf("extendedServiceRuntimeWrapper.ContainerStats() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extendedServiceRuntimeWrapper.ContainerStats() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_extendedServiceRuntimeWrapper_ListContainerStats(t *testing.T) {
	type args struct {
		filter *criruntimev1alpha2.ContainerStatsFilter
	}
	tests := []struct {
		name    string
		prepare prepareFunc
		args    args
		want    []*criruntimev1alpha2.ContainerStats
		wantErr bool
	}{
		{
			name: "error",
			args: args{
				filter: &criruntimev1alpha2.ContainerStatsFilter{
					LabelSelector: map[string]string{
						"a": "b",
					},
				},
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().ListContainerStats(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.ListContainerStatsRequest{
						Filter: &criruntimev1alpha2.ContainerStatsFilter{
							LabelSelector: map[string]string{
								"a": "b",
							},
						},
					}),
				).Times(1).Return(nil, errMock)
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "error",
			args: args{
				filter: &criruntimev1alpha2.ContainerStatsFilter{
					LabelSelector: map[string]string{
						"a": "b",
					},
				},
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().ListContainerStats(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.ListContainerStatsRequest{
						Filter: &criruntimev1alpha2.ContainerStatsFilter{
							LabelSelector: map[string]string{
								"a": "b",
							},
						},
					}),
				).Times(1).Return(&criruntimev1alpha2.ListContainerStatsResponse{
					Stats: []*criruntimev1alpha2.ContainerStats{
						{
							Attributes: &criruntimev1alpha2.ContainerAttributes{
								Id: "one",
								Labels: map[string]string{
									"a": "b",
								},
							},
						},
						{
							Attributes: &criruntimev1alpha2.ContainerAttributes{
								Id: "two",
								Labels: map[string]string{
									"a": "b",
								},
							},
						},
					},
				}, nil)
			},
			want: []*criruntimev1alpha2.ContainerStats{
				{
					Attributes: &criruntimev1alpha2.ContainerAttributes{
						Id: "one",
						Labels: map[string]string{
							"a": "b",
						},
					},
				},
				{
					Attributes: &criruntimev1alpha2.ContainerAttributes{
						Id: "two",
						Labels: map[string]string{
							"a": "b",
						},
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// the same in every test
			ctrl, client, cancel, w := newUnitTestCRIExtendedRuntimeServiceWrapper(t)
			defer cancel()
			defer ctrl.Finish()
			if tt.prepare != nil {
				tt.prepare(t, client)
			}
			got, err := w.ListContainerStats(tt.args.filter)
			if (err != nil) != tt.wantErr {
				t.Errorf("extendedServiceRuntimeWrapper.ListContainerStats() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extendedServiceRuntimeWrapper.ListContainerStats() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_extendedServiceRuntimeWrapper_UpdateRuntimeConfig(t *testing.T) {
	type args struct {
		runtimeConfig *criruntimev1alpha2.RuntimeConfig
	}
	tests := []struct {
		name    string
		prepare prepareFunc
		args    args
		wantErr bool
	}{
		{
			name: "error",
			args: args{
				runtimeConfig: &criruntimev1alpha2.RuntimeConfig{
					NetworkConfig: &criruntimev1alpha2.NetworkConfig{
						PodCidr: "10.10.10.0/24",
					},
				},
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().UpdateRuntimeConfig(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.UpdateRuntimeConfigRequest{
						RuntimeConfig: &criruntimev1alpha2.RuntimeConfig{
							NetworkConfig: &criruntimev1alpha2.NetworkConfig{
								PodCidr: "10.10.10.0/24",
							},
						},
					}),
				).Times(1).Return(nil, errMock)
			},
			wantErr: true,
		},
		{
			name: "success",
			args: args{
				runtimeConfig: &criruntimev1alpha2.RuntimeConfig{
					NetworkConfig: &criruntimev1alpha2.NetworkConfig{
						PodCidr: "10.10.10.0/24",
					},
				},
			},
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().UpdateRuntimeConfig(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.UpdateRuntimeConfigRequest{
						RuntimeConfig: &criruntimev1alpha2.RuntimeConfig{
							NetworkConfig: &criruntimev1alpha2.NetworkConfig{
								PodCidr: "10.10.10.0/24",
							},
						},
					}),
				).Times(1).Return(&criruntimev1alpha2.UpdateRuntimeConfigResponse{}, nil)
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// the same in every test
			ctrl, client, cancel, w := newUnitTestCRIExtendedRuntimeServiceWrapper(t)
			defer cancel()
			defer ctrl.Finish()
			if tt.prepare != nil {
				tt.prepare(t, client)
			}
			if err := w.UpdateRuntimeConfig(tt.args.runtimeConfig); (err != nil) != tt.wantErr {
				t.Errorf("extendedServiceRuntimeWrapper.UpdateRuntimeConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_extendedServiceRuntimeWrapper_Status(t *testing.T) {
	tests := []struct {
		name    string
		prepare prepareFunc
		want    *criruntimev1alpha2.RuntimeStatus
		wantErr bool
	}{
		{
			name: "error",
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().Status(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.StatusRequest{
						Verbose: false,
					}),
				).Times(1).Return(nil, errMock)
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "success",
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().Status(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.StatusRequest{
						Verbose: false,
					}),
				).Times(1).Return(&criruntimev1alpha2.StatusResponse{
					Status: &criruntimev1alpha2.RuntimeStatus{
						Conditions: []*criruntimev1alpha2.RuntimeCondition{
							{
								Type:    "RuntimeReady",
								Status:  true,
								Reason:  "",
								Message: "",
							},
							{
								Type:    "NetworkReady",
								Status:  true,
								Reason:  "",
								Message: "",
							},
						},
					},
				}, nil)
			},
			want: &criruntimev1alpha2.RuntimeStatus{
				Conditions: []*criruntimev1alpha2.RuntimeCondition{
					{
						Type:    "RuntimeReady",
						Status:  true,
						Reason:  "",
						Message: "",
					},
					{
						Type:    "NetworkReady",
						Status:  true,
						Reason:  "",
						Message: "",
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// the same in every test
			ctrl, client, cancel, w := newUnitTestCRIExtendedRuntimeServiceWrapper(t)
			defer cancel()
			defer ctrl.Finish()
			if tt.prepare != nil {
				tt.prepare(t, client)
			}
			got, err := w.Status()
			if (err != nil) != tt.wantErr {
				t.Errorf("extendedServiceRuntimeWrapper.Status() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extendedServiceRuntimeWrapper.Status() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_extendedServiceRuntimeWrapper_StatusVerbose(t *testing.T) {
	tests := []struct {
		name    string
		prepare prepareFunc
		want    *criruntimev1alpha2.RuntimeStatus
		want1   map[string]string
		wantErr bool
	}{
		{
			name: "error",
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().Status(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.StatusRequest{
						Verbose: true,
					}),
				).Times(1).Return(nil, errMock)
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "success",
			prepare: func(t *testing.T, c *mockcri.MockRuntimeServiceClient) {
				c.EXPECT().Status(
					gomock.Any(),
					gomock.Eq(&criruntimev1alpha2.StatusRequest{
						Verbose: true,
					}),
				).Times(1).Return(&criruntimev1alpha2.StatusResponse{
					Status: &criruntimev1alpha2.RuntimeStatus{
						Conditions: []*criruntimev1alpha2.RuntimeCondition{
							{
								Type:    "RuntimeReady",
								Status:  true,
								Reason:  "",
								Message: "",
							},
							{
								Type:    "NetworkReady",
								Status:  true,
								Reason:  "",
								Message: "",
							},
						},
					},
					Info: map[string]string{
						"verobse": "output",
					},
				}, nil)
			},
			want: &criruntimev1alpha2.RuntimeStatus{
				Conditions: []*criruntimev1alpha2.RuntimeCondition{
					{
						Type:    "RuntimeReady",
						Status:  true,
						Reason:  "",
						Message: "",
					},
					{
						Type:    "NetworkReady",
						Status:  true,
						Reason:  "",
						Message: "",
					},
				},
			},
			want1: map[string]string{
				"verobse": "output",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// the same in every test
			ctrl, client, cancel, w := newUnitTestCRIExtendedRuntimeServiceWrapper(t)
			defer cancel()
			defer ctrl.Finish()
			if tt.prepare != nil {
				tt.prepare(t, client)
			}
			got, got1, err := w.StatusVerbose()
			if (err != nil) != tt.wantErr {
				t.Errorf("extendedServiceRuntimeWrapper.StatusVerbose() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extendedServiceRuntimeWrapper.StatusVerbose() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("extendedServiceRuntimeWrapper.StatusVerbose() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
