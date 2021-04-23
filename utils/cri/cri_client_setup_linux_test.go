// +build linux

package cri

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
)

func Test_DetectCRIRuntimeEndpoint(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	path := filepath.Join(wd, "testdata", "var", "run", "crio", "crio.sock")

	if err := os.RemoveAll(path); err != nil {
		panic(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0777); err != nil {
		panic(err)
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		panic(err)
	}
	defer l.Close() // nolint

	oldGetHostPath := getHostPath
	defer func() {
		getHostPath = oldGetHostPath
	}()
	tests := []struct {
		name        string
		getHostPath func(string) string
		want        string
		runType     Type
		wantErr     bool
	}{
		{
			name: "failed to detect a runtime",
			getHostPath: func(path string) string {
				return filepath.Join(wd, "does-not-exist", path)
			},
			want:    "",
			runType: TypeNone,
			wantErr: true,
		},
		{
			name: "detected a runtime",
			getHostPath: func(path string) string {
				return filepath.Join(wd, "testdata", path)
			},
			want:    "unix://" + filepath.Join(wd, "testdata", "var", "run", "crio", "crio.sock"),
			runType: TypeCRIO,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getHostPath = tt.getHostPath
			got, rtype, err := DetectCRIRuntimeEndpoint()
			if (err != nil) != tt.wantErr {
				t.Errorf("DetectCRIRuntimeEndpoint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("DetectCRIRuntimeEndpoint() = %v, want %v", got, tt.want)
			}
			if rtype != tt.runType {
				t.Errorf("DetectCRIRuntimeEndpoint() = %v, want %v", rtype, tt.runType)
			}
		})
	}
}

func Test_getCRISocketAddr(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	path := filepath.Join(wd, "testdata", "var", "run", "crio", "crio.sock")

	if err := os.RemoveAll(path); err != nil {
		panic(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0777); err != nil {
		panic(err)
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		panic(err)
	}
	defer l.Close() // nolint

	oldGetHostPath := getHostPath
	defer func() {
		getHostPath = oldGetHostPath
	}()
	type args struct {
		criRuntimeEndpoint string
	}
	tests := []struct {
		name        string
		getHostPath func(string) string
		args        args
		want        string
		wantErr     bool
	}{
		{
			name: "auto-detected runtime should return without any error if it succeeds",
			args: args{
				criRuntimeEndpoint: "", // empty string enables auto-detection
			},
			getHostPath: func(path string) string {
				return filepath.Join(wd, "testdata", path)
			},
			want:    filepath.Join(wd, "testdata", "var", "run", "crio", "crio.sock"),
			wantErr: false,
		},
		{
			name: "if auto-detection is enabled and fails, we must fail",
			args: args{
				criRuntimeEndpoint: "", // empty string enables auto-detection
			},
			getHostPath: func(path string) string {
				return filepath.Join(wd, "does-not-exist", path)
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "we fail on tcp endpoints",
			args: args{
				criRuntimeEndpoint: "tcp://127.0.0.1:1234",
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "correct file paths to a unix socket should work",
			args: args{
				criRuntimeEndpoint: filepath.Join(wd, "testdata", "var", "run", "crio", "crio.sock"),
			},
			want:    filepath.Join(wd, "testdata", "var", "run", "crio", "crio.sock"),
			wantErr: false,
		},
		{
			name: "frakti is not supported",
			args: args{
				criRuntimeEndpoint: "/var/run/frakti.sock",
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "frakti is not supported",
			args: args{
				criRuntimeEndpoint: "/var/run/frakti.sock",
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "URL parsing of endpoint fails",
			args: args{
				criRuntimeEndpoint: string([]byte{0x7f}),
			},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getHostPath = tt.getHostPath
			got, err := getCRISocketAddr(tt.args.criRuntimeEndpoint)
			if (err != nil) != tt.wantErr {
				t.Errorf("getCRISocketAddr() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getCRISocketAddr() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_connectCRISocket(t *testing.T) {
	oldConnectTimeout := connectTimeout
	defer func() {
		connectTimeout = oldConnectTimeout
	}()
	type args struct {
		ctx  context.Context
		addr string
	}
	tests := []struct {
		name           string
		args           args
		connectTimeout time.Duration
		runServer      bool
		wantErr        bool
	}{
		{
			name: "no timeout produces a canceled context which must always error",
			args: args{
				ctx:  context.Background(),
				addr: "",
			},
			connectTimeout: 0,
			wantErr:        true,
		},
		{
			name: "successful connection to a unix server listening",
			args: args{
				ctx:  context.Background(),
				addr: "@aporeto_cri_grpc_connect_test",
			},
			runServer:      true,
			connectTimeout: time.Second * 10,
			wantErr:        false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			connectTimeout = tt.connectTimeout
			ctx, cancel := context.WithCancel(tt.args.ctx)
			defer cancel()
			if tt.runServer {
				s := grpc.NewServer()
				defer s.Stop()
				go func() {
					l, err := (&net.ListenConfig{}).Listen(ctx, "unix", tt.args.addr)
					if err != nil {
						panic(err)
					}
					s.Serve(l) // nolint: errcheck
				}()
			}
			_, err := connectCRISocket(ctx, tt.args.addr)
			if (err != nil) != tt.wantErr {
				t.Errorf("connectCRISocket() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestNewCRIRuntimeServiceClient(t *testing.T) {
	oldConnectTimeout := connectTimeout
	oldCallTimeout := callTimeout
	defer func() {
		connectTimeout = oldConnectTimeout
		callTimeout = oldCallTimeout
	}()
	type args struct {
		ctx                context.Context
		criRuntimeEndpoint string
	}
	tests := []struct {
		name           string
		args           args
		connectTimeout time.Duration
		callTimeout    time.Duration
		runServer      bool
		wantErr        bool
	}{
		{
			name: "fails on getting socket path",
			args: args{
				ctx:                context.Background(),
				criRuntimeEndpoint: string([]byte{0x7f}),
			},
			runServer: false,
			wantErr:   true,
		},
		{
			name: "success",
			args: args{
				ctx:                context.Background(),
				criRuntimeEndpoint: "unix:@aporeto_cri_grpc_connect_test1",
			},
			connectTimeout: time.Second * 10,
			callTimeout:    time.Second * 5,
			runServer:      true,
			wantErr:        false,
		},
		{
			name: "fails creating the ExtendedRuntimeService",
			args: args{
				ctx:                context.Background(),
				criRuntimeEndpoint: "unix:@aporeto_cri_grpc_connect_test2",
			},
			connectTimeout: time.Second * 10,
			callTimeout:    0, // call timeout must not be 0
			runServer:      true,
			wantErr:        true,
		},
		{
			name: "fails connecting to the grpc socket",
			args: args{
				ctx:                context.Background(),
				criRuntimeEndpoint: "unix:@aporeto_cri_grpc_connect_test3",
			},
			connectTimeout: 0,
			runServer:      true,
			wantErr:        true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			connectTimeout = tt.connectTimeout
			callTimeout = tt.callTimeout
			ctx, cancel := context.WithCancel(tt.args.ctx)
			defer cancel()
			if tt.runServer {
				s := grpc.NewServer()
				defer s.Stop()
				go func() {
					l, err := (&net.ListenConfig{}).Listen(ctx, "unix", strings.TrimPrefix(strings.TrimPrefix(tt.args.criRuntimeEndpoint, "unix:"), "//"))
					if err != nil {
						panic(err)
					}
					s.Serve(l) // nolint: errcheck
				}()
			}
			_, err := NewCRIRuntimeServiceClient(ctx, tt.args.criRuntimeEndpoint)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewCRIRuntimeServiceClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
