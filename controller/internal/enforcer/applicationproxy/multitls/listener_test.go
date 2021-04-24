// Package multitls implements a listener which can serve different TLS servers depending on their original destination.
// A connection might be meant for the public application port or for the normal service port. With this listener here
// we can serve different TLS servers on the same listener/port by just inspecting the connection.
package multitls

import (
	"crypto/tls"
	"fmt"
	"net"
	"reflect"
	"testing"

	gomock "github.com/golang/mock/gomock"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/markedconn"
)

func Test_listener_Accept(t *testing.T) {
	ctrl := gomock.NewController(t)

	l := NewMockListener(ctrl)

	mc := &markedconn.ProxiedConnection{}
	internal := &tls.Config{ServerName: "internal"}
	public := &tls.Config{ServerName: "public"}

	// Assert that Bar() is invoked.
	defer ctrl.Finish()
	type fields struct {
		Listener   net.Listener
		publicPort int
		internal   *tls.Config
		public     *tls.Config
	}
	tests := []struct {
		name    string
		fields  fields
		want    net.Conn
		wantErr bool
		f       func()
	}{
		{
			name: "accept fails in upstream listener",
			fields: fields{
				Listener: l,
			},
			f: func() {
				l.EXPECT().Accept().Times(1).Return(nil, fmt.Errorf("the error"))
			},
			wantErr: true,
		},
		{
			name: "connection is not a proxied connection",
			fields: fields{
				Listener: l,
			},
			f: func() {
				l.EXPECT().Accept().Times(1).Return(NewMockConn(ctrl), nil)
			},
			wantErr: true,
		},
		{
			name: "connection is internal",
			fields: fields{
				Listener: l,
				internal: internal,
			},
			f: func() {
				l.EXPECT().Accept().Times(1).Return(mc, nil)
			},
			want:    tls.Server(mc, internal),
			wantErr: false,
		},
		{
			name: "public port does not match public port of connection",
			fields: fields{
				Listener:   l,
				public:     public,
				internal:   internal,
				publicPort: 8888,
			},
			f: func() {
				l.EXPECT().Accept().Times(1).Return(mc, nil)
			},
			want:    tls.Server(mc, internal),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &listener{
				Listener:   tt.fields.Listener,
				publicPort: tt.fields.publicPort,
				internal:   tt.fields.internal,
				public:     tt.fields.public,
			}
			tt.f()
			got, err := l.Accept()
			if (err != nil) != tt.wantErr {
				t.Errorf("listener.Accept() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("listener.Accept() = %v, want %v", got, tt.want)
			}
		})
	}
}
