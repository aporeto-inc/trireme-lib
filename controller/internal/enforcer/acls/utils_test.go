package acls

import (
	"net"
	"reflect"
	"testing"
)

func TestParseAddress(t *testing.T) {
	ipv4 := net.ParseIP("192.0.2.1")
	if ipv4 == nil {
		panic("ipv4 address invalid at test prerequisite")
	}
	ipv6 := net.ParseIP("2001:db8::1")
	if ipv6 == nil {
		panic("ipv6 address invalid at test prerequisite")
	}
	type args struct {
		address string
	}
	tests := []struct {
		name    string
		args    args
		want    *Address
		wantErr bool
	}{
		{
			name: "invalid IP address",
			args: args{
				address: "invalid IP address",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "invalid network mask",
			args: args{
				address: "192.0.2.0/invalid",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "IPv4 address without mask",
			args: args{
				address: "192.0.2.1",
			},
			want: &Address{
				IP:      ipv4,
				Mask:    32,
				NoMatch: false,
			},
		},
		{
			name: "IPv6 address without mask",
			args: args{
				address: "2001:db8::1",
			},
			want: &Address{
				IP:      ipv6,
				Mask:    128,
				NoMatch: false,
			},
		},
		{
			name: "IPv4 address with mask",
			args: args{
				address: "192.0.2.1/24",
			},
			want: &Address{
				IP:      ipv4,
				Mask:    24,
				NoMatch: false,
			},
		},
		{
			name: "IPv6 address with mask",
			args: args{
				address: "2001:db8::1/64",
			},
			want: &Address{
				IP:      ipv6,
				Mask:    64,
				NoMatch: false,
			},
		},
		{
			name: "IPv4 address with mask and nomatch",
			args: args{
				address: "!192.0.2.1/24",
			},
			want: &Address{
				IP:      ipv4,
				Mask:    24,
				NoMatch: true,
			},
		},
		{
			name: "IPv6 address with mask and nomatch",
			args: args{
				address: "!2001:db8::1/64",
			},
			want: &Address{
				IP:      ipv6,
				Mask:    64,
				NoMatch: true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseAddress(tt.args.address)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseAddress() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseAddress() = %v, want %v", got, tt.want)
			}
		})
	}
}
