package fqdn

import (
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
)

func TestFind(t *testing.T) {
	ip41 := net.ParseIP("192.0.2.1")
	if ip41 == nil {
		panic("failed to parse ip41")
	}
	ip42 := net.ParseIP("192.0.2.2")
	if ip42 == nil {
		panic("failed to parse ip42")
	}
	ip61 := net.ParseIP("2001:db8::68")
	if ip61 == nil {
		panic("failed to parse ip61")
	}
	ip62 := net.ParseIP("2001:db8::69")
	if ip62 == nil {
		panic("failed to parse ip62")
	}
	invalidIP := (net.IP)([]byte("012345678901234567890"))
	tests := []struct {
		name          string
		want          string
		osHostname    func() (string, error)
		netLookupIP   func(string) ([]net.IP, error)
		netLookupAddr func(string) ([]string, error)
		pre           func()
	}{
		{
			name: "os.Hostname errors",
			want: unknownHostname,
			osHostname: func() (string, error) {
				return "", fmt.Errorf("failed to get hostname from the kernel")
			},
		},
		{
			name: "net.LookupIP errors",
			want: constMyhostname,
			osHostname: func() (string, error) {
				return constMyhostname, nil
			},
			netLookupIP: func(string) ([]net.IP, error) {
				return nil, fmt.Errorf("massive error")
			},
		},
		{
			name: "net.LookupIP returns empty",
			want: constMyhostname,
			osHostname: func() (string, error) {
				return constMyhostname, nil
			},
			netLookupIP: func(string) ([]net.IP, error) {
				return []net.IP{}, nil
			},
		},
		{
			name: "net.LookupIP returns addresses which cannot be reversed looked up",
			want: constMyhostname,
			osHostname: func() (string, error) {
				return constMyhostname, nil
			},
			netLookupIP: func(string) ([]net.IP, error) {
				return []net.IP{ip41, ip42}, nil
			},
		},
		{
			// NOTE: this will not cover the branch if `ipv4.MarshalText()` errors, because that is an impossible branch
			name: "net.LookupIP returns an invalid IP address",
			want: constMyhostname,
			osHostname: func() (string, error) {
				return constMyhostname, nil
			},
			netLookupIP: func(string) ([]net.IP, error) {
				return []net.IP{invalidIP}, nil
			},
		},
		{
			name: "net.LookupIP returns IPv6 addresses which cannot be reversed looked up",
			want: constMyhostname,
			osHostname: func() (string, error) {
				return constMyhostname, nil
			},
			netLookupIP: func(string) ([]net.IP, error) {
				return []net.IP{ip61, ip62}, nil
			},
		},
		{
			name: "if an alternative hostname is set, return with this instead",
			want: constHostname,
			pre: func() {
				InitializeAlternativeHostname(constHostname)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.pre != nil {
				tt.pre()
			}
			if tt.osHostname != nil {
				osHostname = tt.osHostname
			} else {
				osHostname = os.Hostname
			}
			if tt.netLookupIP != nil {
				netLookupIP = tt.netLookupIP
			} else {
				netLookupIP = net.LookupIP
			}
			if tt.netLookupAddr != nil {
				netLookupAddr = tt.netLookupAddr
			} else {
				netLookupAddr = net.LookupAddr
			}
			if got := Find(); got != tt.want {
				t.Errorf("FindFQDN() = %v, want %v", got, tt.want)
			}
			// reset everything after each run
			alternativeHostnameLock.Lock()
			defer alternativeHostnameLock.Unlock()
			alternativeHostname = ""
			alternativeHostnameOnce = &sync.Once{}
		})
	}
}

const (
	constHostname   = "alternative.hostname"
	constMyhostname = "myhostname"
)

func TestInitializeAlternativeHostname(t *testing.T) {
	type args struct {
		hostname string
	}
	tests := []struct {
		name string
		args args
		want string
		pre  func()
	}{
		{
			name: "set and success",
			args: args{hostname: constHostname},
			want: constHostname,
		},
		{
			name: "second initialize call will not override",
			args: args{hostname: "hostname2"},
			want: constHostname,
			pre: func() {
				InitializeAlternativeHostname(constHostname)
			},
		},
		{
			name: "an empty initialize call does not initialize it",
			args: args{hostname: constHostname},
			want: constHostname,
			pre: func() {
				InitializeAlternativeHostname("")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.pre != nil {
				tt.pre()
			}
			InitializeAlternativeHostname(tt.args.hostname)
			if got := getAlternativeHostname(); got != tt.want {
				t.Errorf("IntializeAlternativeHostname() = %v, want %v", got, tt.want)
			}
			// reset everything after each run
			alternativeHostnameLock.Lock()
			defer alternativeHostnameLock.Unlock()
			alternativeHostname = ""
			alternativeHostnameOnce = &sync.Once{}
		})
	}
}
