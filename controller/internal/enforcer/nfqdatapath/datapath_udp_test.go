package nfqdatapath

import (
	"fmt"
	"net"
	"reflect"
	"testing"

	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/nfqdatapath/afinetrawsocket"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/policy"
)

func TestDatapath_checkForApplicationACLs(t *testing.T) {

	type args struct {
		p *packet.Packet
	}

	prevRawSocket := GetUDPRawSocket
	defer func() {
		GetUDPRawSocket = prevRawSocket
	}()
	GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
		return nil, nil
	}

	udpPkt := []byte{0x45, 0x00, 0x00, 0x22, 0x4c, 0x0a, 0x40, 0x00, 0x40, 0x11, 0xa4, 0xa6, 0xc0, 0xa8, 0x64, 0x64, 0xc0, 0xa8, 0x64, 0x65, 0xaf, 0x3e, 0x1f, 0x95, 0x00, 0x0e, 0x98, 0xfd, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	p, err := packet.New(0, udpPkt, "0")
	if err != nil {
		fmt.Println("Error during packet creation", err)
	}
	tests := []struct {
		name       string
		args       args
		wantAction *policy.FlowPolicy
		wantErr    bool
		id         int
	}{
		{
			name: "Test external service (App) for udp with packet not in cache",
			args: args{
				p: p,
			},
			wantAction: nil,
			wantErr:    true,
			id:         1,
		},
		{
			name: "Test external service (App) for udp with packet in cache and accept",
			args: args{
				p: p,
			},
			wantAction: &policy.FlowPolicy{Action: policy.Accept, PolicyID: "2"},
			wantErr:    false,
			id:         2,
		},
		{
			name: "Test external service (App) for udp for packet in cache and reject",
			args: args{
				p: p,
			},
			wantAction: &policy.FlowPolicy{Action: policy.Reject, PolicyID: "1"},
			wantErr:    false,
			id:         3,
		},
		{
			name: "Test external service (App) for udp packet in net cache and accept",
			args: args{
				p: p,
			},
			wantAction: &policy.FlowPolicy{Action: policy.Accept, PolicyID: "3"},
			wantErr:    false,
			id:         4,
		},
		{
			name: "Test external service (App) for udp packet in net cache and reject",
			args: args{
				p: p,
			},
			wantAction: &policy.FlowPolicy{Action: policy.Reject, PolicyID: "4"},
			wantErr:    false,
			id:         5,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := secrets.NewPSKSecrets([]byte("Dummy Test Password"))
			appACL1 := policy.IPRule{
				Policy: &policy.FlowPolicy{
					Action:   policy.Reject,
					PolicyID: "1",
				},
				Address:  "10.0.0.0/8",
				Protocol: "udp",
				Port:     "80",
			}
			appACL2 := policy.IPRule{
				Policy: &policy.FlowPolicy{
					Action:   policy.Accept,
					PolicyID: "2",
				},
				Address:  "12.0.0.0/8",
				Protocol: "udp",
				Port:     "80",
			}

			netACL1 := policy.IPRule{
				Policy: &policy.FlowPolicy{
					Action:   policy.Accept,
					PolicyID: "3",
				},
				Address:  "20.0.0.0/8",
				Protocol: "udp",
				Port:     "80",
			}

			netACL2 := policy.IPRule{
				Policy: &policy.FlowPolicy{
					Action:   policy.Reject,
					PolicyID: "4",
				},
				Address:  "21.0.0.0/8",
				Protocol: "udp",
				Port:     "80",
			}

			plcy := policy.NewPUPolicy(
				"id1",
				policy.AllowAll,
				policy.IPRuleList{appACL1, appACL2},
				policy.IPRuleList{netACL1, netACL2},
				nil,
				nil,
				nil,
				nil,
				nil,
				nil,
				nil,
				nil,
				nil,
				nil,
				[]string{},
			)

			runtime := policy.NewPURuntime("", 0, "", nil, nil, common.ContainerPU, nil)

			collector := &collector.DefaultCollector{}

			// mock the call
			prevRawSocket := GetUDPRawSocket
			defer func() {
				GetUDPRawSocket = prevRawSocket
			}()
			GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
				return nil, nil
			}

			puInfo := policy.PUInfoFromPolicyAndRuntime("0", plcy, runtime)
			d := NewWithDefaults("SomeServerId", collector, nil, secret, constants.RemoteContainer, "/proc")
			d.Enforce("someServerID", puInfo)

			switch tt.id {
			case 1:
				tt.args.p.DestinationAddress = net.ParseIP("11.0.0.2")
				tt.args.p.DestinationPort = 80
				tt.args.p.SourcePort = 1234

			case 2:
				tt.args.p.DestinationAddress = net.ParseIP("12.0.0.2")
				tt.args.p.DestinationPort = 80
				tt.args.p.SourcePort = 1234

			case 3:
				tt.args.p.DestinationAddress = net.ParseIP("10.0.0.2")
				tt.args.p.DestinationPort = 80
				tt.args.p.SourcePort = 1234

			case 4:
				tt.args.p.DestinationAddress = net.ParseIP("20.0.0.2")
				tt.args.p.DestinationPort = 1234
				tt.args.p.SourcePort = 80

			case 5:
				tt.args.p.DestinationAddress = net.ParseIP("21.0.0.2")
				tt.args.p.DestinationPort = 1234
				tt.args.p.SourcePort = 80

			}

			gotAction, err := d.checkForApplicationACLs(tt.args.p)
			if (err != nil) != tt.wantErr {
				t.Errorf("Datapath.checkForApplicationACLs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotAction, tt.wantAction) {
				t.Errorf("Datapath.checkForApplicationACLs() = %v, want %v", gotAction, tt.wantAction)
			}
		})
	}
}

func TestDatapath_checkForExternalServices(t *testing.T) {

	type args struct {
		p *packet.Packet
	}

	prevRawSocket := GetUDPRawSocket
	defer func() {
		GetUDPRawSocket = prevRawSocket
	}()
	GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
		return nil, nil
	}

	udpPkt := []byte{0x45, 0x00, 0x00, 0x22, 0x4c, 0x0a, 0x40, 0x00, 0x40, 0x11, 0xa4, 0xa6, 0xc0, 0xa8, 0x64, 0x64, 0xc0, 0xa8, 0x64, 0x65, 0xaf, 0x3e, 0x1f, 0x95, 0x00, 0x0e, 0x98, 0xfd, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	p, err := packet.New(0, udpPkt, "0")
	if err != nil {
		fmt.Println("Error during packet creation", err)
	}
	tests := []struct {
		name       string
		args       args
		wantAction *policy.FlowPolicy
		wantErr    bool
		id         int
	}{
		{
			name: "Test external service (Net) for udp with packet not in cache",
			args: args{
				p: p,
			},
			wantAction: nil,
			wantErr:    true,
			id:         1,
		},
		{
			name: "Test external service (Net) for udp with packet in cache and accept",
			args: args{
				p: p,
			},
			wantAction: &policy.FlowPolicy{Action: policy.Accept, PolicyID: "3"},
			wantErr:    false,
			id:         2,
		},
		{
			name: "Test external service (Net) for udp for packet in cache and reject",
			args: args{
				p: p,
			},
			wantAction: &policy.FlowPolicy{Action: policy.Reject, PolicyID: "4"},
			wantErr:    false,
			id:         3,
		},
		{
			name: "Test external service (Net) for udp packet in net cache and accept",
			args: args{
				p: p,
			},
			wantAction: &policy.FlowPolicy{Action: policy.Accept, PolicyID: "2"},
			wantErr:    false,
			id:         4,
		},
		{
			name: "Test external service (Net) for udp packet in net cache and reject",
			args: args{
				p: p,
			},
			wantAction: &policy.FlowPolicy{Action: policy.Reject, PolicyID: "1"},
			wantErr:    false,
			id:         5,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := secrets.NewPSKSecrets([]byte("Dummy Test Password"))
			appACL1 := policy.IPRule{
				Policy: &policy.FlowPolicy{
					Action:   policy.Reject,
					PolicyID: "1",
				},
				Address:  "10.0.0.0/8",
				Protocol: "udp",
				Port:     "80",
			}
			appACL2 := policy.IPRule{
				Policy: &policy.FlowPolicy{
					Action:   policy.Accept,
					PolicyID: "2",
				},
				Address:  "12.0.0.0/8",
				Protocol: "udp",
				Port:     "80",
			}

			netACL1 := policy.IPRule{
				Policy: &policy.FlowPolicy{
					Action:   policy.Accept,
					PolicyID: "3",
				},
				Address:  "20.0.0.0/8",
				Protocol: "udp",
				Port:     "80",
			}

			netACL2 := policy.IPRule{
				Policy: &policy.FlowPolicy{
					Action:   policy.Reject,
					PolicyID: "4",
				},
				Address:  "21.0.0.0/8",
				Protocol: "udp",
				Port:     "80",
			}

			plcy := policy.NewPUPolicy(
				"id1",
				policy.AllowAll,
				policy.IPRuleList{appACL1, appACL2},
				policy.IPRuleList{netACL1, netACL2},
				nil,
				nil,
				nil,
				nil,
				nil,
				nil,
				nil,
				nil,
				nil,
				nil,
				[]string{},
			)

			runtime := policy.NewPURuntime("", 0, "", nil, nil, common.ContainerPU, nil)

			collector := &collector.DefaultCollector{}

			// mock the call
			prevRawSocket := GetUDPRawSocket
			defer func() {
				GetUDPRawSocket = prevRawSocket
			}()
			GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
				return nil, nil
			}

			puInfo := policy.PUInfoFromPolicyAndRuntime("0", plcy, runtime)
			d := NewWithDefaults("SomeServerId", collector, nil, secret, constants.RemoteContainer, "/proc")
			d.Enforce("someServerID", puInfo)

			switch tt.id {
			case 1:
				tt.args.p.SourceAddress = net.ParseIP("11.0.0.2")
				tt.args.p.DestinationPort = 80
				tt.args.p.SourcePort = 1234

			case 2:
				tt.args.p.SourceAddress = net.ParseIP("20.0.0.2")
				tt.args.p.DestinationPort = 80
				tt.args.p.SourcePort = 1234

			case 3:
				tt.args.p.SourceAddress = net.ParseIP("21.0.0.2")
				tt.args.p.DestinationPort = 80
				tt.args.p.SourcePort = 1234

			case 4:
				tt.args.p.SourceAddress = net.ParseIP("12.0.0.2")
				tt.args.p.SourcePort = 80
				tt.args.p.DestinationPort = 1244

			case 5:
				tt.args.p.SourceAddress = net.ParseIP("10.0.0.2")
				tt.args.p.SourcePort = 80
				tt.args.p.DestinationPort = 1244

			}

			gotAction, err := d.checkForExternalServices(tt.args.p)
			if (err != nil) != tt.wantErr {
				t.Errorf("Datapath.checkForExternalServices() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotAction, tt.wantAction) {
				t.Errorf("Datapath.checkForExternalServices() = %v, want %v", gotAction, tt.wantAction)
			}
		})
	}
}
