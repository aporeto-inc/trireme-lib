package ipsetmanager

import (
	"reflect"
	"testing"
)

const (
	service     = "blah"
	ip192_0_2_1 = "192.0.2.1"
	ip192_0_2_2 = "192.0.2.2"
	ip192_0_2_3 = "192.0.2.3"
)

func Test_handler_deleteDynamicAddresses(t *testing.T) {
	type args struct {
		ips       []string
		serviceID string
	}

	tests := []struct {
		name                 string
		args                 args
		existingDynamicAddrs map[string][]string
		wantEntry            bool
		wantIPs              []string
	}{
		{
			name: "entry does not exist",
			args: args{
				ips:       []string{ip192_0_2_1},
				serviceID: service,
			},
			existingDynamicAddrs: map[string][]string{},
			wantEntry:            false,
			wantIPs:              nil,
		},
		{
			name: "entry is empty",
			args: args{
				ips:       []string{ip192_0_2_1},
				serviceID: service,
			},
			existingDynamicAddrs: map[string][]string{
				service: {},
			},
			wantEntry: true,
			wantIPs:   []string{},
		},
		{
			name: "entry not in existing set",
			args: args{
				ips:       []string{ip192_0_2_1},
				serviceID: service,
			},
			existingDynamicAddrs: map[string][]string{
				service: {
					ip192_0_2_2,
					ip192_0_2_3,
				},
			},
			wantEntry: true,
			wantIPs:   []string{ip192_0_2_2, ip192_0_2_3},
		},
		{
			name: "entry is removed from set",
			args: args{
				ips:       []string{ip192_0_2_2},
				serviceID: service,
			},
			existingDynamicAddrs: map[string][]string{
				service: {
					ip192_0_2_1,
					ip192_0_2_2,
					ip192_0_2_3,
				},
			},
			wantEntry: true,
			wantIPs:   []string{ip192_0_2_1, ip192_0_2_3},
		},
		{
			name: "entries are removed from set",
			args: args{
				ips:       []string{ip192_0_2_1, ip192_0_2_3},
				serviceID: service,
			},
			existingDynamicAddrs: map[string][]string{
				service: {
					ip192_0_2_1,
					ip192_0_2_2,
					ip192_0_2_3,
				},
			},
			wantEntry: true,
			wantIPs:   []string{ip192_0_2_2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipv4Handler.dynamicUpdates = tt.existingDynamicAddrs
			ipv4Handler.deleteDynamicAddresses(tt.args.ips, tt.args.serviceID)
			have, ok := ipv4Handler.dynamicUpdates[tt.args.serviceID]
			if ok != tt.wantEntry {
				t.Errorf("%q wantEntry: %#v, haveEntry: %#v", tt.args.serviceID, tt.wantEntry, ok)
			}
			if !reflect.DeepEqual(tt.wantIPs, have) {
				t.Errorf("want: %#v, have: %#v", tt.wantIPs, have)
			}
		})
	}
}

func Test_handler_updateDynamicAddresses(t *testing.T) {
	type args struct {
		ips       []string
		serviceID string
	}

	tests := []struct {
		name                 string
		args                 args
		existingDynamicAddrs map[string][]string
		wantIPs              []string
	}{
		{
			name: "nothing to add should create empty service entry",
			args: args{
				ips:       []string{},
				serviceID: service,
			},
			existingDynamicAddrs: map[string][]string{},
			wantIPs:              []string{},
		},
		{
			name: "en empty entry should simply add the IPs",
			args: args{
				ips:       []string{ip192_0_2_1, ip192_0_2_2},
				serviceID: service,
			},
			existingDynamicAddrs: map[string][]string{},
			wantIPs:              []string{ip192_0_2_1, ip192_0_2_2},
		},
		{
			name: "different IPs should always get added to the list",
			args: args{
				ips:       []string{ip192_0_2_2, ip192_0_2_3},
				serviceID: service,
			},
			existingDynamicAddrs: map[string][]string{
				service: {ip192_0_2_1},
			},
			wantIPs: []string{ip192_0_2_1, ip192_0_2_2, ip192_0_2_3},
		},
		{
			name: "existing IPs should not be added",
			args: args{
				ips:       []string{ip192_0_2_2, ip192_0_2_3},
				serviceID: service,
			},
			existingDynamicAddrs: map[string][]string{
				service: {ip192_0_2_2, ip192_0_2_3},
			},
			wantIPs: []string{ip192_0_2_2, ip192_0_2_3},
		},
		{
			name: "mix of existing and new",
			args: args{
				ips:       []string{ip192_0_2_2, ip192_0_2_3},
				serviceID: service,
			},
			existingDynamicAddrs: map[string][]string{
				service: {ip192_0_2_1, ip192_0_2_2},
			},
			wantIPs: []string{ip192_0_2_1, ip192_0_2_2, ip192_0_2_3},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipv4Handler.dynamicUpdates = tt.existingDynamicAddrs
			ipv4Handler.updateDynamicAddresses(tt.args.ips, tt.args.serviceID)
			have, ok := ipv4Handler.dynamicUpdates[tt.args.serviceID]
			if !ok {
				t.Errorf("no entry for service %q", tt.args.serviceID)
			}
			if !reflect.DeepEqual(tt.wantIPs, have) {
				t.Errorf("want: %#v, have: %#v", tt.wantIPs, have)
			}
		})
	}
}
