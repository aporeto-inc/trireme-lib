package collector

import (
	"testing"

	"go.aporeto.io/enforcerd/trireme-lib/policy"
)

func TestStatsUserHash(t *testing.T) {
	type args struct {
		userRecord *UserRecord
		hash       string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Test_StatsUserHash1",
			args: args{
				userRecord: &UserRecord{
					Namespace: "/_apotests",
					Claims: []string{
						"CN=b01a6042-437-allow",
						"O=b01a6042-437-allow",
					},
				},
				hash: "14815208496714115169",
			},
			wantErr: false,
		},
		{
			name: "Test_StatsUserHash2",
			args: args{
				userRecord: &UserRecord{
					Namespace: "/_apotests",
					Claims: []string{
						"CN=apotests-master-staging2 Root CA",
						"O=_apotests/b01a6042-437c-44ab-a17f-e14f6f915b87",
						"OU=aporeto-enforcerd",
					},
				},
				hash: "3750309273572959404",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := StatsUserHash(tt.args.userRecord); (err != nil) != tt.wantErr {
				t.Errorf("StatsUserHash() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.args.hash != tt.args.userRecord.ID {
				t.Errorf("Wanted %s but got %s", tt.args.hash, tt.args.userRecord.ID)
			}
		})
	}
}

func TestStatsFlowHash(t *testing.T) {
	type args struct {
		r *FlowRecord
	}
	tests := []struct {
		name            string
		args            args
		wantFlowhash    uint64
		wantContenthash uint64
	}{
		{
			name: "basic hash",
			args: args{
				r: &FlowRecord{
					ContextID:             "context",
					Namespace:             "ns",
					Source:                EndPoint{},
					Destination:           EndPoint{},
					Tags:                  []string{"tag=val"},
					DropReason:            "none",
					PolicyID:              "default",
					ObservedPolicyID:      "default",
					ServiceType:           policy.ServiceL3,
					ServiceID:             "svc",
					Count:                 1,
					Action:                policy.Accept,
					ObservedAction:        policy.Accept,
					ObservedActionType:    policy.ObserveContinue,
					L4Protocol:            7,
					SourceController:      "src-controller",
					DestinationController: "dst-controller",
					RuleName:              "1",
				},
			},
			wantFlowhash:    11145182160106660097,
			wantContenthash: 5951126184511352450,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotFlowhash, gotContenthash := StatsFlowHash(tt.args.r)
			if gotFlowhash != tt.wantFlowhash {
				t.Errorf("StatsFlowHash() gotFlowhash = %v, want %v", gotFlowhash, tt.wantFlowhash)
			}
			if gotContenthash != tt.wantContenthash {
				t.Errorf("StatsFlowHash() gotContenthash = %v, want %v", gotContenthash, tt.wantContenthash)
			}

			gothash := StatsFlowContentHash(tt.args.r)
			if gothash != tt.wantContenthash {
				t.Errorf("StatsFlowHash() gothash = %v, want %v", gothash, tt.wantContenthash)
			}
		})
	}
}
