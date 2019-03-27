package extractors

import (
	"reflect"
	"strconv"
	"testing"

	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/policy"
)

func createDummyPolicy(event *common.EventInfo) *policy.PURuntime {
	runtimeTags := policy.NewTagStore()
	runtimeTags.AppendKeyValue("@sys:test", "valid")
	runtimeTags.AppendKeyValue("@app:linux:test", "valid")
	runtimeIps := policy.ExtendedMap{"bridge": "0.0.0.0/0"}
	options := &policy.OptionsType{
		CgroupName: event.PUID,
		CgroupMark: strconv.Itoa(104),
		UserID:     event.PUID,
		Services:   nil,
	}
	return policy.NewPURuntime(event.Name, int(event.PID), "", runtimeTags, runtimeIps, common.UIDLoginPU, options)
}
func TestUIDMetadataExtractor(t *testing.T) {
	var marshaledgot, marshalledwant []byte
	type args struct {
		event *common.EventInfo
	}
	e := &common.EventInfo{
		PID:      100,
		Name:     "TestPU",
		Tags:     []string{"test=valid"},
		PUID:     "TestPU",
		Services: nil,
		PUType:   common.LinuxProcessPU,
	}
	tests := []struct {
		name    string
		args    args
		want    *policy.PURuntime
		wantErr bool
	}{
		{
			name: "Invalid Tags",
			args: args{
				event: &common.EventInfo{
					Tags: []string{"InvalidTagFormat"},
				},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Valid Tags",
			args: args{
				event: e,
			},
			want:    createDummyPolicy(e),
			wantErr: false,
		},

		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UIDMetadataExtractor(tt.args.event)
			if (err != nil) != tt.wantErr {
				t.Errorf("UIDMetadataExtractor() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != nil && tt.want != nil {
				marshaledgot, _ = got.MarshalJSON()
				marshalledwant, _ = tt.want.MarshalJSON()
			}
			if !reflect.DeepEqual(marshaledgot, marshalledwant) {
				t.Errorf("\nUIDMetadataExtractor()\ngot  = %s\n, want %s\n", string(marshaledgot), string(marshalledwant))
			}
		})
	}
}
