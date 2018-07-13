package extractors

import (
	"reflect"
	"testing"

	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/policy"
)

func TestUIDMetadataExtractor(t *testing.T) {
	type args struct {
		event *common.EventInfo
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UIDMetadataExtractor(tt.args.event)
			if (err != nil) != tt.wantErr {
				t.Errorf("UIDMetadataExtractor() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UIDMetadataExtractor() = %v, want %v", got, tt.want)
			}
		})
	}
}
