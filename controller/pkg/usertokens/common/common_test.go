package common

import (
	"testing"

	. "github.com/smartystreets/assertions"
)

func TestFlattenClaim(t *testing.T) {
	type args struct {
		key   string
		claim interface{}
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		notwant []string
	}{
		{
			name: "test-string",
			args: args{key: "testkey1", claim: "testclaim1"},
			want: []string{"testkey1=testclaim1"},
		},
		{
			name: "test-empty-string",
			args: args{key: "testkey1", claim: ""},
			want: []string{"testkey1="},
		},
		{
			name: "test-bool-true",
			args: args{key: "key", claim: true},
			want: []string{"key=true"},
		},
		{
			name: "test-bool-false",
			args: args{key: "key", claim: false},
			want: []string{"key=false"},
		},
		{
			name:    "test-bool-not-true",
			args:    args{key: "key", claim: true},
			notwant: []string{"key=false"},
		},
		{
			name:    "test-bool-not-false",
			args:    args{key: "key", claim: false},
			notwant: []string{"key=true"},
		},
		{
			name: "test-string-slice-succeed",
			args: args{key: "key", claim: []string{"testclaim1", "testclaim2"}},
			want: []string{"key=testclaim1", "key=testclaim2"},
		},
		{
			name:    "test-string-slice-fail",
			args:    args{key: "key", claim: []string{"testclaim1", "testclaim2"}},
			notwant: []string{"key=testclaim3", "key=testclaim4"},
		},
		{
			name: "test-map-succeed",
			args: args{key: "testkey", claim: map[string]interface{}{"key1": "value1", "key2": "value2"}},
			want: []string{"testkey:key1=value1", "testkey:key2=value2"},
		},
		{
			name:    "test-map-fail",
			args:    args{key: "testkey", claim: map[string]interface{}{"key1": "value1", "key2": "value2"}},
			notwant: []string{"testkey:key1=value3", "testkey:key2=value4"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FlattenClaim(tt.args.key, tt.args.claim)
			for _, want := range tt.want {
				if ok, errStr := So(got, ShouldContain, want); !ok {
					t.Errorf("%s", errStr)
				}
			}
			for _, notwant := range tt.notwant {
				if ok, errStr := So(got, ShouldNotContain, notwant); !ok {
					t.Errorf("%s", errStr)
				}
			}
		})
	}
}
