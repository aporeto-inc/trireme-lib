package common

import (
	"fmt"
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
			args: args{key: "key", claim: []string{"claim1", "claim2"}},
			want: []string{"key=claim1", "key=claim2"},
		},
		{
			name:    "test-string-slice-fail",
			args:    args{key: "key", claim: []string{"claim1", "claim2"}},
			notwant: []string{"key=claim3", "key=claim4"},
		},
		{
			name: "test-map-string-string",
			args: args{key: "testkey", claim: map[string]interface{}{"key1": "value1", "key2": "value2"}},
			want: []string{"testkey:key1=value1", "testkey:key2=value2"},
		},
		{
			name: "test-map-string-int",
			args: args{key: "testkey", claim: map[string]interface{}{"key1": 1, "key2": 2}},
			want: []string{"testkey:key1=1", "testkey:key2=2"},
		},
		{
			name: "test-map-string-bool",
			args: args{key: "testkey", claim: map[string]interface{}{"key1": true, "key2": false}},
			want: []string{"testkey:key1=true", "testkey:key2=false"},
		},
		{
			name: "test-map-string-slice",
			args: args{key: "rootkey", claim: map[string]interface{}{"key1": []string{"val1", "val2"}}},
			want: []string{"rootkey:key1=val1", "rootkey:key1=val2"},
		},
		{
			name: "test-map-string-map",
			args: args{
				key: "rootkey",
				claim: map[string]interface{}{
					"level1": map[string]interface{}{
						"key1": "val1",
					},
					"level2": map[string]interface{}{
						"key2": "val2",
					},
				},
			},
			want: []string{"rootkey:level1:key1=val1", "rootkey:level2:key2=val2"},
		},
		{
			name: "test-positive-int",
			args: args{key: "key", claim: int(1)},
			want: []string{"key=1"},
		},
		{
			name: "test-positive-int8",
			args: args{key: "key", claim: int8(1)},
			want: []string{"key=1"},
		},
		{
			name: "test-positive-int16",
			args: args{key: "key", claim: int16(1)},
			want: []string{"key=1"},
		},
		{
			name: "test-positive-int32",
			args: args{key: "key", claim: int32(1)},
			want: []string{"key=1"},
		},
		{
			name: "test-positive-int64",
			args: args{key: "key", claim: int64(1)},
			want: []string{"key=1"},
		},
		{
			name: "test-negative-int",
			args: args{key: "key", claim: int(-1)},
			want: []string{"key=-1"},
		},
		{
			name: "test-uint",
			args: args{key: "key", claim: uint(1)},
			want: []string{"key=1"},
		},
		{
			name: "test-uint8",
			args: args{key: "key", claim: uint8(1)},
			want: []string{"key=1"},
		},
		{
			name: "test-uint16",
			args: args{key: "key", claim: uint16(1)},
			want: []string{"key=1"},
		},
		{
			name: "test-uint32",
			args: args{key: "key", claim: uint32(1)},
			want: []string{"key=1"},
		},
		{
			name: "test-uint64",
			args: args{key: "key", claim: uint64(1)},
			want: []string{"key=1"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FlattenClaim(tt.args.key, tt.args.claim)
			fmt.Printf("test: %s, got: %v\n", tt.name, got)
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
