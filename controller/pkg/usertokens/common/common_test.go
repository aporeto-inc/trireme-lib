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
			name: "test-slice",
			args: args{
				key:   "slicekey",
				claim: []interface{}{"claim1", "claim2"},
			},
			want: []string{"slicekey=claim1", "slicekey=claim2"},
		},
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
		{
			name: "test-float32-small",
			args: args{key: "key", claim: float32(3.14)},
			want: []string{"key=3.14"},
		},
		{
			name: "test-negative-float32-small",
			args: args{key: "key", claim: float32(-3.14)},
			want: []string{"key=-3.14"},
		},
		{
			name: "test-float32-rounding",
			args: args{key: "key", claim: float32(3.141592654)},
			want: []string{"key=3.1415927"},
		},
		{
			name: "test-negative-float32-rounding",
			args: args{key: "key", claim: float32(-3.141592654)},
			want: []string{"key=-3.1415927"},
		},
		{
			name: "test-float32-exponent",
			args: args{key: "key", claim: float32(3.141592654e22)},
			want: []string{"key=3.1415927E+22"},
		},
		{
			name: "test-float32-negative-exponent",
			args: args{key: "key", claim: float32(3.141592654e-22)},
			want: []string{"key=3.1415927E-22"},
		},
		{
			name: "test-negative-float32-exponent",
			args: args{key: "key", claim: float32(-3.141592654e22)},
			want: []string{"key=-3.1415927E+22"},
		},
		{
			name: "test-negative-float32-negative-exponent",
			args: args{key: "key", claim: float32(-3.141592654e-22)},
			want: []string{"key=-3.1415927E-22"},
		},
		{
			name: "test-float64-small",
			args: args{key: "key", claim: float64(3.14)},
			want: []string{"key=3.14"},
		},
		{
			name: "test-negative-float64-small",
			args: args{key: "key", claim: float64(-3.14)},
			want: []string{"key=-3.14"},
		},
		{
			name: "test-float64-rounding",
			args: args{key: "key", claim: float64(1.412135623730950488)},
			want: []string{"key=1.4121356237309506"},
		},
		{
			name: "test-negative-float64-rounding",
			args: args{key: "key", claim: float64(-1.412135623730950488)},
			want: []string{"key=-1.4121356237309506"},
		},
		{
			name: "test-float64-exponent",
			args: args{key: "key", claim: float64(1.41213562373095e22)},
			want: []string{"key=1.41213562373095E+22"},
		},
		{
			name: "test-float64-negative-exponent",
			args: args{key: "key", claim: float64(1.41213562373095e-22)},
			want: []string{"key=1.41213562373095E-22"},
		},
		{
			name: "test-negative-float64-exponent",
			args: args{key: "key", claim: float64(-1.41213562373095e22)},
			want: []string{"key=-1.41213562373095E+22"},
		},
		{
			name: "test-negative-float64-negative-exponent",
			args: args{key: "key", claim: float64(-1.41213562373095e-22)},
			want: []string{"key=-1.41213562373095E-22"},
		},
		{
			name: "test-map-string-float",
			args: args{key: "test", claim: map[string]interface{}{"key1": 3.1415, "key2": -1.21e+33}},
			want: []string{"test:key1=3.1415", "test:key2=-1.21E+33"},
		},
		{
			name: "test-map-string-mixed",
			args: args{key: "test", claim: map[string]interface{}{"key1": true, "key2": -1.21e+33, "key3": "val3"}},
			want: []string{"test:key1=true", "test:key2=-1.21E+33", "test:key3=val3"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FlattenClaim(tt.args.key, tt.args.claim)
			t.Logf("test: %s, got: %v\n", tt.name, got)
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

func Test_toInt64(t *testing.T) {
	type args struct {
		i interface{}
	}
	tests := []struct {
		name      string
		args      args
		want      int64
		wantPanic bool
	}{
		{
			name: "test-toInt64-int",
			args: args{i: int(1)},
			want: int64(1),
		},
		{
			name: "test-toInt64-int8",
			args: args{i: int8(1)},
			want: int64(1),
		},
		{
			name: "test-toInt64-int16",
			args: args{i: int16(1)},
			want: int64(1),
		},
		{
			name: "test-toInt64-int32",
			args: args{i: int32(1)},
			want: int64(1),
		},
		{
			name: "test-toInt64-int64",
			args: args{i: int64(1)},
			want: int64(1),
		},
		{
			name:      "test-toInt64-string",
			args:      args{i: "a string"},
			want:      int64(1),
			wantPanic: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				r := recover()
				if (r != nil) != tt.wantPanic {
					t.Errorf("toInt64() recover = %v, wantPanic = %v", r, tt.wantPanic)
				}
			}()
			if got := toInt64(tt.args.i); got != tt.want {
				t.Errorf("toInt64() = %v, want %v", got, tt.want)
			} else {
				t.Logf("toInt64(): test: %s PASS, want %v, got: %v\n", tt.name, tt.want, got)
			}
		})
	}
}

func Test_toUint64(t *testing.T) {
	type args struct {
		i interface{}
	}
	tests := []struct {
		name      string
		args      args
		want      uint64
		wantPanic bool
	}{
		{
			name: "test-toUint64-int",
			args: args{i: uint(1)},
			want: uint64(1),
		},
		{
			name: "test-toUint64-int8",
			args: args{i: uint8(1)},
			want: uint64(1),
		},
		{
			name: "test-toUint64-int16",
			args: args{i: uint16(1)},
			want: uint64(1),
		},
		{
			name: "test-toUint64-int32",
			args: args{i: uint32(1)},
			want: uint64(1),
		},
		{
			name: "test-toUint64-int64",
			args: args{i: uint64(1)},
			want: uint64(1),
		},
		{
			name:      "test-toUint64-string",
			args:      args{i: "a string"},
			want:      uint64(1),
			wantPanic: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				r := recover()
				if (r != nil) != tt.wantPanic {
					t.Errorf("toUint64() recover = %v, wantPanic = %v", r, tt.wantPanic)
				}
			}()
			if got := toUint64(tt.args.i); got != tt.want {
				t.Errorf("toUint64() = %v, want %v", got, tt.want)
			} else {
				t.Logf("toUint64(): test: %s PASS, want %v, got: %v\n", tt.name, tt.want, got)
			}
		})
	}
}
