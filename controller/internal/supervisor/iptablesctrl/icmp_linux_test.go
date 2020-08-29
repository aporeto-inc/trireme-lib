// +build !windows

package iptablesctrl

import "testing"

func Test_getICMPv6(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"icmpv6DefaultAllow", "(icmp6[0] == 133 and icmp6[1] == 0) or (icmp6[0] == 134 and icmp6[1] == 0) or (icmp6[0] == 135 and icmp6[1] == 0) or (icmp6[0] == 136 and icmp6[1] == 0) or (icmp6[0] == 141 and icmp6[1] == 0) or (icmp6[0] == 142 and icmp6[1] == 0)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getICMPv6(); got != tt.want {
				t.Errorf("getICMPv6() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_generateExpr(t *testing.T) {
	type args struct {
		icmpTypeCode      string
		policyRestriction []string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"1", args{"icmp", []string{}}, "((icmp))"},
		{"2", args{"icmp6", []string{}}, "((icmp6))"},
		{"3", args{"icmp/1", []string{}}, "(((icmp) and (icmp[0] == 1)))"},
		{"4", args{"icmp6/1", []string{}}, "(((icmp6) and (icmp6[0] == 1)))"},
		{"5", args{"icmp/255", []string{}}, "(((icmp) and (icmp[0] == 255)))"},
		{"6", args{"icmp/1/2", []string{}}, "((((icmp) and (icmp[0] == 1)) and ((icmp[1] == 2))))"},
		{"7", args{"icmp/1/2,3,4", []string{}}, "((((icmp) and (icmp[0] == 1)) and ((icmp[1] == 2)or(icmp[1] == 3)or(icmp[1] == 4))))"},
		{"8", args{"icmp/1/0:255", []string{}}, "((((icmp) and (icmp[0] == 1)) and (((icmp[1] >= 0) and (icmp[1] <= 255)))))"},
		{"9", args{"icmp/1/1,2,3:255", []string{}}, "((((icmp) and (icmp[0] == 1)) and ((icmp[1] == 1)or(icmp[1] == 2)or((icmp[1] >= 3) and (icmp[1] <= 255)))))"},
		{"10", args{"icmp6/255", []string{}}, "(((icmp6) and (icmp6[0] == 255)))"},
		{"11", args{"icmp6/1/2", []string{}}, "((((icmp6) and (icmp6[0] == 1)) and ((icmp6[1] == 2))))"},
		{"12", args{"icmp6/1/2,3,4", []string{}}, "((((icmp6) and (icmp6[0] == 1)) and ((icmp6[1] == 2)or(icmp6[1] == 3)or(icmp6[1] == 4))))"},
		{"13", args{"icmp6/1/0:255", []string{}}, "((((icmp6) and (icmp6[0] == 1)) and (((icmp6[1] >= 0) and (icmp6[1] <= 255)))))"},
		{"14", args{"icmp6/1/1,2,3:255", []string{}}, "((((icmp6) and (icmp6[0] == 1)) and ((icmp6[1] == 1)or(icmp6[1] == 2)or((icmp6[1] >= 3) and (icmp6[1] <= 255)))))"},
		{"15", args{"icmp", []string{"icmp/1/1"}}, "(((((icmp) and (icmp[0] == 1)) and ((icmp[1] == 1)))) and (icmp))"},
		{"16", args{"icmp6", []string{"icmp6/1/0:255"}}, "(((((icmp6) and (icmp6[0] == 1)) and (((icmp6[1] >= 0) and (icmp6[1] <= 255))))) and (icmp6))"},
		{"17", args{"icmp/1", []string{"icmp", "icmp6"}}, "(((icmp) or (icmp6)) and ((icmp) and (icmp[0] == 1)))"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := generateExpr(tt.args.icmpTypeCode, tt.args.policyRestriction); got != tt.want {
				t.Errorf("generateExpr() = %v, want %v", got, tt.want)
			}
		})
	}
}
