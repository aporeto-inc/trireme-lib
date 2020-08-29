// +build windows

package iptablesctrl

import (
	"strings"
	"testing"

	"go.aporeto.io/trireme-lib/controller/internal/windows"
	"go.aporeto.io/trireme-lib/controller/internal/windows/frontman"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/common"
)

func TestTransformACLRuleHost(t *testing.T) {

	Convey("When I parse some acl rules", t, func() {

		var aclRules [][]string
		aclRules = append(aclRules, strings.Split("OUTPUT TRI-App-hostZ7PbqL-0 -p 6 -m set --match-set TRI-v4-ext-cUDEx1114Z2xd dst -m state --state NEW -m set ! --match-set TRI-v4-TargetTCP dst --match multiport --dports 1:65535 -m state --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 531138568:5d6044b9e99572000149d650:5d60448a884e46000145cf67:6", " "))
		aclRules = append(aclRules, strings.Split("OUTPUT TRI-App-hostZ7PbqL-0 -p 6 -m set --match-set TRI-v4-ext-cUDEx1114Z2xd dst -m state --state NEW -m set ! --match-set TRI-v4-TargetTCP dst --match multiport --dports 1:65535 -j DROP", " "))
		aclRules = append(aclRules, strings.Split("OUTPUT TRI-App-hostZ7PbqL-0 -p 17 -m set --match-set TRI-v4-TargetUDP src --match multiport --dports 80,443,8080:8443 -j ACCEPT", " "))
		aclRules = append(aclRules, strings.Split("OUTPUT TRI-App-hostZ7PbqL-0 -p 6 -m set --match-set TRI-v4-ext-z4QRD1114Z2xd dst -m state --state NEW -m set ! --match-set TRI-v4-TargetTCP dst --match multiport --dports 2323 -m state --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 531138568:5d9e2e2d8431510001bcc931:5d61b8f4884e46000146bcd9:3", " "))
		aclRules = append(aclRules, strings.Split("OUTPUT TRI-App-hostZ7PbqL-0 -p 6 -m set --match-set TRI-v4-ext-z4QRD1114Z2xd dst -m state --state NEW -m set ! --match-set TRI-v4-TargetTCP dst --match multiport --dports 2323 -j ACCEPT", " "))
		aclRules = append(aclRules, strings.Split("OUTPUT TRI-App-hostZ7PbqL-0 -p 6 -m state --state NEW -m set --match-set TRI-v4-TargetTCP dst --match multiport --dports 2323 -j ACCEPT", " "))

		aclInfo := &ACLInfo{}
		aclInfo.TCPPorts = "80,443"
		aclInfo.UDPPorts = ""
		aclInfo.PUType = common.HostPU

		xformedRules := transformACLRules(aclRules, aclInfo, nil, true)

		Convey("Adjacent like ones should be merged", func() {

			So(xformedRules, ShouldHaveLength, 4)
			So(xformedRules[0][1], ShouldEqual, "HostPU-OUTPUT")
			So(xformedRules[1][1], ShouldEqual, "HostPU-OUTPUT")
			So(xformedRules[2][1], ShouldEqual, "HostPU-OUTPUT")
			So(xformedRules[3][1], ShouldEqual, "HostPU-OUTPUT")

			// check combined rule 1 and 2
			// OUTPUT HostSvcRules-OUTPUT -p 6 --dports 1:65535 -m set --match-set TRI-v4-ext-cUDEx1114Z2xd dstIP,dstPort -m set ! --match-set TRI-v4-TargetTCP dstIP,dstPort -j DROP -j NFLOG --nflog-group 0 --nflog-prefix 531138568:5d6044b9e99572000149d650:5d60448a884e46000145cf67:6
			rs, err := windows.ParseRuleSpec(xformedRules[0][2:]...)

			So(err, ShouldBeNil)
			So(rs.Protocol, ShouldEqual, 6)
			So(rs.Action, ShouldEqual, frontman.FilterActionBlock)
			So(rs.Log, ShouldBeTrue)
			So(rs.LogPrefix, ShouldEqual, "531138568:5d6044b9e99572000149d650:5d60448a884e46000145cf67:6")
			So(rs.MatchDstPort, ShouldHaveLength, 1)
			So(rs.MatchDstPort[0].Start, ShouldEqual, 1)
			So(rs.MatchDstPort[0].End, ShouldEqual, 65535)
			So(rs.MatchSet, ShouldHaveLength, 2)
			So(rs.MatchSet[0].MatchSetName, ShouldEqual, "TRI-v4-ext-cUDEx1114Z2xd")
			So(rs.MatchSet[0].MatchSetNegate, ShouldBeFalse)
			So(rs.MatchSet[0].MatchSetSrcIp, ShouldBeFalse)
			So(rs.MatchSet[0].MatchSetSrcPort, ShouldBeFalse)
			So(rs.MatchSet[0].MatchSetDstIp, ShouldBeTrue)
			So(rs.MatchSet[0].MatchSetDstPort, ShouldBeTrue)
			So(rs.MatchSet[1].MatchSetName, ShouldEqual, "TRI-v4-TargetTCP")
			So(rs.MatchSet[1].MatchSetNegate, ShouldBeTrue)
			So(rs.MatchSet[1].MatchSetSrcIp, ShouldBeFalse)
			So(rs.MatchSet[1].MatchSetSrcPort, ShouldBeFalse)
			So(rs.MatchSet[1].MatchSetDstIp, ShouldBeTrue)
			So(rs.MatchSet[1].MatchSetDstPort, ShouldBeTrue)

			// check singular rule 3
			// OUTPUT TRI-App-hostZ7PbqL-0 -p 17 -m set --match-set TRI-v4-TargetUDP src --match multiport --dports 80,443,8080:8443 -j ACCEPT
			rs, err = windows.ParseRuleSpec(xformedRules[1][2:]...)

			So(err, ShouldBeNil)
			So(rs.Protocol, ShouldEqual, 17)
			So(rs.Action, ShouldEqual, frontman.FilterActionAllow)
			So(rs.Log, ShouldBeFalse)
			So(rs.MatchDstPort, ShouldHaveLength, 3)
			So(rs.MatchDstPort[0].Start, ShouldEqual, 80)
			So(rs.MatchDstPort[0].End, ShouldEqual, 80)
			So(rs.MatchDstPort[1].Start, ShouldEqual, 443)
			So(rs.MatchDstPort[1].End, ShouldEqual, 443)
			So(rs.MatchDstPort[2].Start, ShouldEqual, 8080)
			So(rs.MatchDstPort[2].End, ShouldEqual, 8443)
			So(rs.MatchSet, ShouldHaveLength, 1)

			// check combined rule 4 and 5
			// OUTPUT HostSvcRules-OUTPUT -p 6 --dports 2323 -m set --match-set TRI-v4-ext-z4QRD1114Z2xd dstIP,dstPort -m set ! --match-set TRI-v4-TargetTCP dstIP,dstPort -j ACCEPT -j NFLOG --nflog-group 0 --nflog-prefix 531138568:5d9e2e2d8431510001bcc931:5d61b8f4884e46000146bcd9:3
			rs, err = windows.ParseRuleSpec(xformedRules[2][2:]...)

			So(err, ShouldBeNil)
			So(rs.Protocol, ShouldEqual, 6)
			So(rs.Action, ShouldEqual, frontman.FilterActionAllow)
			So(rs.Log, ShouldBeTrue)
			So(rs.LogPrefix, ShouldEqual, "531138568:5d9e2e2d8431510001bcc931:5d61b8f4884e46000146bcd9:3")
			So(rs.MatchDstPort, ShouldHaveLength, 1)
			So(rs.MatchDstPort[0].Start, ShouldEqual, 2323)
			So(rs.MatchDstPort[0].End, ShouldEqual, 2323)
			So(rs.MatchSet, ShouldHaveLength, 2)
			So(rs.MatchSet[0].MatchSetName, ShouldEqual, "TRI-v4-ext-z4QRD1114Z2xd")
			So(rs.MatchSet[0].MatchSetNegate, ShouldBeFalse)
			So(rs.MatchSet[0].MatchSetSrcIp, ShouldBeFalse)
			So(rs.MatchSet[0].MatchSetSrcPort, ShouldBeFalse)
			So(rs.MatchSet[0].MatchSetDstIp, ShouldBeTrue)
			So(rs.MatchSet[0].MatchSetDstPort, ShouldBeTrue)
			So(rs.MatchSet[1].MatchSetName, ShouldEqual, "TRI-v4-TargetTCP")
			So(rs.MatchSet[1].MatchSetNegate, ShouldBeTrue)
			So(rs.MatchSet[1].MatchSetSrcIp, ShouldBeFalse)
			So(rs.MatchSet[1].MatchSetSrcPort, ShouldBeFalse)
			So(rs.MatchSet[1].MatchSetDstIp, ShouldBeTrue)
			So(rs.MatchSet[1].MatchSetDstPort, ShouldBeTrue)

			// check last rule 6
			// OUTPUT TRI-App-hostZ7PbqL-0 -p 6 -m state --state NEW -m set --match-set TRI-v4-TargetTCP dst --match multiport --dports 2323 -j ACCEPT
			rs, err = windows.ParseRuleSpec(xformedRules[3][2:]...)

			So(err, ShouldBeNil)
			So(rs.Protocol, ShouldEqual, 6)
			So(rs.Action, ShouldEqual, frontman.FilterActionAllow)
			So(rs.Log, ShouldBeFalse)
			So(rs.MatchDstPort, ShouldHaveLength, 1)
			So(rs.MatchDstPort[0].Start, ShouldEqual, 2323)
			So(rs.MatchDstPort[0].End, ShouldEqual, 2323)
			So(rs.MatchSet, ShouldHaveLength, 1)

		})

	})

}

func TestTransformACLRuleHostNet(t *testing.T) {

	Convey("When I parse a set of net acl rules for host pu", t, func() {

		var aclRules [][]string
		aclRules = append(aclRules, strings.Split("OUTPUT TRI-Net-hostZ7PbqL-0 -p 6 -m set --match-set TRI-v6-ext-cUDEx1114Z2xd src -m state --state NEW -m set ! --match-set TRI-v6-TargetTCP src --match multiport --dports 1:65535 -m state --state NEW -j NFLOG --nflog-group 11 --nflog-prefix 3617624947:5d6967333561e000018a3a65:5d60448a884e46000145cf67:3", " "))
		aclRules = append(aclRules, strings.Split("OUTPUT TRI-Net-hostZ7PbqL-0 -p 6 -m set --match-set TRI-v6-ext-cUDEx1114Z2xd src -m state --state NEW -m set ! --match-set TRI-v6-TargetTCP src --match multiport --dports 1:65535 -j ACCEPT", " "))

		aclInfo := &ACLInfo{}
		aclInfo.TCPPorts = "80,443"
		aclInfo.UDPPorts = ""
		aclInfo.PUType = common.HostPU

		xformedRules := transformACLRules(aclRules, aclInfo, nil, false)

		Convey("They should be merged to one rule for the HostPU-INPUT chain", func() {

			So(xformedRules, ShouldHaveLength, 1)
			So(xformedRules[0][1], ShouldEqual, "HostPU-INPUT")

			// check combined rule 1 and 2
			// OUTPUT HostPU-INPUT -p 6 --dports 1:65535 -m set --match-set TRI-v6-ext-cUDEx1114Z2xd srcIP,srcPort -m set ! --match-set TRI-v6-TargetTCP srcIP,srcPort -j ACCEPT -j NFLOG --nflog-group 0 --nflog-prefix 3617624947:5d6967333561e000018a3a65:5d60448a884e46000145cf67:3
			rs, err := windows.ParseRuleSpec(xformedRules[0][2:]...)

			So(err, ShouldBeNil)
			So(rs.Protocol, ShouldEqual, 6)
			So(rs.Action, ShouldEqual, frontman.FilterActionAllow)
			So(rs.Log, ShouldBeTrue)
			So(rs.LogPrefix, ShouldEqual, "3617624947:5d6967333561e000018a3a65:5d60448a884e46000145cf67:3")
			So(rs.MatchDstPort, ShouldHaveLength, 1)
			So(rs.MatchDstPort[0].Start, ShouldEqual, 1)
			So(rs.MatchDstPort[0].End, ShouldEqual, 65535)
			So(rs.MatchSet, ShouldHaveLength, 2)
			So(rs.MatchSet[0].MatchSetName, ShouldEqual, "TRI-v6-ext-cUDEx1114Z2xd")
			So(rs.MatchSet[0].MatchSetNegate, ShouldBeFalse)
			So(rs.MatchSet[0].MatchSetSrcIp, ShouldBeTrue)
			So(rs.MatchSet[0].MatchSetSrcPort, ShouldBeTrue)
			So(rs.MatchSet[0].MatchSetDstIp, ShouldBeFalse)
			So(rs.MatchSet[0].MatchSetDstPort, ShouldBeFalse)
			So(rs.MatchSet[1].MatchSetName, ShouldEqual, "TRI-v6-TargetTCP")
			So(rs.MatchSet[1].MatchSetNegate, ShouldBeTrue)
			So(rs.MatchSet[1].MatchSetSrcIp, ShouldBeTrue)
			So(rs.MatchSet[1].MatchSetSrcPort, ShouldBeTrue)
			So(rs.MatchSet[1].MatchSetDstIp, ShouldBeFalse)
			So(rs.MatchSet[1].MatchSetDstPort, ShouldBeFalse)

		})
	})

}

func TestTransformACLRuleHostSvc(t *testing.T) {

	Convey("When I parse some acl rules for a host service", t, func() {

		var aclRules [][]string
		aclRules = append(aclRules, strings.Split("OUTPUT TRI-App-1114oqLQAD-0 -p 6 -m set --match-set TRI-v4-ext-cUDEx1114Z2xd dst -m state --state NEW -m set ! --match-set TRI-v4-TargetTCP dst --match multiport --dports 1:65535 -m state --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 531138568:5d6044b9e99572000149d650:5d60448a884e46000145cf67:6", " "))
		aclRules = append(aclRules, strings.Split("OUTPUT TRI-App-1114oqLQAD-0 -p 6 -m set --match-set TRI-v4-ext-cUDEx1114Z2xd dst -m state --state NEW -m set ! --match-set TRI-v4-TargetTCP dst --match multiport --dports 1:65535 -j DROP", " "))
		aclRules = append(aclRules, strings.Split("OUTPUT TRI-App-1114oqLQAD-0 -p 17 -m set --match-set TRI-v4-TargetUDP src --match multiport --dports 80,443,8080:8443 -j ACCEPT", " "))
		aclRules = append(aclRules, strings.Split("OUTPUT TRI-App-1114oqLQAD-0 -m set --match-set TRI-v4-ext-z4QRD1114Z2xd dst -m state --state NEW -m set ! --match-set TRI-v4-TargetTCP dst --match multiport --dports 2323 -m state --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 531138568:5d9e2e2d8431510001bcc931:5d61b8f4884e46000146bcd9:3", " "))
		aclRules = append(aclRules, strings.Split("OUTPUT TRI-App-1114oqLQAD-0 -m set --match-set TRI-v4-ext-z4QRD1114Z2xd dst -m state --state NEW -m set ! --match-set TRI-v4-TargetTCP dst --match multiport --dports 2323 -j ACCEPT", " "))

		aclInfo := &ACLInfo{}
		aclInfo.TCPPorts = "80,443"
		aclInfo.UDPPorts = ""
		aclInfo.PUType = common.HostNetworkPU

		xformedRules := transformACLRules(aclRules, aclInfo, nil, true)

		Convey("No outgoing rules are kept for host-service PU", func() {

			So(xformedRules, ShouldHaveLength, 0)

		})

	})

}

func TestTransformACLRuleHostSvcNet(t *testing.T) {

	Convey("When I parse a set of net acl rules for a host svc pu", t, func() {

		var aclRules [][]string
		aclRules = append(aclRules, strings.Split("OUTPUT TRI-Net-1114oqLQAD-0 -p 6 -m set --match-set TRI-v4-ext-cUDEx1114Z2xd src -m state --state NEW -m set ! --match-set TRI-v4-TargetTCP src --match multiport --dports 1:65535 -m state --state NEW -j NFLOG --nflog-group 11 --nflog-prefix 531138568:5d6967333561e000018a3a65:5d60448a884e46000145cf67:3", " "))
		aclRules = append(aclRules, strings.Split("OUTPUT TRI-Net-1114oqLQAD-0 -p 6 -m set --match-set TRI-v4-ext-cUDEx1114Z2xd src -m state --state NEW -m set ! --match-set TRI-v4-TargetTCP src --match multiport --dports 1:65535 -j ACCEPT", " "))
		// protocol any rules for input on host-svc should be dropped
		aclRules = append(aclRules, strings.Split("OUTPUT TRI-Net-1114oqLQAD-0 -m set --match-set TRI-v4-ext-dxxgXBWCQy0= src -m state --state NEW -m set ! --match-set TRI-v4-TargetTCP src --match multiport --dports 1:65535 -m state --state NEW -j NFLOG --nflog-group 11 --nflog-prefix 187906336:5e2b46b82e67d60001766eda:5dfd1e479facec0001e5936b:3", " "))
		aclRules = append(aclRules, strings.Split("OUTPUT TRI-Net-1114oqLQAD-0 -m set --match-set TRI-v4-ext-dxxgXBWCQy0= src -m state --state NEW -m set ! --match-set TRI-v4-TargetTCP src --match multiport --dports 1:65535 -j ACCEPT", " "))

		aclInfo := &ACLInfo{}
		aclInfo.TCPPorts = "80,443"
		aclInfo.UDPPorts = ""
		aclInfo.PUType = common.HostNetworkPU

		xformedRules := transformACLRules(aclRules, aclInfo, nil, false)

		Convey("They should be merged to one rule for the HostSvcRules-INPUT chain and should have the PU's ports", func() {

			So(xformedRules, ShouldHaveLength, 1)
			So(xformedRules[0][1], ShouldEqual, "HostSvcRules-INPUT")

			// check combined rule 1 and 2
			// dports should be replaced with PU's ports
			// OUTPUT HostSvcRules-INPUT -p 6 --dports 80,443 -m set --match-set TRI-v4-ext-cUDEx1114Z2xd srcIP,srcPort -m set ! --match-set TRI-v4-TargetTCP srcIP,srcPort -j ACCEPT -j NFLOG --nflog-group 0 --nflog-prefix 531138568:5d6967333561e000018a3a65:5d60448a884e46000145cf67:3
			rs, err := windows.ParseRuleSpec(xformedRules[0][2:]...)

			So(err, ShouldBeNil)
			So(rs.Protocol, ShouldEqual, 6)
			So(rs.Action, ShouldEqual, frontman.FilterActionAllow)
			So(rs.Log, ShouldBeTrue)
			So(rs.LogPrefix, ShouldEqual, "531138568:5d6967333561e000018a3a65:5d60448a884e46000145cf67:3")
			So(rs.MatchDstPort, ShouldHaveLength, 2)
			So(rs.MatchDstPort[0].Start, ShouldEqual, 80)
			So(rs.MatchDstPort[0].End, ShouldEqual, 80)
			So(rs.MatchDstPort[1].Start, ShouldEqual, 443)
			So(rs.MatchDstPort[1].End, ShouldEqual, 443)
			So(rs.MatchSet, ShouldHaveLength, 2)
			So(rs.MatchSet[0].MatchSetName, ShouldEqual, "TRI-v4-ext-cUDEx1114Z2xd")
			So(rs.MatchSet[0].MatchSetNegate, ShouldBeFalse)
			So(rs.MatchSet[0].MatchSetSrcIp, ShouldBeTrue)
			So(rs.MatchSet[0].MatchSetSrcPort, ShouldBeTrue)
			So(rs.MatchSet[0].MatchSetDstIp, ShouldBeFalse)
			So(rs.MatchSet[0].MatchSetDstPort, ShouldBeFalse)
			So(rs.MatchSet[1].MatchSetName, ShouldEqual, "TRI-v4-TargetTCP")
			So(rs.MatchSet[1].MatchSetNegate, ShouldBeTrue)
			So(rs.MatchSet[1].MatchSetSrcIp, ShouldBeTrue)
			So(rs.MatchSet[1].MatchSetSrcPort, ShouldBeTrue)
			So(rs.MatchSet[1].MatchSetDstIp, ShouldBeFalse)
			So(rs.MatchSet[1].MatchSetDstPort, ShouldBeFalse)

		})

	})

}

func TestTransformACLRuleIcmp(t *testing.T) {

	Convey("When I parse a set of net acl rules with an icmp rule", t, func() {

		var aclRules [][]string
		aclRules = append(aclRules, strings.Split("OUTPUT TRI-Net-hostZ7PbqL-0 -p 1 --icmp-type 3/0:2,6 -j NFLOG --nflog-group 11 --nflog-prefix 3617624947:5d6967333561e000018a3a65:5d60448a884e46000145cf67:3", " "))
		aclRules = append(aclRules, strings.Split("OUTPUT TRI-Net-hostZ7PbqL-0 -p 1 --icmp-type 3/0:2,6 -j ACCEPT", " "))
		aclRules = append(aclRules, strings.Split("OUTPUT TRI-Net-hostZ7PbqL-0 -p 1 --icmp-type 8/0:3,5 -j NFLOG --nflog-group 11 --nflog-prefix 3617624947:5d6967333561e000018a3a65:5d60448a884e46000145cf67:3", " "))
		aclRules = append(aclRules, strings.Split("OUTPUT TRI-Net-hostZ7PbqL-0 -p 1 --icmp-type 8/0:3 -j ACCEPT", " "))

		aclInfo := &ACLInfo{}
		aclInfo.TCPPorts = "80,443"
		aclInfo.UDPPorts = ""
		aclInfo.PUType = common.HostPU

		xformedRules := transformACLRules(aclRules, aclInfo, nil, false)

		Convey("They should be merged to one rule for the HostPU-INPUT chain", func() {

			So(xformedRules, ShouldHaveLength, 3)
			So(xformedRules[0][1], ShouldEqual, "HostPU-INPUT")
			So(xformedRules[1][1], ShouldEqual, "HostPU-INPUT")
			So(xformedRules[2][1], ShouldEqual, "HostPU-INPUT")

			// check combined rule 1 and 2
			// OUTPUT HostPU-INPUT -p 1 --icmp-type 3/0:2,6 -j ACCEPT -j NFLOG --nflog-group 11 --nflog-prefix 3617624947:5d6967333561e000018a3a65:5d60448a884e46000145cf67:3
			rs, err := windows.ParseRuleSpec(xformedRules[0][2:]...)

			So(err, ShouldBeNil)
			So(rs.Protocol, ShouldEqual, 1)
			So(rs.Action, ShouldEqual, frontman.FilterActionAllow)
			So(rs.IcmpMatch, ShouldHaveLength, 2)
			So(rs.IcmpMatch[0].IcmpType, ShouldEqual, 3)
			So(rs.IcmpMatch[0].IcmpCodeRange.Start, ShouldEqual, 0)
			So(rs.IcmpMatch[0].IcmpCodeRange.End, ShouldEqual, 2)
			So(rs.IcmpMatch[1].IcmpType, ShouldEqual, 3)
			So(rs.IcmpMatch[1].IcmpCodeRange.Start, ShouldEqual, 6)
			So(rs.IcmpMatch[1].IcmpCodeRange.End, ShouldEqual, 6)
			So(rs.Log, ShouldBeTrue)
			So(rs.LogPrefix, ShouldEqual, "3617624947:5d6967333561e000018a3a65:5d60448a884e46000145cf67:3")

			// rules 3 and 4 should not be combined (they differ by icmp code)
			rs, err = windows.ParseRuleSpec(xformedRules[1][2:]...)
			So(err, ShouldBeNil)
			So(rs.Protocol, ShouldEqual, 1)
			So(rs.Action, ShouldEqual, frontman.FilterActionContinue)
			So(rs.IcmpMatch, ShouldHaveLength, 2)
			So(rs.IcmpMatch[0].IcmpType, ShouldEqual, 8)
			So(rs.IcmpMatch[0].IcmpCodeRange.Start, ShouldEqual, 0)
			So(rs.IcmpMatch[0].IcmpCodeRange.End, ShouldEqual, 3)
			So(rs.IcmpMatch[1].IcmpType, ShouldEqual, 8)
			So(rs.IcmpMatch[1].IcmpCodeRange.Start, ShouldEqual, 5)
			So(rs.IcmpMatch[1].IcmpCodeRange.End, ShouldEqual, 5)
			So(rs.Log, ShouldBeTrue)
			So(rs.LogPrefix, ShouldEqual, "3617624947:5d6967333561e000018a3a65:5d60448a884e46000145cf67:3")

			rs, err = windows.ParseRuleSpec(xformedRules[2][2:]...)
			So(err, ShouldBeNil)
			So(rs.Protocol, ShouldEqual, 1)
			So(rs.Action, ShouldEqual, frontman.FilterActionAllow)
			So(rs.IcmpMatch, ShouldHaveLength, 1)
			So(rs.IcmpMatch[0].IcmpType, ShouldEqual, 8)
			So(rs.IcmpMatch[0].IcmpCodeRange.Start, ShouldEqual, 0)
			So(rs.IcmpMatch[0].IcmpCodeRange.End, ShouldEqual, 3)
			So(rs.Log, ShouldBeFalse)
			So(rs.LogPrefix, ShouldEqual, "")

		})
	})

	Convey("When I parse a set of app acl rules with an icmp rule", t, func() {

		var aclRules [][]string
		aclRules = append(aclRules, strings.Split("OUTPUT TRI-App-hostZ7PbqL-0 -p 1 --icmp-type 8/1:3 -j NFLOG --nflog-group 10 --nflog-prefix 531138568:5d6044b9e99572000149d650:5d60448a884e46000145cf67:6", " "))
		aclRules = append(aclRules, strings.Split("OUTPUT TRI-App-hostZ7PbqL-0 -p 1 --icmp-type 8/1:3 -j DROP", " "))

		aclInfo := &ACLInfo{}
		aclInfo.TCPPorts = "80,443"
		aclInfo.UDPPorts = ""
		aclInfo.PUType = common.HostPU

		xformedRules := transformACLRules(aclRules, aclInfo, nil, true)

		Convey("They should be merged to one rule for the HostPU-OUTPUT chain", func() {

			So(xformedRules, ShouldHaveLength, 1)
			So(xformedRules[0][1], ShouldEqual, "HostPU-OUTPUT")

			// check combined rule 1 and 2
			// OUTPUT HostPU-OUTPUT -p 1 --icmp-type 8/1:3 -j DROP -j NFLOG --nflog-group 10 --nflog-prefix 531138568:5d6044b9e99572000149d650:5d60448a884e46000145cf67:6
			rs, err := windows.ParseRuleSpec(xformedRules[0][2:]...)

			So(err, ShouldBeNil)
			So(rs.Protocol, ShouldEqual, 1)
			So(rs.Action, ShouldEqual, frontman.FilterActionBlock)
			So(rs.IcmpMatch, ShouldHaveLength, 1)
			So(rs.IcmpMatch[0].IcmpType, ShouldEqual, 8)
			So(rs.IcmpMatch[0].IcmpCodeRange.Start, ShouldEqual, 1)
			So(rs.IcmpMatch[0].IcmpCodeRange.End, ShouldEqual, 3)
			So(rs.Log, ShouldBeTrue)
			So(rs.LogPrefix, ShouldEqual, "531138568:5d6044b9e99572000149d650:5d60448a884e46000145cf67:6")

		})
	})

}
