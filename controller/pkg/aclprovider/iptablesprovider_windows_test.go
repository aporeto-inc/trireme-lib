// +build windows

package provider

import (
	"strings"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/controller/internal/windows"
	"go.aporeto.io/trireme-lib/controller/internal/windows/frontman"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
)

func TestParseRuleSpecMatchSet(t *testing.T) {

	Convey("When I parse a rule with an ipset match", t, func() {
		ruleSpec, err := windows.ParseRuleSpec(strings.Split("-m set --match-set TRI-ipset-1 srcIP -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given ipset", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.MatchSet, ShouldNotBeNil)
			So(ruleSpec.MatchSet, ShouldHaveLength, 1)
			So(ruleSpec.MatchSet[0].MatchSetName, ShouldEqual, "TRI-ipset-1")
			So(ruleSpec.MatchSet[0].MatchSetNegate, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstIp, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstPort, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetSrcIp, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetSrcPort, ShouldBeFalse)
		})
	})

	Convey("When I parse a rule with more than one ipset match", t, func() {
		ruleSpec, err := windows.ParseRuleSpec(strings.Split("-m set --match-set TRI-ipset-1 srcIP -j ACCEPT -m set --match-set TRI-ipset-2 dstIP", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given ipsets", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.MatchSet, ShouldNotBeNil)
			So(ruleSpec.MatchSet, ShouldHaveLength, 2)
			So(ruleSpec.MatchSet[0].MatchSetName, ShouldEqual, "TRI-ipset-1")
			So(ruleSpec.MatchSet[0].MatchSetNegate, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstIp, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstPort, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetSrcIp, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetSrcPort, ShouldBeFalse)
			So(ruleSpec.MatchSet[1].MatchSetName, ShouldEqual, "TRI-ipset-2")
			So(ruleSpec.MatchSet[1].MatchSetNegate, ShouldBeFalse)
			So(ruleSpec.MatchSet[1].MatchSetDstIp, ShouldBeTrue)
			So(ruleSpec.MatchSet[1].MatchSetDstPort, ShouldBeFalse)
			So(ruleSpec.MatchSet[1].MatchSetSrcIp, ShouldBeFalse)
			So(ruleSpec.MatchSet[1].MatchSetSrcPort, ShouldBeFalse)
		})
	})

	Convey("When I parse a rule with an ipset match without ip or port specifier", t, func() {
		_, err := windows.ParseRuleSpec(strings.Split("-m set --match-set TRI-ipset-1 -j ACCEPT", " ")...)
		Convey("I should get an error", func() {
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "Missing argument for option 'match-set'")
		})
	})

	Convey("When I parse a rule with an ipset match with invalid ip or port specifier", t, func() {
		_, err := windows.ParseRuleSpec(strings.Split("-m set --match-set TRI-ipset-1 both -j ACCEPT", " ")...)
		Convey("I should get an error", func() {
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "ipset match needs ip/port specifier")
		})
	})

	Convey("When I parse a rule with an ipset match on port without protocol", t, func() {
		_, err := windows.ParseRuleSpec(strings.Split("-m set --match-set TRI-ipset-1 srcPort -j ACCEPT", " ")...)
		Convey("I should get an error", func() {
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "ipset match on port requires protocol be set")
		})
	})

	Convey("When I parse a rule with an ipset match on src port", t, func() {
		ruleSpec, err := windows.ParseRuleSpec(strings.Split("-p tcp -m set --match-set TRI-ipset-1 srcPort -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given ipset's port", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.MatchSet, ShouldNotBeNil)
			So(ruleSpec.MatchSet, ShouldHaveLength, 1)
			So(ruleSpec.MatchSet[0].MatchSetName, ShouldEqual, "TRI-ipset-1")
			So(ruleSpec.MatchSet[0].MatchSetNegate, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstIp, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstPort, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetSrcIp, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetSrcPort, ShouldBeTrue)
		})
	})

	Convey("When I parse a rule with an ipset match on dst port", t, func() {
		ruleSpec, err := windows.ParseRuleSpec(strings.Split("-p tcp -m set --match-set TRI-ipset-1 dstPort -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given ipset's port", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.MatchSet, ShouldNotBeNil)
			So(ruleSpec.MatchSet, ShouldHaveLength, 1)
			So(ruleSpec.MatchSet[0].MatchSetName, ShouldEqual, "TRI-ipset-1")
			So(ruleSpec.MatchSet[0].MatchSetNegate, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstIp, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstPort, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetSrcIp, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetSrcPort, ShouldBeFalse)
		})
	})

	Convey("When I parse a rule with an ipset match on ip and port", t, func() {
		ruleSpec, err := windows.ParseRuleSpec(strings.Split("-p tcp -m set --match-set TRI-ipset-1 dstIP,dstPort -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given ipset's ip and port", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.MatchSet, ShouldNotBeNil)
			So(ruleSpec.MatchSet, ShouldHaveLength, 1)
			So(ruleSpec.MatchSet[0].MatchSetName, ShouldEqual, "TRI-ipset-1")
			So(ruleSpec.MatchSet[0].MatchSetNegate, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstIp, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetDstPort, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetSrcIp, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetSrcPort, ShouldBeFalse)
		})
	})

	Convey("When I parse a rule with an ipset match on ip and port mixed", t, func() {
		ruleSpec, err := windows.ParseRuleSpec(strings.Split("-p tcp -m set --match-set TRI-ipset-1 srcIP,dstPort -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given ipset's ip and port", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.MatchSet, ShouldNotBeNil)
			So(ruleSpec.MatchSet, ShouldHaveLength, 1)
			So(ruleSpec.MatchSet[0].MatchSetName, ShouldEqual, "TRI-ipset-1")
			So(ruleSpec.MatchSet[0].MatchSetNegate, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstIp, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstPort, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetSrcIp, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetSrcPort, ShouldBeFalse)
		})
	})

	Convey("When I parse a rule with an ipset match on ip and port with one specifier (src)", t, func() {
		ruleSpec, err := windows.ParseRuleSpec(strings.Split("-p tcp -m set --match-set TRI-ipset-1 src -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given ipset's ip and port", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.MatchSet, ShouldNotBeNil)
			So(ruleSpec.MatchSet, ShouldHaveLength, 1)
			So(ruleSpec.MatchSet[0].MatchSetName, ShouldEqual, "TRI-ipset-1")
			So(ruleSpec.MatchSet[0].MatchSetNegate, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstIp, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstPort, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetSrcIp, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetSrcPort, ShouldBeTrue)
		})
	})

	Convey("When I parse a rule with an ipset match on ip and port with one specifier (dst)", t, func() {
		ruleSpec, err := windows.ParseRuleSpec(strings.Split("-p tcp -m set --match-set TRI-ipset-1 dst -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given ipset's ip and port", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.MatchSet, ShouldNotBeNil)
			So(ruleSpec.MatchSet, ShouldHaveLength, 1)
			So(ruleSpec.MatchSet[0].MatchSetName, ShouldEqual, "TRI-ipset-1")
			So(ruleSpec.MatchSet[0].MatchSetNegate, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstIp, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetDstPort, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetSrcIp, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetSrcPort, ShouldBeFalse)
		})
	})

	Convey("When I parse a rule with an ipset match on ip and port with specifier order important", t, func() {
		ruleSpec, err := windows.ParseRuleSpec(strings.Split("-p tcp -m set --match-set TRI-ipset-1 src,dst -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given ipset's ip and port", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.MatchSet, ShouldNotBeNil)
			So(ruleSpec.MatchSet, ShouldHaveLength, 1)
			So(ruleSpec.MatchSet[0].MatchSetName, ShouldEqual, "TRI-ipset-1")
			So(ruleSpec.MatchSet[0].MatchSetNegate, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstIp, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstPort, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetSrcIp, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetSrcPort, ShouldBeFalse)
		})
	})

	Convey("When I parse a rule with no ipset match", t, func() {
		ruleSpec, err := windows.ParseRuleSpec(strings.Split("-j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.MatchSet, ShouldBeNil)
		})
	})

	Convey("When I parse a rule with a negative ipset match", t, func() {
		ruleSpec, err := windows.ParseRuleSpec(strings.Split("-p tcp -m set ! --match-set TRI-ipset-1 dstPort -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept except for the given ipset", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.MatchSet, ShouldNotBeNil)
			So(ruleSpec.MatchSet, ShouldHaveLength, 1)
			So(ruleSpec.MatchSet[0].MatchSetName, ShouldEqual, "TRI-ipset-1")
			So(ruleSpec.MatchSet[0].MatchSetNegate, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetDstIp, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstPort, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetSrcIp, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetSrcPort, ShouldBeFalse)
		})
	})

}

func TestParseRuleSpecProtocol(t *testing.T) {

	Convey("When I parse a rule with a protocol match on tcp", t, func() {
		ruleSpec, err := windows.ParseRuleSpec(strings.Split("-p tcp -m set --match-set TRI-ipset-1 srcPort -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given ipset/protocol", func() {
			So(ruleSpec.Protocol, ShouldEqual, packet.IPProtocolTCP)
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.MatchSet, ShouldNotBeNil)
			So(ruleSpec.MatchSet, ShouldHaveLength, 1)
		})
	})

	Convey("When I parse a rule with a protocol match on udp", t, func() {
		ruleSpec, err := windows.ParseRuleSpec(strings.Split("-p udp -m set --match-set TRI-ipset-1 srcPort -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given ipset/protocol", func() {
			So(ruleSpec.Protocol, ShouldEqual, packet.IPProtocolUDP)
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.MatchSet, ShouldNotBeNil)
			So(ruleSpec.MatchSet, ShouldHaveLength, 1)
		})
	})

	Convey("When I parse a rule with a protocol match on icmp", t, func() {
		ruleSpec, err := windows.ParseRuleSpec(strings.Split("-p icmp -j DROP", " ")...)
		So(err, ShouldBeNil)
		Convey("I should reject for the given protocol", func() {
			So(ruleSpec.Protocol, ShouldEqual, 1)
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionBlock)
		})
	})

	Convey("When I parse a rule with a protocol match on tcp by number", t, func() {
		ruleSpec, err := windows.ParseRuleSpec(strings.Split("-p 6 -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given protocol", func() {
			So(ruleSpec.Protocol, ShouldEqual, packet.IPProtocolTCP)
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
		})
	})

	Convey("When I parse a rule with a protocol match on udp by number", t, func() {
		ruleSpec, err := windows.ParseRuleSpec(strings.Split("-p 17 -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given protocol", func() {
			So(ruleSpec.Protocol, ShouldEqual, packet.IPProtocolUDP)
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
		})
	})

	Convey("When I parse a rule with a protocol match on ICMP for IPv6 by number", t, func() {
		ruleSpec, err := windows.ParseRuleSpec(strings.Split("-p 58 -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given protocol", func() {
			So(ruleSpec.Protocol, ShouldEqual, 58)
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
		})
	})

	Convey("When I parse a rule with an invalid protocol match", t, func() {
		_, err := windows.ParseRuleSpec(strings.Split("-p http -m set --match-set TRI-ipset-1 srcPort -j ACCEPT", " ")...)
		Convey("I should get an error", func() {
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "invalid protocol")
		})
	})

}

func TestParseRuleSpecAction(t *testing.T) {

	Convey("When I parse a rule with an accept action", t, func() {
		ruleSpec, err := windows.ParseRuleSpec(strings.Split("-p tcp -m set --match-set TRI-ipset-1 dstPort -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
		})
	})

	Convey("When I parse a rule with a drop action", t, func() {
		ruleSpec, err := windows.ParseRuleSpec(strings.Split("-p tcp -m set --match-set TRI-ipset-1 dstPort -j DROP", " ")...)
		So(err, ShouldBeNil)
		Convey("I should block", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionBlock)
		})
	})

	Convey("When I parse a rule with an nfq action and a given mark", t, func() {
		ruleSpec, err := windows.ParseRuleSpec(strings.Split("-p tcp -m set --match-set TRI-ipset-1 srcIP,srcPort -j NFQUEUE -j MARK 100", " ")...)
		So(err, ShouldBeNil)
		Convey("I should route to nfq and set the mark", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionNfq)
			So(ruleSpec.Mark, ShouldEqual, 100)
		})
	})

	Convey("When I parse a rule with an nfq action without a mark", t, func() {
		_, err := windows.ParseRuleSpec(strings.Split("-p tcp -m set --match-set TRI-ipset-1 srcIP -j NFQUEUE", " ")...)
		Convey("I should get an error", func() {
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "nfq action needs to set mark")
		})
	})

	Convey("When I parse a rule with a force nfq action", t, func() {
		ruleSpec, err := windows.ParseRuleSpec(strings.Split("-p tcp -m set --match-set TRI-ipset-1 srcIP,srcPort -j NFQUEUE --queue-force -j MARK 100", " ")...)
		So(err, ShouldBeNil)
		Convey("I should route to nfq (without honoring ignore-flow) and set the mark", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionForceNfq)
			So(ruleSpec.Mark, ShouldEqual, 100)
		})
	})

	Convey("When I parse a rule with a proxy action", t, func() {
		ruleSpec, err := windows.ParseRuleSpec(strings.Split("-p tcp -m set --match-set TRI-ipset-1 dstPort -j REDIRECT --to-ports 20992", " ")...)
		So(err, ShouldBeNil)
		Convey("I should redirect to given port", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionProxy)
			So(ruleSpec.ProxyPort, ShouldEqual, 20992)
		})
	})

	Convey("When I parse a rule with a proxy action without a redirect port", t, func() {
		_, err := windows.ParseRuleSpec(strings.Split("-p tcp -m set --match-set TRI-ipset-1 srcIP -j REDIRECT", " ")...)
		Convey("I should get an error", func() {
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "no redirect port given")
		})
	})

	Convey("When I parse a rule with a log and drop action", t, func() {
		ruleSpec, err := windows.ParseRuleSpec(strings.Split("-p tcp -j DROP -j NFLOG", " ")...)
		So(err, ShouldBeNil)
		Convey("I should drop and log", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionBlock)
			So(ruleSpec.Log, ShouldBeTrue)
		})
	})

	Convey("When I parse a rule with a log and accept action", t, func() {
		ruleSpec, err := windows.ParseRuleSpec(strings.Split("-p tcp -j ACCEPT -j NFLOG", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept and log", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.Log, ShouldBeTrue)
		})
	})

}

func TestParseRuleSpecSPortDPort(t *testing.T) {

	Convey("When I parse a rule with a match on source port", t, func() {
		ruleSpec, err := windows.ParseRuleSpec(strings.Split("-p tcp --sport 12345 -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given source port", func() {
			So(ruleSpec.MatchDstPort, ShouldHaveLength, 0)
			So(ruleSpec.MatchSrcPort, ShouldHaveLength, 1)
			So(ruleSpec.MatchSrcPort[0].PortStart, ShouldEqual, 12345)
			So(ruleSpec.MatchSrcPort[0].PortEnd, ShouldEqual, 12345)
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
		})
	})

	Convey("When I parse a rule with a match on source port range", t, func() {
		ruleSpec, err := windows.ParseRuleSpec(strings.Split("-p tcp --sport 80,1024:65535 -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given source port range", func() {
			So(ruleSpec.MatchSrcPort, ShouldHaveLength, 2)
			So(ruleSpec.MatchSrcPort[0].PortStart, ShouldEqual, 80)
			So(ruleSpec.MatchSrcPort[0].PortEnd, ShouldEqual, 80)
			So(ruleSpec.MatchSrcPort[1].PortStart, ShouldEqual, 1024)
			So(ruleSpec.MatchSrcPort[1].PortEnd, ShouldEqual, 65535)
			So(ruleSpec.MatchDstPort, ShouldHaveLength, 0)
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
		})
	})

	Convey("When I parse a rule with a match on dest port", t, func() {
		ruleSpec, err := windows.ParseRuleSpec(strings.Split("-p tcp --dport 80 -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given dest port", func() {
			So(ruleSpec.MatchSrcPort, ShouldHaveLength, 0)
			So(ruleSpec.MatchDstPort, ShouldHaveLength, 1)
			So(ruleSpec.MatchDstPort[0].PortStart, ShouldEqual, 80)
			So(ruleSpec.MatchDstPort[0].PortEnd, ShouldEqual, 80)
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
		})
	})

	Convey("When I parse a rule with a match on dest port range", t, func() {
		ruleSpec, err := windows.ParseRuleSpec(strings.Split("-p tcp --dport 1234,8080:8443,65000:65005,65530 -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given dest port range", func() {
			So(ruleSpec.MatchDstPort, ShouldHaveLength, 4)
			So(ruleSpec.MatchDstPort[0].PortStart, ShouldEqual, 1234)
			So(ruleSpec.MatchDstPort[0].PortEnd, ShouldEqual, 1234)
			So(ruleSpec.MatchDstPort[1].PortStart, ShouldEqual, 8080)
			So(ruleSpec.MatchDstPort[1].PortEnd, ShouldEqual, 8443)
			So(ruleSpec.MatchDstPort[2].PortStart, ShouldEqual, 65000)
			So(ruleSpec.MatchDstPort[2].PortEnd, ShouldEqual, 65005)
			So(ruleSpec.MatchDstPort[3].PortStart, ShouldEqual, 65530)
			So(ruleSpec.MatchDstPort[3].PortEnd, ShouldEqual, 65530)
			So(ruleSpec.MatchSrcPort, ShouldHaveLength, 0)
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
		})
	})

}

func TestParseRuleSpecMatchString(t *testing.T) {

	Convey("When I parse a rule with a string match", t, func() {
		ruleSpec, err := windows.ParseRuleSpec(strings.Split("-p udp -m set --match-set TRI-ipset-udp-1 srcIP -m string --string n30njxq7bmiwr6dtxq --offset 2 -j NFQUEUE -j MARK 1234 -m set --match-set TRI-ipset-udp-2 srcIP", " ")...)
		So(err, ShouldBeNil)
		Convey("I should forward to nfq if I see the given string at the given offset", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionNfq)
			So(ruleSpec.Mark, ShouldEqual, 1234)
			So(ruleSpec.Protocol, ShouldEqual, packet.IPProtocolUDP)
			So(ruleSpec.MatchBytesOffset, ShouldEqual, 2)
			So(ruleSpec.MatchBytes, ShouldResemble, []byte("n30njxq7bmiwr6dtxq"))
			So(ruleSpec.MatchSet, ShouldNotBeNil)
			So(ruleSpec.MatchSet, ShouldHaveLength, 2)
			So(ruleSpec.MatchSet[0].MatchSetName, ShouldEqual, "TRI-ipset-udp-1")
			So(ruleSpec.MatchSet[0].MatchSetNegate, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstIp, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstPort, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetSrcIp, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetSrcPort, ShouldBeFalse)
			So(ruleSpec.MatchSet[1].MatchSetName, ShouldEqual, "TRI-ipset-udp-2")
			So(ruleSpec.MatchSet[1].MatchSetNegate, ShouldBeFalse)
			So(ruleSpec.MatchSet[1].MatchSetDstIp, ShouldBeFalse)
			So(ruleSpec.MatchSet[1].MatchSetDstPort, ShouldBeFalse)
			So(ruleSpec.MatchSet[1].MatchSetSrcIp, ShouldBeTrue)
			So(ruleSpec.MatchSet[1].MatchSetSrcPort, ShouldBeFalse)
		})
	})

}

func TestParseRuleSpecMatchPid(t *testing.T) {

	Convey("When I parse a rule with a process ID match", t, func() {
		ruleSpec, err := windows.ParseRuleSpec(strings.Split("-p tcp -m set --match-set TRI-ipset-tcp-1 dstIP -j NFQUEUE -j MARK 103 -m owner --pid-owner 2438", " ")...)
		So(err, ShouldBeNil)
		Convey("I should forward to nfq for all packets from or two the given process", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionNfq)
			So(ruleSpec.Mark, ShouldEqual, 103)
			So(ruleSpec.Protocol, ShouldEqual, packet.IPProtocolTCP)
			So(ruleSpec.ProcessId, ShouldEqual, 2438)
			So(ruleSpec.MatchSet, ShouldNotBeNil)
			So(ruleSpec.MatchSet, ShouldHaveLength, 1)
			So(ruleSpec.MatchSet[0].MatchSetName, ShouldEqual, "TRI-ipset-tcp-1")
			So(ruleSpec.MatchSet[0].MatchSetNegate, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstIp, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetDstPort, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetSrcIp, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetSrcPort, ShouldBeFalse)
		})
	})

}

// test generated acl rule
func TestParseRuleSpecACLRule(t *testing.T) {

	Convey("When I parse an acl rule for nflog", t, func() {
		ruleSpec, err := windows.ParseRuleSpec(strings.Split("-p 6 -m set --match-set TRI-v4-ext-cUDEx1114Z2xd dst -m state --state NEW -m set ! --match-set TRI-v4-TargetTCP dst --match multiport --dports 1:65535 -m state --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 3617624947:5d6044b9e99572000149d650:5d60448a884e46000145cf67:6", " ")...)
		So(err, ShouldBeNil)
		Convey("I should be able to interpret it as a windows rule", func() {
			So(ruleSpec.Protocol, ShouldEqual, packet.IPProtocolTCP)
			So(ruleSpec.MatchSrcPort, ShouldHaveLength, 0)
			So(ruleSpec.MatchDstPort, ShouldHaveLength, 1)
			So(ruleSpec.MatchDstPort[0].PortStart, ShouldEqual, 1)
			So(ruleSpec.MatchDstPort[0].PortEnd, ShouldEqual, 65535)
			So(ruleSpec.Action, ShouldEqual, 0) // degenerate log-only rule
			So(ruleSpec.Log, ShouldBeTrue)
			So(ruleSpec.LogPrefix, ShouldEqual, "3617624947:5d6044b9e99572000149d650:5d60448a884e46000145cf67:6")
			So(ruleSpec.MatchSet, ShouldNotBeNil)
			So(ruleSpec.MatchSet, ShouldHaveLength, 2)
			So(ruleSpec.MatchSet[0].MatchSetName, ShouldEqual, "TRI-v4-ext-cUDEx1114Z2xd")
			So(ruleSpec.MatchSet[0].MatchSetNegate, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstIp, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetDstPort, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetSrcIp, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetSrcPort, ShouldBeFalse)
			So(ruleSpec.MatchSet[1].MatchSetName, ShouldEqual, "TRI-v4-TargetTCP")
			So(ruleSpec.MatchSet[1].MatchSetNegate, ShouldBeTrue)
			So(ruleSpec.MatchSet[1].MatchSetDstIp, ShouldBeTrue)
			So(ruleSpec.MatchSet[1].MatchSetDstPort, ShouldBeTrue)
			So(ruleSpec.MatchSet[1].MatchSetSrcIp, ShouldBeFalse)
			So(ruleSpec.MatchSet[1].MatchSetSrcPort, ShouldBeFalse)
		})
	})

	Convey("When I parse an acl rule for drop or accept", t, func() {
		ruleSpec, err := windows.ParseRuleSpec(strings.Split("-p 6 -m set --match-set TRI-v4-ext-cUDEx1114Z2xd dst -m state --state NEW -m set ! --match-set TRI-v4-TargetTCP dst --match multiport --dports 1:65535 -j DROP", " ")...)
		So(err, ShouldBeNil)
		Convey("I should be able to interpret it as a windows rule", func() {
			So(ruleSpec.Protocol, ShouldEqual, packet.IPProtocolTCP)
			So(ruleSpec.MatchSrcPort, ShouldHaveLength, 0)
			So(ruleSpec.MatchDstPort, ShouldHaveLength, 1)
			So(ruleSpec.MatchDstPort[0].PortStart, ShouldEqual, 1)
			So(ruleSpec.MatchDstPort[0].PortEnd, ShouldEqual, 65535)
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionBlock)
			So(ruleSpec.Log, ShouldBeFalse)
			So(ruleSpec.MatchSet, ShouldNotBeNil)
			So(ruleSpec.MatchSet, ShouldHaveLength, 2)
			So(ruleSpec.MatchSet[0].MatchSetName, ShouldEqual, "TRI-v4-ext-cUDEx1114Z2xd")
			So(ruleSpec.MatchSet[0].MatchSetNegate, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstIp, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetDstPort, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetSrcIp, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetSrcPort, ShouldBeFalse)
			So(ruleSpec.MatchSet[1].MatchSetName, ShouldEqual, "TRI-v4-TargetTCP")
			So(ruleSpec.MatchSet[1].MatchSetNegate, ShouldBeTrue)
			So(ruleSpec.MatchSet[1].MatchSetDstIp, ShouldBeTrue)
			So(ruleSpec.MatchSet[1].MatchSetDstPort, ShouldBeTrue)
			So(ruleSpec.MatchSet[1].MatchSetSrcIp, ShouldBeFalse)
			So(ruleSpec.MatchSet[1].MatchSetSrcPort, ShouldBeFalse)
		})
	})

}
