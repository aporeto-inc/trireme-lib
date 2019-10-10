// +build windows

package provider

import (
	"strings"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/controller/internal/windows/frontman"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
)

func TestParseRuleSpecMatchSet(t *testing.T) {

	Convey("When I parse a rule with an ipset match", t, func() {
		ruleSpec, err := parseRuleSpec(strings.Split("-m set --match-set TRI-ipset-1 srcIP -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given ipset", func() {
			So(ruleSpec.action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.matchSet, ShouldNotBeNil)
			So(ruleSpec.matchSet, ShouldHaveLength, 1)
			So(ruleSpec.matchSet[0].matchSetName, ShouldEqual, "TRI-ipset-1")
			So(ruleSpec.matchSet[0].matchSetNegate, ShouldBeFalse)
			So(ruleSpec.matchSet[0].matchSetDstIp, ShouldBeFalse)
			So(ruleSpec.matchSet[0].matchSetDstPort, ShouldBeFalse)
			So(ruleSpec.matchSet[0].matchSetSrcIp, ShouldBeTrue)
			So(ruleSpec.matchSet[0].matchSetSrcPort, ShouldBeFalse)
		})
	})

	Convey("When I parse a rule with more than one ipset match", t, func() {
		ruleSpec, err := parseRuleSpec(strings.Split("-m set --match-set TRI-ipset-1 srcIP -j ACCEPT -m set --match-set TRI-ipset-2 dstIP", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given ipsets", func() {
			So(ruleSpec.action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.matchSet, ShouldNotBeNil)
			So(ruleSpec.matchSet, ShouldHaveLength, 2)
			So(ruleSpec.matchSet[0].matchSetName, ShouldEqual, "TRI-ipset-1")
			So(ruleSpec.matchSet[0].matchSetNegate, ShouldBeFalse)
			So(ruleSpec.matchSet[0].matchSetDstIp, ShouldBeFalse)
			So(ruleSpec.matchSet[0].matchSetDstPort, ShouldBeFalse)
			So(ruleSpec.matchSet[0].matchSetSrcIp, ShouldBeTrue)
			So(ruleSpec.matchSet[0].matchSetSrcPort, ShouldBeFalse)
			So(ruleSpec.matchSet[1].matchSetName, ShouldEqual, "TRI-ipset-2")
			So(ruleSpec.matchSet[1].matchSetNegate, ShouldBeFalse)
			So(ruleSpec.matchSet[1].matchSetDstIp, ShouldBeTrue)
			So(ruleSpec.matchSet[1].matchSetDstPort, ShouldBeFalse)
			So(ruleSpec.matchSet[1].matchSetSrcIp, ShouldBeFalse)
			So(ruleSpec.matchSet[1].matchSetSrcPort, ShouldBeFalse)
		})
	})

	Convey("When I parse a rule with an ipset match without ip or port specifier", t, func() {
		_, err := parseRuleSpec(strings.Split("-m set --match-set TRI-ipset-1 -j ACCEPT", " ")...)
		Convey("I should get an error", func() {
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "Missing argument for option 'match-set'")
		})
	})

	Convey("When I parse a rule with an ipset match with invalid ip or port specifier", t, func() {
		_, err := parseRuleSpec(strings.Split("-m set --match-set TRI-ipset-1 both -j ACCEPT", " ")...)
		Convey("I should get an error", func() {
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "ipset match needs ip/port specifier")
		})
	})

	Convey("When I parse a rule with an ipset match on port without protocol", t, func() {
		_, err := parseRuleSpec(strings.Split("-m set --match-set TRI-ipset-1 srcPort -j ACCEPT", " ")...)
		Convey("I should get an error", func() {
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "ipset match on port requires protocol be set")
		})
	})

	Convey("When I parse a rule with an ipset match on src port", t, func() {
		ruleSpec, err := parseRuleSpec(strings.Split("-p tcp -m set --match-set TRI-ipset-1 srcPort -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given ipset's port", func() {
			So(ruleSpec.action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.matchSet, ShouldNotBeNil)
			So(ruleSpec.matchSet, ShouldHaveLength, 1)
			So(ruleSpec.matchSet[0].matchSetName, ShouldEqual, "TRI-ipset-1")
			So(ruleSpec.matchSet[0].matchSetNegate, ShouldBeFalse)
			So(ruleSpec.matchSet[0].matchSetDstIp, ShouldBeFalse)
			So(ruleSpec.matchSet[0].matchSetDstPort, ShouldBeFalse)
			So(ruleSpec.matchSet[0].matchSetSrcIp, ShouldBeFalse)
			So(ruleSpec.matchSet[0].matchSetSrcPort, ShouldBeTrue)
		})
	})

	Convey("When I parse a rule with an ipset match on dst port", t, func() {
		ruleSpec, err := parseRuleSpec(strings.Split("-p tcp -m set --match-set TRI-ipset-1 dstPort -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given ipset's port", func() {
			So(ruleSpec.action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.matchSet, ShouldNotBeNil)
			So(ruleSpec.matchSet, ShouldHaveLength, 1)
			So(ruleSpec.matchSet[0].matchSetName, ShouldEqual, "TRI-ipset-1")
			So(ruleSpec.matchSet[0].matchSetNegate, ShouldBeFalse)
			So(ruleSpec.matchSet[0].matchSetDstIp, ShouldBeFalse)
			So(ruleSpec.matchSet[0].matchSetDstPort, ShouldBeTrue)
			So(ruleSpec.matchSet[0].matchSetSrcIp, ShouldBeFalse)
			So(ruleSpec.matchSet[0].matchSetSrcPort, ShouldBeFalse)
		})
	})

	Convey("When I parse a rule with an ipset match on ip and port", t, func() {
		ruleSpec, err := parseRuleSpec(strings.Split("-p tcp -m set --match-set TRI-ipset-1 dstIP,dstPort -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given ipset's ip and port", func() {
			So(ruleSpec.action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.matchSet, ShouldNotBeNil)
			So(ruleSpec.matchSet, ShouldHaveLength, 1)
			So(ruleSpec.matchSet[0].matchSetName, ShouldEqual, "TRI-ipset-1")
			So(ruleSpec.matchSet[0].matchSetNegate, ShouldBeFalse)
			So(ruleSpec.matchSet[0].matchSetDstIp, ShouldBeTrue)
			So(ruleSpec.matchSet[0].matchSetDstPort, ShouldBeTrue)
			So(ruleSpec.matchSet[0].matchSetSrcIp, ShouldBeFalse)
			So(ruleSpec.matchSet[0].matchSetSrcPort, ShouldBeFalse)
		})
	})

	Convey("When I parse a rule with an ipset match on ip and port mixed", t, func() {
		ruleSpec, err := parseRuleSpec(strings.Split("-p tcp -m set --match-set TRI-ipset-1 srcIP,dstPort -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given ipset's ip and port", func() {
			So(ruleSpec.action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.matchSet, ShouldNotBeNil)
			So(ruleSpec.matchSet, ShouldHaveLength, 1)
			So(ruleSpec.matchSet[0].matchSetName, ShouldEqual, "TRI-ipset-1")
			So(ruleSpec.matchSet[0].matchSetNegate, ShouldBeFalse)
			So(ruleSpec.matchSet[0].matchSetDstIp, ShouldBeFalse)
			So(ruleSpec.matchSet[0].matchSetDstPort, ShouldBeTrue)
			So(ruleSpec.matchSet[0].matchSetSrcIp, ShouldBeTrue)
			So(ruleSpec.matchSet[0].matchSetSrcPort, ShouldBeFalse)
		})
	})

	Convey("When I parse a rule with an ipset match on ip and port with one specifier (src)", t, func() {
		ruleSpec, err := parseRuleSpec(strings.Split("-p tcp -m set --match-set TRI-ipset-1 src -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given ipset's ip and port", func() {
			So(ruleSpec.action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.matchSet, ShouldNotBeNil)
			So(ruleSpec.matchSet, ShouldHaveLength, 1)
			So(ruleSpec.matchSet[0].matchSetName, ShouldEqual, "TRI-ipset-1")
			So(ruleSpec.matchSet[0].matchSetNegate, ShouldBeFalse)
			So(ruleSpec.matchSet[0].matchSetDstIp, ShouldBeFalse)
			So(ruleSpec.matchSet[0].matchSetDstPort, ShouldBeFalse)
			So(ruleSpec.matchSet[0].matchSetSrcIp, ShouldBeTrue)
			So(ruleSpec.matchSet[0].matchSetSrcPort, ShouldBeTrue)
		})
	})

	Convey("When I parse a rule with an ipset match on ip and port with one specifier (dst)", t, func() {
		ruleSpec, err := parseRuleSpec(strings.Split("-p tcp -m set --match-set TRI-ipset-1 dst -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given ipset's ip and port", func() {
			So(ruleSpec.action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.matchSet, ShouldNotBeNil)
			So(ruleSpec.matchSet, ShouldHaveLength, 1)
			So(ruleSpec.matchSet[0].matchSetName, ShouldEqual, "TRI-ipset-1")
			So(ruleSpec.matchSet[0].matchSetNegate, ShouldBeFalse)
			So(ruleSpec.matchSet[0].matchSetDstIp, ShouldBeTrue)
			So(ruleSpec.matchSet[0].matchSetDstPort, ShouldBeTrue)
			So(ruleSpec.matchSet[0].matchSetSrcIp, ShouldBeFalse)
			So(ruleSpec.matchSet[0].matchSetSrcPort, ShouldBeFalse)
		})
	})

	Convey("When I parse a rule with an ipset match on ip and port with specifier order important", t, func() {
		ruleSpec, err := parseRuleSpec(strings.Split("-p tcp -m set --match-set TRI-ipset-1 src,dst -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given ipset's ip and port", func() {
			So(ruleSpec.action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.matchSet, ShouldNotBeNil)
			So(ruleSpec.matchSet, ShouldHaveLength, 1)
			So(ruleSpec.matchSet[0].matchSetName, ShouldEqual, "TRI-ipset-1")
			So(ruleSpec.matchSet[0].matchSetNegate, ShouldBeFalse)
			So(ruleSpec.matchSet[0].matchSetDstIp, ShouldBeFalse)
			So(ruleSpec.matchSet[0].matchSetDstPort, ShouldBeTrue)
			So(ruleSpec.matchSet[0].matchSetSrcIp, ShouldBeTrue)
			So(ruleSpec.matchSet[0].matchSetSrcPort, ShouldBeFalse)
		})
	})

	Convey("When I parse a rule with no ipset match", t, func() {
		ruleSpec, err := parseRuleSpec(strings.Split("-j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept", func() {
			So(ruleSpec.action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.matchSet, ShouldBeNil)
		})
	})

	Convey("When I parse a rule with a negative ipset match", t, func() {
		ruleSpec, err := parseRuleSpec(strings.Split("-p tcp -m set ! --match-set TRI-ipset-1 dstPort -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept except for the given ipset", func() {
			So(ruleSpec.action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.matchSet, ShouldNotBeNil)
			So(ruleSpec.matchSet, ShouldHaveLength, 1)
			So(ruleSpec.matchSet[0].matchSetName, ShouldEqual, "TRI-ipset-1")
			So(ruleSpec.matchSet[0].matchSetNegate, ShouldBeTrue)
			So(ruleSpec.matchSet[0].matchSetDstIp, ShouldBeFalse)
			So(ruleSpec.matchSet[0].matchSetDstPort, ShouldBeTrue)
			So(ruleSpec.matchSet[0].matchSetSrcIp, ShouldBeFalse)
			So(ruleSpec.matchSet[0].matchSetSrcPort, ShouldBeFalse)
		})
	})

}

func TestParseRuleSpecProtocol(t *testing.T) {

	Convey("When I parse a rule with a protocol match on tcp", t, func() {
		ruleSpec, err := parseRuleSpec(strings.Split("-p tcp -m set --match-set TRI-ipset-1 srcPort -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given ipset/protocol", func() {
			So(ruleSpec.protocol, ShouldEqual, packet.IPProtocolTCP)
			So(ruleSpec.action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.matchSet, ShouldNotBeNil)
			So(ruleSpec.matchSet, ShouldHaveLength, 1)
		})
	})

	Convey("When I parse a rule with a protocol match on udp", t, func() {
		ruleSpec, err := parseRuleSpec(strings.Split("-p udp -m set --match-set TRI-ipset-1 srcPort -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given ipset/protocol", func() {
			So(ruleSpec.protocol, ShouldEqual, packet.IPProtocolUDP)
			So(ruleSpec.action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.matchSet, ShouldNotBeNil)
			So(ruleSpec.matchSet, ShouldHaveLength, 1)
		})
	})

	Convey("When I parse a rule with a protocol match on icmp", t, func() {
		ruleSpec, err := parseRuleSpec(strings.Split("-p icmp -j DROP", " ")...)
		So(err, ShouldBeNil)
		Convey("I should reject for the given protocol", func() {
			So(ruleSpec.protocol, ShouldEqual, 1)
			So(ruleSpec.action, ShouldEqual, frontman.FilterActionBlock)
		})
	})

	Convey("When I parse a rule with a protocol match on tcp by number", t, func() {
		ruleSpec, err := parseRuleSpec(strings.Split("-p 6 -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given protocol", func() {
			So(ruleSpec.protocol, ShouldEqual, packet.IPProtocolTCP)
			So(ruleSpec.action, ShouldEqual, frontman.FilterActionAllow)
		})
	})

	Convey("When I parse a rule with a protocol match on udp by number", t, func() {
		ruleSpec, err := parseRuleSpec(strings.Split("-p 17 -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given protocol", func() {
			So(ruleSpec.protocol, ShouldEqual, packet.IPProtocolUDP)
			So(ruleSpec.action, ShouldEqual, frontman.FilterActionAllow)
		})
	})

	Convey("When I parse a rule with a protocol match on ICMP for IPv6 by number", t, func() {
		ruleSpec, err := parseRuleSpec(strings.Split("-p 58 -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given protocol", func() {
			So(ruleSpec.protocol, ShouldEqual, 58)
			So(ruleSpec.action, ShouldEqual, frontman.FilterActionAllow)
		})
	})

	Convey("When I parse a rule with an invalid protocol match", t, func() {
		_, err := parseRuleSpec(strings.Split("-p http -m set --match-set TRI-ipset-1 srcPort -j ACCEPT", " ")...)
		Convey("I should get an error", func() {
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "invalid protocol")
		})
	})

}

func TestParseRuleSpecAction(t *testing.T) {

	Convey("When I parse a rule with an accept action", t, func() {
		ruleSpec, err := parseRuleSpec(strings.Split("-p tcp -m set --match-set TRI-ipset-1 dstPort -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept", func() {
			So(ruleSpec.action, ShouldEqual, frontman.FilterActionAllow)
		})
	})

	Convey("When I parse a rule with a drop action", t, func() {
		ruleSpec, err := parseRuleSpec(strings.Split("-p tcp -m set --match-set TRI-ipset-1 dstPort -j DROP", " ")...)
		So(err, ShouldBeNil)
		Convey("I should block", func() {
			So(ruleSpec.action, ShouldEqual, frontman.FilterActionBlock)
		})
	})

	Convey("When I parse a rule with an nfq action and a given mark", t, func() {
		ruleSpec, err := parseRuleSpec(strings.Split("-p tcp -m set --match-set TRI-ipset-1 srcIP,srcPort -j NFQUEUE -j MARK 100", " ")...)
		So(err, ShouldBeNil)
		Convey("I should route to nfq and set the mark", func() {
			So(ruleSpec.action, ShouldEqual, frontman.FilterActionNfq)
			So(ruleSpec.mark, ShouldEqual, 100)
		})
	})

	Convey("When I parse a rule with an nfq action without a mark", t, func() {
		_, err := parseRuleSpec(strings.Split("-p tcp -m set --match-set TRI-ipset-1 srcIP -j NFQUEUE", " ")...)
		Convey("I should get an error", func() {
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "nfq action needs to set mark")
		})
	})

	Convey("When I parse a rule with a proxy action", t, func() {
		ruleSpec, err := parseRuleSpec(strings.Split("-p tcp -m set --match-set TRI-ipset-1 dstPort -j REDIRECT --to-ports 20992", " ")...)
		So(err, ShouldBeNil)
		Convey("I should redirect to given port", func() {
			So(ruleSpec.action, ShouldEqual, frontman.FilterActionProxy)
			So(ruleSpec.proxyPort, ShouldEqual, 20992)
		})
	})

	Convey("When I parse a rule with a proxy action without a redirect port", t, func() {
		_, err := parseRuleSpec(strings.Split("-p tcp -m set --match-set TRI-ipset-1 srcIP -j REDIRECT", " ")...)
		Convey("I should get an error", func() {
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "no redirect port given")
		})
	})

	Convey("When I parse a rule with a log and drop action", t, func() {
		ruleSpec, err := parseRuleSpec(strings.Split("-p tcp -j DROP -j NFLOG", " ")...)
		So(err, ShouldBeNil)
		Convey("I should drop and log", func() {
			So(ruleSpec.action, ShouldEqual, frontman.FilterActionBlock)
			So(ruleSpec.log, ShouldBeTrue)
		})
	})

	Convey("When I parse a rule with a log and accept action", t, func() {
		ruleSpec, err := parseRuleSpec(strings.Split("-p tcp -j ACCEPT -j NFLOG", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept and log", func() {
			So(ruleSpec.action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.log, ShouldBeTrue)
		})
	})

}

func TestParseRuleSpecSPortDPort(t *testing.T) {

	Convey("When I parse a rule with a match on source port", t, func() {
		ruleSpec, err := parseRuleSpec(strings.Split("-p tcp --sport 12345 -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given source port", func() {
			So(ruleSpec.matchDstPort, ShouldHaveLength, 0)
			So(ruleSpec.matchSrcPort, ShouldHaveLength, 1)
			So(ruleSpec.matchSrcPort[0].portStart, ShouldEqual, 12345)
			So(ruleSpec.matchSrcPort[0].portEnd, ShouldEqual, 12345)
			So(ruleSpec.action, ShouldEqual, frontman.FilterActionAllow)
		})
	})

	Convey("When I parse a rule with a match on source port range", t, func() {
		ruleSpec, err := parseRuleSpec(strings.Split("-p tcp --sport 80,1024:65535 -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given source port range", func() {
			So(ruleSpec.matchSrcPort, ShouldHaveLength, 2)
			So(ruleSpec.matchSrcPort[0].portStart, ShouldEqual, 80)
			So(ruleSpec.matchSrcPort[0].portEnd, ShouldEqual, 80)
			So(ruleSpec.matchSrcPort[1].portStart, ShouldEqual, 1024)
			So(ruleSpec.matchSrcPort[1].portEnd, ShouldEqual, 65535)
			So(ruleSpec.matchDstPort, ShouldHaveLength, 0)
			So(ruleSpec.action, ShouldEqual, frontman.FilterActionAllow)
		})
	})

	Convey("When I parse a rule with a match on dest port", t, func() {
		ruleSpec, err := parseRuleSpec(strings.Split("-p tcp --dport 80 -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given dest port", func() {
			So(ruleSpec.matchSrcPort, ShouldHaveLength, 0)
			So(ruleSpec.matchDstPort, ShouldHaveLength, 1)
			So(ruleSpec.matchDstPort[0].portStart, ShouldEqual, 80)
			So(ruleSpec.matchDstPort[0].portEnd, ShouldEqual, 80)
			So(ruleSpec.action, ShouldEqual, frontman.FilterActionAllow)
		})
	})

	Convey("When I parse a rule with a match on dest port range", t, func() {
		ruleSpec, err := parseRuleSpec(strings.Split("-p tcp --dport 1234,8080:8443,65000:65005,65530 -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given dest port range", func() {
			So(ruleSpec.matchDstPort, ShouldHaveLength, 4)
			So(ruleSpec.matchDstPort[0].portStart, ShouldEqual, 1234)
			So(ruleSpec.matchDstPort[0].portEnd, ShouldEqual, 1234)
			So(ruleSpec.matchDstPort[1].portStart, ShouldEqual, 8080)
			So(ruleSpec.matchDstPort[1].portEnd, ShouldEqual, 8443)
			So(ruleSpec.matchDstPort[2].portStart, ShouldEqual, 65000)
			So(ruleSpec.matchDstPort[2].portEnd, ShouldEqual, 65005)
			So(ruleSpec.matchDstPort[3].portStart, ShouldEqual, 65530)
			So(ruleSpec.matchDstPort[3].portEnd, ShouldEqual, 65530)
			So(ruleSpec.matchSrcPort, ShouldHaveLength, 0)
			So(ruleSpec.action, ShouldEqual, frontman.FilterActionAllow)
		})
	})

}

func TestParseRuleSpecMatchString(t *testing.T) {

	Convey("When I parse a rule with a string match", t, func() {
		ruleSpec, err := parseRuleSpec(strings.Split("-p udp -m set --match-set TRI-ipset-udp-1 srcIP -m string --string n30njxq7bmiwr6dtxq --offset 2 -j NFQUEUE -j MARK 1234 -m set --match-set TRI-ipset-udp-2 srcIP", " ")...)
		So(err, ShouldBeNil)
		Convey("I should forward to nfq if I see the given string at the given offset", func() {
			So(ruleSpec.action, ShouldEqual, frontman.FilterActionNfq)
			So(ruleSpec.mark, ShouldEqual, 1234)
			So(ruleSpec.protocol, ShouldEqual, packet.IPProtocolUDP)
			So(ruleSpec.matchBytesOffset, ShouldEqual, 2)
			So(ruleSpec.matchBytes, ShouldResemble, []byte("n30njxq7bmiwr6dtxq"))
			So(ruleSpec.matchSet, ShouldNotBeNil)
			So(ruleSpec.matchSet, ShouldHaveLength, 2)
			So(ruleSpec.matchSet[0].matchSetName, ShouldEqual, "TRI-ipset-udp-1")
			So(ruleSpec.matchSet[0].matchSetNegate, ShouldBeFalse)
			So(ruleSpec.matchSet[0].matchSetDstIp, ShouldBeFalse)
			So(ruleSpec.matchSet[0].matchSetDstPort, ShouldBeFalse)
			So(ruleSpec.matchSet[0].matchSetSrcIp, ShouldBeTrue)
			So(ruleSpec.matchSet[0].matchSetSrcPort, ShouldBeFalse)
			So(ruleSpec.matchSet[1].matchSetName, ShouldEqual, "TRI-ipset-udp-2")
			So(ruleSpec.matchSet[1].matchSetNegate, ShouldBeFalse)
			So(ruleSpec.matchSet[1].matchSetDstIp, ShouldBeFalse)
			So(ruleSpec.matchSet[1].matchSetDstPort, ShouldBeFalse)
			So(ruleSpec.matchSet[1].matchSetSrcIp, ShouldBeTrue)
			So(ruleSpec.matchSet[1].matchSetSrcPort, ShouldBeFalse)
		})
	})

}

// test generated acl rule
func TestParseRuleSpecACLRule(t *testing.T) {

	Convey("When I parse an acl rule for nflog", t, func() {
		ruleSpec, err := parseRuleSpec(strings.Split("-p 6 -m set --match-set TRI-v4-ext-cUDEx1114Z2xd dst -m state --state NEW -m set ! --match-set TRI-v4-TargetTCP dst --match multiport --dports 1:65535 -m state --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 3617624947:5d6044b9e99572000149d650:5d60448a884e46000145cf67:6", " ")...)
		So(err, ShouldBeNil)
		Convey("I should be able to interpret it as a windows rule", func() {
			So(ruleSpec.protocol, ShouldEqual, packet.IPProtocolTCP)
			So(ruleSpec.matchSrcPort, ShouldHaveLength, 0)
			So(ruleSpec.matchDstPort, ShouldHaveLength, 1)
			So(ruleSpec.matchDstPort[0].portStart, ShouldEqual, 1)
			So(ruleSpec.matchDstPort[0].portEnd, ShouldEqual, 65535)
			So(ruleSpec.action, ShouldEqual, 0) // degenerate log-only rule
			So(ruleSpec.log, ShouldBeTrue)
			So(ruleSpec.logPrefix, ShouldEqual, "3617624947:5d6044b9e99572000149d650:5d60448a884e46000145cf67:6")
			So(ruleSpec.matchSet, ShouldNotBeNil)
			So(ruleSpec.matchSet, ShouldHaveLength, 2)
			So(ruleSpec.matchSet[0].matchSetName, ShouldEqual, "TRI-v4-ext-cUDEx1114Z2xd")
			So(ruleSpec.matchSet[0].matchSetNegate, ShouldBeFalse)
			So(ruleSpec.matchSet[0].matchSetDstIp, ShouldBeTrue)
			So(ruleSpec.matchSet[0].matchSetDstPort, ShouldBeTrue)
			So(ruleSpec.matchSet[0].matchSetSrcIp, ShouldBeFalse)
			So(ruleSpec.matchSet[0].matchSetSrcPort, ShouldBeFalse)
			So(ruleSpec.matchSet[1].matchSetName, ShouldEqual, "TRI-v4-TargetTCP")
			So(ruleSpec.matchSet[1].matchSetNegate, ShouldBeTrue)
			So(ruleSpec.matchSet[1].matchSetDstIp, ShouldBeTrue)
			So(ruleSpec.matchSet[1].matchSetDstPort, ShouldBeTrue)
			So(ruleSpec.matchSet[1].matchSetSrcIp, ShouldBeFalse)
			So(ruleSpec.matchSet[1].matchSetSrcPort, ShouldBeFalse)
		})
	})

	Convey("When I parse an acl rule for drop or accept", t, func() {
		ruleSpec, err := parseRuleSpec(strings.Split("-p 6 -m set --match-set TRI-v4-ext-cUDEx1114Z2xd dst -m state --state NEW -m set ! --match-set TRI-v4-TargetTCP dst --match multiport --dports 1:65535 -j DROP", " ")...)
		So(err, ShouldBeNil)
		Convey("I should be able to interpret it as a windows rule", func() {
			So(ruleSpec.protocol, ShouldEqual, packet.IPProtocolTCP)
			So(ruleSpec.matchSrcPort, ShouldHaveLength, 0)
			So(ruleSpec.matchDstPort, ShouldHaveLength, 1)
			So(ruleSpec.matchDstPort[0].portStart, ShouldEqual, 1)
			So(ruleSpec.matchDstPort[0].portEnd, ShouldEqual, 65535)
			So(ruleSpec.action, ShouldEqual, frontman.FilterActionBlock)
			So(ruleSpec.log, ShouldBeFalse)
			So(ruleSpec.matchSet, ShouldNotBeNil)
			So(ruleSpec.matchSet, ShouldHaveLength, 2)
			So(ruleSpec.matchSet[0].matchSetName, ShouldEqual, "TRI-v4-ext-cUDEx1114Z2xd")
			So(ruleSpec.matchSet[0].matchSetNegate, ShouldBeFalse)
			So(ruleSpec.matchSet[0].matchSetDstIp, ShouldBeTrue)
			So(ruleSpec.matchSet[0].matchSetDstPort, ShouldBeTrue)
			So(ruleSpec.matchSet[0].matchSetSrcIp, ShouldBeFalse)
			So(ruleSpec.matchSet[0].matchSetSrcPort, ShouldBeFalse)
			So(ruleSpec.matchSet[1].matchSetName, ShouldEqual, "TRI-v4-TargetTCP")
			So(ruleSpec.matchSet[1].matchSetNegate, ShouldBeTrue)
			So(ruleSpec.matchSet[1].matchSetDstIp, ShouldBeTrue)
			So(ruleSpec.matchSet[1].matchSetDstPort, ShouldBeTrue)
			So(ruleSpec.matchSet[1].matchSetSrcIp, ShouldBeFalse)
			So(ruleSpec.matchSet[1].matchSetSrcPort, ShouldBeFalse)
		})
	})

}
