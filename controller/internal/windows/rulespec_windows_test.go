// +build windows

package windows

import (
	"strings"
	"testing"

	"github.com/kballard/go-shellquote"
	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/enforcerd/trireme-lib/utils/frontman"
)

func TestParseRuleSpecMatchSet(t *testing.T) {

	Convey("When I parse a rule with an ipset match", t, func() {
		rsOrig := "-m set --match-set TRI-ipset-1 srcIP -j ACCEPT"
		ruleSpec, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given ipset", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.MatchSet, ShouldNotBeNil)
			So(ruleSpec.MatchSet, ShouldHaveLength, 1)
			So(ruleSpec.MatchSet[0].MatchSetName, ShouldEqual, "TRI-ipset-1")
			So(ruleSpec.MatchSet[0].MatchSetNegate, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstIP, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstPort, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetSrcIP, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetSrcPort, ShouldBeFalse)
		})
		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I parse a rule with more than one ipset match", t, func() {
		rsOrig := "-m set --match-set TRI-ipset-1 srcIP -j ACCEPT -m set --match-set TRI-ipset-2 dstIP"
		ruleSpec, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given ipsets", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.MatchSet, ShouldNotBeNil)
			So(ruleSpec.MatchSet, ShouldHaveLength, 2)
			So(ruleSpec.MatchSet[0].MatchSetName, ShouldEqual, "TRI-ipset-1")
			So(ruleSpec.MatchSet[0].MatchSetNegate, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstIP, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstPort, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetSrcIP, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetSrcPort, ShouldBeFalse)
			So(ruleSpec.MatchSet[1].MatchSetName, ShouldEqual, "TRI-ipset-2")
			So(ruleSpec.MatchSet[1].MatchSetNegate, ShouldBeFalse)
			So(ruleSpec.MatchSet[1].MatchSetDstIP, ShouldBeTrue)
			So(ruleSpec.MatchSet[1].MatchSetDstPort, ShouldBeFalse)
			So(ruleSpec.MatchSet[1].MatchSetSrcIP, ShouldBeFalse)
			So(ruleSpec.MatchSet[1].MatchSetSrcPort, ShouldBeFalse)
		})
		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I parse a rule with an ipset match without ip or port specifier", t, func() {
		rsOrig := "-m set --match-set TRI-ipset-1 -j ACCEPT"
		_, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		Convey("I should get an error", func() {
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "Missing argument for option 'match-set'")
		})
	})

	Convey("When I parse a rule with an ipset match with invalid ip or port specifier", t, func() {
		rsOrig := "-m set --match-set TRI-ipset-1 both -j ACCEPT"
		_, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		Convey("I should get an error", func() {
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "ipset match needs ip/port specifier")
		})
	})

	Convey("When I parse a rule with an ipset match on port without protocol", t, func() {
		rsOrig := "-m set --match-set TRI-ipset-1 srcPort -j ACCEPT"
		_, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		Convey("I should get an error", func() {
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "ipset match on port requires protocol be set")
		})
	})

	Convey("When I parse a rule with an ipset match on src port", t, func() {
		rsOrig := "-p tcp -m set --match-set TRI-ipset-1 srcPort -j ACCEPT"
		ruleSpec, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given ipset's port", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.MatchSet, ShouldNotBeNil)
			So(ruleSpec.MatchSet, ShouldHaveLength, 1)
			So(ruleSpec.MatchSet[0].MatchSetName, ShouldEqual, "TRI-ipset-1")
			So(ruleSpec.MatchSet[0].MatchSetNegate, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstIP, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstPort, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetSrcIP, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetSrcPort, ShouldBeTrue)
		})
		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I parse a rule with an ipset match on dst port", t, func() {
		rsOrig := "-p tcp -m set --match-set TRI-ipset-1 dstPort -j ACCEPT"
		ruleSpec, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given ipset's port", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.MatchSet, ShouldNotBeNil)
			So(ruleSpec.MatchSet, ShouldHaveLength, 1)
			So(ruleSpec.MatchSet[0].MatchSetName, ShouldEqual, "TRI-ipset-1")
			So(ruleSpec.MatchSet[0].MatchSetNegate, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstIP, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstPort, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetSrcIP, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetSrcPort, ShouldBeFalse)
		})
		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I parse a rule with an ipset match on ip and port", t, func() {
		rsOrig := "-p tcp -m set --match-set TRI-ipset-1 dstIP,dstPort -j ACCEPT"
		ruleSpec, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given ipset's ip and port", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.MatchSet, ShouldNotBeNil)
			So(ruleSpec.MatchSet, ShouldHaveLength, 1)
			So(ruleSpec.MatchSet[0].MatchSetName, ShouldEqual, "TRI-ipset-1")
			So(ruleSpec.MatchSet[0].MatchSetNegate, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstIP, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetDstPort, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetSrcIP, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetSrcPort, ShouldBeFalse)
		})
		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I parse a rule with an ipset match on ip and port mixed", t, func() {
		rsOrig := "-p tcp -m set --match-set TRI-ipset-1 srcIP,dstPort -j ACCEPT"
		ruleSpec, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given ipset's ip and port", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.MatchSet, ShouldNotBeNil)
			So(ruleSpec.MatchSet, ShouldHaveLength, 1)
			So(ruleSpec.MatchSet[0].MatchSetName, ShouldEqual, "TRI-ipset-1")
			So(ruleSpec.MatchSet[0].MatchSetNegate, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstIP, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstPort, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetSrcIP, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetSrcPort, ShouldBeFalse)
		})
		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I parse a rule with an ipset match on ip and port with one specifier (src)", t, func() {
		rsOrig := "-p tcp -m set --match-set TRI-ipset-1 src -j ACCEPT"
		ruleSpec, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given ipset's ip and port", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.MatchSet, ShouldNotBeNil)
			So(ruleSpec.MatchSet, ShouldHaveLength, 1)
			So(ruleSpec.MatchSet[0].MatchSetName, ShouldEqual, "TRI-ipset-1")
			So(ruleSpec.MatchSet[0].MatchSetNegate, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstIP, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstPort, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetSrcIP, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetSrcPort, ShouldBeTrue)
		})
		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I parse a rule with an ipset match on ip and port with one specifier (dst)", t, func() {
		rsOrig := "-p tcp -m set --match-set TRI-ipset-1 dst -j ACCEPT"
		ruleSpec, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given ipset's ip and port", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.MatchSet, ShouldNotBeNil)
			So(ruleSpec.MatchSet, ShouldHaveLength, 1)
			So(ruleSpec.MatchSet[0].MatchSetName, ShouldEqual, "TRI-ipset-1")
			So(ruleSpec.MatchSet[0].MatchSetNegate, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstIP, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetDstPort, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetSrcIP, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetSrcPort, ShouldBeFalse)
		})
		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I parse a rule with an ipset match on ip and port with specifier order important", t, func() {
		rsOrig := "-p tcp -m set --match-set TRI-ipset-1 src,dst -j ACCEPT"
		ruleSpec, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given ipset's ip and port", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.MatchSet, ShouldNotBeNil)
			So(ruleSpec.MatchSet, ShouldHaveLength, 1)
			So(ruleSpec.MatchSet[0].MatchSetName, ShouldEqual, "TRI-ipset-1")
			So(ruleSpec.MatchSet[0].MatchSetNegate, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstIP, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstPort, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetSrcIP, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetSrcPort, ShouldBeFalse)
		})
		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I parse a rule with no ipset match", t, func() {
		rsOrig := "-j ACCEPT"
		ruleSpec, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.MatchSet, ShouldBeNil)
		})
		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I parse a rule with a negative ipset match", t, func() {
		rsOrig := "-p tcp -m set ! --match-set TRI-ipset-1 dstPort -j ACCEPT"
		ruleSpec, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept except for the given ipset", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.MatchSet, ShouldNotBeNil)
			So(ruleSpec.MatchSet, ShouldHaveLength, 1)
			So(ruleSpec.MatchSet[0].MatchSetName, ShouldEqual, "TRI-ipset-1")
			So(ruleSpec.MatchSet[0].MatchSetNegate, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetDstIP, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstPort, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetSrcIP, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetSrcPort, ShouldBeFalse)
		})
		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

}

func TestParseRuleSpecProtocol(t *testing.T) {

	Convey("When I parse a rule with a protocol match on tcp", t, func() {
		rsOrig := "-p tcp -m set --match-set TRI-ipset-1 srcPort -j ACCEPT"
		ruleSpec, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given ipset/protocol", func() {
			So(ruleSpec.Protocol, ShouldEqual, packet.IPProtocolTCP)
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.MatchSet, ShouldNotBeNil)
			So(ruleSpec.MatchSet, ShouldHaveLength, 1)
		})
		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I parse a rule with a protocol match on udp", t, func() {
		rsOrig := "-p udp -m set --match-set TRI-ipset-1 srcPort -j ACCEPT"
		ruleSpec, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given ipset/protocol", func() {
			So(ruleSpec.Protocol, ShouldEqual, packet.IPProtocolUDP)
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.MatchSet, ShouldNotBeNil)
			So(ruleSpec.MatchSet, ShouldHaveLength, 1)
		})
		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I parse a rule with a protocol match on icmp", t, func() {
		rsOrig := "-p icmp -j DROP"
		ruleSpec, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		So(err, ShouldBeNil)
		Convey("I should reject for the given protocol", func() {
			So(ruleSpec.Protocol, ShouldEqual, 1)
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionBlock)
		})
		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I parse a rule with a protocol match on tcp by number", t, func() {
		rsOrig := "-p 6 -j ACCEPT"
		ruleSpec, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given protocol", func() {
			So(ruleSpec.Protocol, ShouldEqual, packet.IPProtocolTCP)
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
		})
		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I parse a rule with a protocol match on udp by number", t, func() {
		rsOrig := "-p 17 -j ACCEPT"
		ruleSpec, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given protocol", func() {
			So(ruleSpec.Protocol, ShouldEqual, packet.IPProtocolUDP)
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
		})
		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I parse a rule with a protocol match on ICMP for IPv6 by number", t, func() {
		rsOrig := "-p 58 -j ACCEPT"
		ruleSpec, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given protocol", func() {
			So(ruleSpec.Protocol, ShouldEqual, 58)
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
		})
		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I parse a rule with an invalid protocol match", t, func() {
		rsOrig := "-p http -m set --match-set TRI-ipset-1 srcPort -j ACCEPT"
		_, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		Convey("I should get an error", func() {
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "invalid protocol")
		})
	})

}

func TestParseRuleSpecAction(t *testing.T) {

	Convey("When I parse a rule with an accept action", t, func() {
		rsOrig := "-p tcp -m set --match-set TRI-ipset-1 dstPort -j ACCEPT"
		ruleSpec, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
		})
		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I parse a rule with a drop action", t, func() {
		rsOrig := "-p tcp -m set --match-set TRI-ipset-1 dstPort -j DROP"
		ruleSpec, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		So(err, ShouldBeNil)
		Convey("I should block", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionBlock)
		})
		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I parse a rule with an nfq action and a given mark", t, func() {
		rsOrig := "-p tcp -m set --match-set TRI-ipset-1 srcIP,srcPort -j NFQUEUE -j MARK 100"
		ruleSpec, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		So(err, ShouldBeNil)
		Convey("I should route to nfq and set the mark", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionNfq)
			So(ruleSpec.Mark, ShouldEqual, 100)
		})
		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I parse a rule with an nfq action without a mark", t, func() {
		rsOrig := "-p tcp -m set --match-set TRI-ipset-1 srcIP -j NFQUEUE"
		_, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		Convey("I should get an error", func() {
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "nfq action needs to set mark")
		})
	})

	Convey("When I parse a rule with a force nfq action", t, func() {
		rsOrig := "-p tcp -m set --match-set TRI-ipset-1 srcIP,srcPort -j NFQUEUE_FORCE -j MARK 100"
		ruleSpec, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		So(err, ShouldBeNil)
		Convey("I should route to nfq (without honoring ignore-flow) and set the mark", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionForceNfq)
			So(ruleSpec.Mark, ShouldEqual, 100)
		})
		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I parse a rule with a proxy action", t, func() {
		rsOrig := "-p tcp -m set --match-set TRI-ipset-1 dstPort -j REDIRECT --to-ports 20992"
		ruleSpec, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		So(err, ShouldBeNil)
		Convey("I should redirect to given port", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionProxy)
			So(ruleSpec.ProxyPort, ShouldEqual, 20992)
		})
		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I parse a rule with a proxy action without a redirect port", t, func() {
		rsOrig := "-p tcp -m set --match-set TRI-ipset-1 srcIP -j REDIRECT"
		_, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		Convey("I should get an error", func() {
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "no redirect port given")
		})
	})

	Convey("When I parse a rule with a log and drop action", t, func() {
		rsOrig := "-p tcp -j DROP -j NFLOG --nflog-group 10 --nflog-prefix 531138568:5d6044b9e99572000149d650:5d60448a884e46000145cf67:6"
		ruleSpec, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		So(err, ShouldBeNil)
		Convey("I should drop and log", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionBlock)
			So(ruleSpec.Log, ShouldBeTrue)
		})
		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I parse a rule with a log and accept action", t, func() {
		rsOrig := "-p tcp -j ACCEPT -j NFLOG --nflog-group 10 --nflog-prefix 531138568:5d6044b9e99572000149d650:5d60448a884e46000145cf67:6"
		ruleSpec, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept and log", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.Log, ShouldBeTrue)
		})
		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

}

func TestParseRuleSpecSPortDPort(t *testing.T) {

	Convey("When I parse a rule with a match on source port", t, func() {
		rsOrig := "-p tcp --sport 12345 -j ACCEPT"
		ruleSpec, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given source port", func() {
			So(ruleSpec.MatchDstPort, ShouldHaveLength, 0)
			So(ruleSpec.MatchSrcPort, ShouldHaveLength, 1)
			So(ruleSpec.MatchSrcPort[0].Start, ShouldEqual, 12345)
			So(ruleSpec.MatchSrcPort[0].End, ShouldEqual, 12345)
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
		})
		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I parse a rule with a match on source port range", t, func() {
		rsOrig := "-p tcp --sport 80,1024:65535 -j ACCEPT"
		ruleSpec, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given source port range", func() {
			So(ruleSpec.MatchSrcPort, ShouldHaveLength, 2)
			So(ruleSpec.MatchSrcPort[0].Start, ShouldEqual, 80)
			So(ruleSpec.MatchSrcPort[0].End, ShouldEqual, 80)
			So(ruleSpec.MatchSrcPort[1].Start, ShouldEqual, 1024)
			So(ruleSpec.MatchSrcPort[1].End, ShouldEqual, 65535)
			So(ruleSpec.MatchDstPort, ShouldHaveLength, 0)
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
		})
		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I parse a rule with a match on dest port", t, func() {
		rsOrig := "-p tcp --dport 80 -j ACCEPT"
		ruleSpec, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given dest port", func() {
			So(ruleSpec.MatchSrcPort, ShouldHaveLength, 0)
			So(ruleSpec.MatchDstPort, ShouldHaveLength, 1)
			So(ruleSpec.MatchDstPort[0].Start, ShouldEqual, 80)
			So(ruleSpec.MatchDstPort[0].End, ShouldEqual, 80)
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
		})
		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I parse a rule with a match on dest port range", t, func() {
		rsOrig := "-p tcp --dport 1234,8080:8443,65000:65005,65530 -j ACCEPT"
		ruleSpec, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		So(err, ShouldBeNil)
		Convey("I should accept for the given dest port range", func() {
			So(ruleSpec.MatchDstPort, ShouldHaveLength, 4)
			So(ruleSpec.MatchDstPort[0].Start, ShouldEqual, 1234)
			So(ruleSpec.MatchDstPort[0].End, ShouldEqual, 1234)
			So(ruleSpec.MatchDstPort[1].Start, ShouldEqual, 8080)
			So(ruleSpec.MatchDstPort[1].End, ShouldEqual, 8443)
			So(ruleSpec.MatchDstPort[2].Start, ShouldEqual, 65000)
			So(ruleSpec.MatchDstPort[2].End, ShouldEqual, 65005)
			So(ruleSpec.MatchDstPort[3].Start, ShouldEqual, 65530)
			So(ruleSpec.MatchDstPort[3].End, ShouldEqual, 65530)
			So(ruleSpec.MatchSrcPort, ShouldHaveLength, 0)
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
		})
		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

}

func TestParseRuleSpecMatchString(t *testing.T) {

	Convey("When I parse a rule with a string match", t, func() {
		rsOrig := "-p udp -m set --match-set TRI-ipset-udp-1 srcIP -m string --string n30njxq7bmiwr6dtxq --offset 2 -j NFQUEUE -j MARK 1234 -m set --match-set TRI-ipset-udp-2 srcIP"
		ruleSpec, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
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
			So(ruleSpec.MatchSet[0].MatchSetDstIP, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstPort, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetSrcIP, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetSrcPort, ShouldBeFalse)
			So(ruleSpec.MatchSet[1].MatchSetName, ShouldEqual, "TRI-ipset-udp-2")
			So(ruleSpec.MatchSet[1].MatchSetNegate, ShouldBeFalse)
			So(ruleSpec.MatchSet[1].MatchSetDstIP, ShouldBeFalse)
			So(ruleSpec.MatchSet[1].MatchSetDstPort, ShouldBeFalse)
			So(ruleSpec.MatchSet[1].MatchSetSrcIP, ShouldBeTrue)
			So(ruleSpec.MatchSet[1].MatchSetSrcPort, ShouldBeFalse)
		})
		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

}

func TestParseRuleSpecNoMatchString(t *testing.T) {

	Convey("When I parse a rule with a string ! match", t, func() {
		rsOrig := "-p udp -m set --match-set TRI-ipset-udp-1 srcIP -m string --string ! n30njxq7bmiwr6dtxq --offset 2 -j NFQUEUE -j MARK 1234 -m set --match-set TRI-ipset-udp-2 srcIP"
		ruleSpec, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		So(err, ShouldBeNil)
		Convey("I should forward to nfq if I see the given string at the given offset", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionNfq)
			So(ruleSpec.Mark, ShouldEqual, 1234)
			So(ruleSpec.Protocol, ShouldEqual, packet.IPProtocolUDP)
			So(ruleSpec.MatchBytesNoMatch, ShouldEqual, true)
			So(ruleSpec.MatchBytesOffset, ShouldEqual, 2)
			So(ruleSpec.MatchBytes, ShouldResemble, []byte("n30njxq7bmiwr6dtxq"))
			So(ruleSpec.MatchSet, ShouldNotBeNil)
			So(ruleSpec.MatchSet, ShouldHaveLength, 2)
			So(ruleSpec.MatchSet[0].MatchSetName, ShouldEqual, "TRI-ipset-udp-1")
			So(ruleSpec.MatchSet[0].MatchSetNegate, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstIP, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstPort, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetSrcIP, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetSrcPort, ShouldBeFalse)
			So(ruleSpec.MatchSet[1].MatchSetName, ShouldEqual, "TRI-ipset-udp-2")
			So(ruleSpec.MatchSet[1].MatchSetNegate, ShouldBeFalse)
			So(ruleSpec.MatchSet[1].MatchSetDstIP, ShouldBeFalse)
			So(ruleSpec.MatchSet[1].MatchSetDstPort, ShouldBeFalse)
			So(ruleSpec.MatchSet[1].MatchSetSrcIP, ShouldBeTrue)
			So(ruleSpec.MatchSet[1].MatchSetSrcPort, ShouldBeFalse)
		})
		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

}

func TestParseRuleSpecMatchPid(t *testing.T) {

	Convey("When I parse a rule with a process ID match", t, func() {
		ruleSpec, err := ParseRuleSpec(strings.Split("-p tcp -m set --match-set TRI-ipset-tcp-1 dstIP -j NFQUEUE -j MARK 103 -m owner --pid-owner 2438", " ")...)
		So(err, ShouldBeNil)
		Convey("I should forward to nfq for all packets from or to the given process", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionNfq)
			So(ruleSpec.Mark, ShouldEqual, 103)
			So(ruleSpec.Protocol, ShouldEqual, packet.IPProtocolTCP)
			So(ruleSpec.ProcessID, ShouldEqual, 2438)
			So(ruleSpec.ProcessIncludeChildren, ShouldBeFalse)
			So(ruleSpec.ProcessIncludeChildrenOnly, ShouldBeFalse)
			So(ruleSpec.MatchSet, ShouldNotBeNil)
			So(ruleSpec.MatchSet, ShouldHaveLength, 1)
			So(ruleSpec.MatchSet[0].MatchSetName, ShouldEqual, "TRI-ipset-tcp-1")
			So(ruleSpec.MatchSet[0].MatchSetNegate, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstIP, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetDstPort, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetSrcIP, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetSrcPort, ShouldBeFalse)
		})

		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I parse a rule with a process ID match with include children", t, func() {
		ruleSpec, err := ParseRuleSpec(strings.Split("-p tcp -m set --match-set TRI-ipset-tcp-1 dstIP -j NFQUEUE -j MARK 104 -m owner --pid-owner 2439 --pid-children", " ")...)
		So(err, ShouldBeNil)
		Convey("I should forward to nfq for all packets from or to the given process and its children", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionNfq)
			So(ruleSpec.Mark, ShouldEqual, 104)
			So(ruleSpec.Protocol, ShouldEqual, packet.IPProtocolTCP)
			So(ruleSpec.ProcessID, ShouldEqual, 2439)
			So(ruleSpec.ProcessIncludeChildren, ShouldBeTrue)
			So(ruleSpec.ProcessIncludeChildrenOnly, ShouldBeFalse)
			So(ruleSpec.MatchSet, ShouldNotBeNil)
			So(ruleSpec.MatchSet, ShouldHaveLength, 1)
			So(ruleSpec.MatchSet[0].MatchSetName, ShouldEqual, "TRI-ipset-tcp-1")
			So(ruleSpec.MatchSet[0].MatchSetNegate, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstIP, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetDstPort, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetSrcIP, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetSrcPort, ShouldBeFalse)
		})

		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I parse a rule with a process ID match with include children only", t, func() {
		ruleSpec, err := ParseRuleSpec(strings.Split("-p tcp -m set --match-set TRI-ipset-tcp-1 dstIP -j NFQUEUE -j MARK 105 -m owner --pid-owner 2440 --pid-childrenonly", " ")...)
		So(err, ShouldBeNil)
		Convey("I should forward to nfq for all packets from or to the given process' children", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionNfq)
			So(ruleSpec.Mark, ShouldEqual, 105)
			So(ruleSpec.Protocol, ShouldEqual, packet.IPProtocolTCP)
			So(ruleSpec.ProcessID, ShouldEqual, 2440)
			So(ruleSpec.ProcessIncludeChildren, ShouldBeFalse)
			So(ruleSpec.ProcessIncludeChildrenOnly, ShouldBeTrue)
			So(ruleSpec.MatchSet, ShouldNotBeNil)
			So(ruleSpec.MatchSet, ShouldHaveLength, 1)
			So(ruleSpec.MatchSet[0].MatchSetName, ShouldEqual, "TRI-ipset-tcp-1")
			So(ruleSpec.MatchSet[0].MatchSetNegate, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstIP, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetDstPort, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetSrcIP, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetSrcPort, ShouldBeFalse)
		})

		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I parse a rule with an invalid process ID match", t, func() {
		// invalid flags
		_, err := ParseRuleSpec(strings.Split("-p tcp -m set --match-set TRI-ipset-tcp-1 dstIP -j NFQUEUE -j MARK 105 -m owner --pid-owner 2440 --pid-childrenonly --pid-children", " ")...)
		So(err, ShouldNotBeNil)
		// invalid pid
		_, err = ParseRuleSpec(strings.Split("-p tcp -m set --match-set TRI-ipset-tcp-1 dstIP -j NFQUEUE -j MARK 105 -m owner --pid-owner foobar", " ")...)
		So(err, ShouldNotBeNil)
	})
}

func TestParseRuleSpecMatchIcmp(t *testing.T) {

	Convey("When I parse a rule with an icmp type match", t, func() {
		ruleSpec, err := ParseRuleSpec(strings.Split("-p 1 --icmp-type 8 -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should recognize the icmp type", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.Protocol, ShouldEqual, 1)
			So(ruleSpec.IcmpMatch, ShouldHaveLength, 1)
			So(ruleSpec.IcmpMatch[0].Nomatch, ShouldBeFalse)
			So(ruleSpec.IcmpMatch[0].IcmpType, ShouldEqual, 8)
			So(ruleSpec.IcmpMatch[0].IcmpCodeRange, ShouldBeNil)
		})

		rulePart := strings.Join(TransformIcmpProtoString("icmp/8"), " ")
		So(rulePart, ShouldEqual, "--icmp-type 8")

		_, err = MakeRuleSpecText(ruleSpec, true)
		So(err, ShouldBeNil)
	})

	Convey("When I parse a rule with an icmp type and code match", t, func() {
		ruleSpec, err := ParseRuleSpec(strings.Split("-p icmp --icmp-type 3/5 -j DROP", " ")...)
		So(err, ShouldBeNil)
		Convey("I should recognize the icmp type and code", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionBlock)
			So(ruleSpec.Protocol, ShouldEqual, 1)
			So(ruleSpec.IcmpMatch, ShouldHaveLength, 1)
			So(ruleSpec.IcmpMatch[0].Nomatch, ShouldBeFalse)
			So(ruleSpec.IcmpMatch[0].IcmpType, ShouldEqual, 3)
			So(ruleSpec.IcmpMatch[0].IcmpCodeRange.Start, ShouldEqual, 5)
			So(ruleSpec.IcmpMatch[0].IcmpCodeRange.End, ShouldEqual, 5)
		})

		rulePart := strings.Join(TransformIcmpProtoString("icmp/3/5"), " ")
		So(rulePart, ShouldEqual, "--icmp-type 3/5")

		_, err = MakeRuleSpecText(ruleSpec, true)
		So(err, ShouldBeNil)
	})

	Convey("When I parse a rule with an icmp type and multiple codes match", t, func() {
		ruleSpec, err := ParseRuleSpec(strings.Split("-p 1 --icmp-type 3/0:4,15,6:7,14 -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should recognize the icmp type and code ranges", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.Protocol, ShouldEqual, 1)
			So(ruleSpec.IcmpMatch, ShouldHaveLength, 4)
			So(ruleSpec.IcmpMatch[0].Nomatch, ShouldBeFalse)
			So(ruleSpec.IcmpMatch[0].IcmpType, ShouldEqual, 3)
			So(ruleSpec.IcmpMatch[0].IcmpCodeRange.Start, ShouldEqual, 0)
			So(ruleSpec.IcmpMatch[0].IcmpCodeRange.End, ShouldEqual, 4)
			So(ruleSpec.IcmpMatch[1].IcmpType, ShouldEqual, 3)
			So(ruleSpec.IcmpMatch[1].IcmpCodeRange.Start, ShouldEqual, 15)
			So(ruleSpec.IcmpMatch[1].IcmpCodeRange.End, ShouldEqual, 15)
			So(ruleSpec.IcmpMatch[2].IcmpType, ShouldEqual, 3)
			So(ruleSpec.IcmpMatch[2].IcmpCodeRange.Start, ShouldEqual, 6)
			So(ruleSpec.IcmpMatch[2].IcmpCodeRange.End, ShouldEqual, 7)
			So(ruleSpec.IcmpMatch[3].IcmpType, ShouldEqual, 3)
			So(ruleSpec.IcmpMatch[3].IcmpCodeRange.Start, ShouldEqual, 14)
			So(ruleSpec.IcmpMatch[3].IcmpCodeRange.End, ShouldEqual, 14)
		})

		rulePart := strings.Join(TransformIcmpProtoString("icmp/3/0:4,15,6:7,14"), " ")
		So(rulePart, ShouldEqual, "--icmp-type 3/0:4,15,6:7,14")

		_, err = MakeRuleSpecText(ruleSpec, true)
		So(err, ShouldBeNil)
	})

	Convey("When I parse a rule with an icmp v6 type and code match", t, func() {
		ruleSpec, err := ParseRuleSpec(strings.Split("-p 58 --icmp-type 140/1,2 -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should recognize the icmp v6 type and code", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.Protocol, ShouldEqual, 58)
			So(ruleSpec.IcmpMatch, ShouldHaveLength, 2)
			So(ruleSpec.IcmpMatch[0].Nomatch, ShouldBeFalse)
			So(ruleSpec.IcmpMatch[0].IcmpType, ShouldEqual, 140)
			So(ruleSpec.IcmpMatch[0].IcmpCodeRange.Start, ShouldEqual, 1)
			So(ruleSpec.IcmpMatch[0].IcmpCodeRange.End, ShouldEqual, 1)
			So(ruleSpec.IcmpMatch[1].IcmpCodeRange.Start, ShouldEqual, 2)
			So(ruleSpec.IcmpMatch[1].IcmpCodeRange.End, ShouldEqual, 2)
		})

		rulePart := strings.Join(TransformIcmpProtoString("icmpv6/140/1,2"), " ")
		So(rulePart, ShouldEqual, "--icmp-type 140/1,2")

		_, err = MakeRuleSpecText(ruleSpec, true)
		So(err, ShouldBeNil)
	})

	Convey("When I parse a rule with an icmp nomatch", t, func() {
		ruleSpec, err := ParseRuleSpec(strings.Split("-p icmp --icmp-type nomatch -j ACCEPT", " ")...)
		So(err, ShouldBeNil)
		Convey("I should recognize that it should never match", func() {
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllow)
			So(ruleSpec.Protocol, ShouldEqual, 1)
			So(ruleSpec.IcmpMatch, ShouldHaveLength, 1)
			So(ruleSpec.IcmpMatch[0].Nomatch, ShouldBeTrue)
		})

		_, err = MakeRuleSpecText(ruleSpec, true)
		So(err, ShouldBeNil)
	})

	Convey("When I parse a rule with an invalid icmp type/code", t, func() {
		// invalid range separator
		_, err := ParseRuleSpec(strings.Split("-p 1 --icmp-type 3/0:4,15,6-7,14 -j ACCEPT", " ")...)
		So(err, ShouldNotBeNil)
		// code out of range
		_, err = ParseRuleSpec(strings.Split("-p 1 --icmp-type 3/0:4,15,17:256 -j ACCEPT", " ")...)
		So(err, ShouldNotBeNil)
		// code given but no type
		_, err = ParseRuleSpec(strings.Split("-p 1 --icmp-type /2 -j ACCEPT", " ")...)
		So(err, ShouldNotBeNil)
		// type out of range
		_, err = ParseRuleSpec(strings.Split("-p 1 --icmp-type 2555/1,4 -j ACCEPT", " ")...)
		So(err, ShouldNotBeNil)
	})

	Convey("When I handle a rule with policy restrictions", t, func() {

		rulePart, err := ReduceIcmpProtoString("icmp", []string{"icmp/1/1", "icmp/2/3:4"})
		So(err, ShouldBeNil)
		So(rulePart, ShouldHaveLength, 4)
		So(rulePart[0], ShouldEqual, "--icmp-type")
		So(rulePart[1], ShouldEqual, "1/1")
		So(rulePart[3], ShouldEqual, "2/3:4")

		rulePart, err = ReduceIcmpProtoString("icmp/3", []string{"icmp/2", "icmp", "icmp/3/0"})
		So(err, ShouldBeNil)
		So(rulePart, ShouldHaveLength, 4)
		So(rulePart[1], ShouldEqual, "3")
		So(rulePart[3], ShouldEqual, "3/0")

		rulePart, err = ReduceIcmpProtoString("icmp/3/0:2,3:3,5:7,10:18", []string{"icmp/3/2:4,6:8,11", "icmp/3/1,2,4,6:7,9,14,16,18", "icmp/3/0,10,20:22"})
		So(err, ShouldBeNil)
		So(rulePart, ShouldHaveLength, 6)
		So(rulePart[1], ShouldEqual, "3/2:2,3:3,6:7,11:11")
		So(rulePart[3], ShouldEqual, "3/1:1,2:2,6:7,14:14,16:16,18:18")
		So(rulePart[5], ShouldEqual, "3/0:0,10:10")

		rulePart, err = ReduceIcmpProtoString("icmp/8/10,1:3,7", []string{"icmp/2/10", "icmp/8", "icmp/8/0,4:6,11:20,9,8"})
		So(err, ShouldBeNil)
		So(rulePart, ShouldHaveLength, 2)
		So(rulePart[1], ShouldEqual, "8/10,1:3,7")

		rulePart, err = ReduceIcmpProtoString("icmp", []string{"icmp/1/1"})
		So(err, ShouldBeNil)
		So(rulePart, ShouldHaveLength, 2)
		So(rulePart[1], ShouldEqual, "1/1")

		rulePart, err = ReduceIcmpProtoString("icmp6", []string{"icmp6/1/0:255"})
		So(err, ShouldBeNil)
		So(rulePart, ShouldHaveLength, 2)
		So(rulePart[1], ShouldEqual, "1/0:255")

		rulePart, err = ReduceIcmpProtoString("icmp/1", []string{"icmp", "icmp6"})
		So(err, ShouldBeNil)
		So(rulePart, ShouldHaveLength, 2)
		So(rulePart[1], ShouldEqual, "1")

		// proto match without type/code should return empty
		rulePart, err = ReduceIcmpProtoString("icmp", []string{"icmp"})
		So(err, ShouldBeNil)
		So(rulePart, ShouldHaveLength, 0)

		// proto match with type/code conflict should return error
		_, err = ReduceIcmpProtoString("icmp/0", []string{"icmp/1"})
		So(err, ShouldNotBeNil)
	})
}

// test generated acl rule
func TestParseRuleSpecACLRule(t *testing.T) {

	Convey("When I parse an acl rule for nflog", t, func() {
		rsOrig := "-p 6 -m set --match-set TRI-v4-ext-cUDEx1114Z2xd dst -m state --state NEW -m set ! --match-set TRI-v4-TargetTCP dst --match multiport --dports 1:65535 -m state --state NEW -j NFLOG --nflog-group 10 --nflog-prefix \"3617624947:5d6044b9e99572000149d650:5d60448a884e46000145cf67:incoming n_3484738895:6\""

		rule, err := shellquote.Split(rsOrig)
		So(err, ShouldBeNil)

		ruleSpec, err := ParseRuleSpec(rule...)
		So(err, ShouldBeNil)
		Convey("I should be able to interpret it as a windows rule", func() {
			So(ruleSpec.Protocol, ShouldEqual, packet.IPProtocolTCP)
			So(ruleSpec.MatchSrcPort, ShouldHaveLength, 0)
			So(ruleSpec.MatchDstPort, ShouldHaveLength, 1)
			So(ruleSpec.MatchDstPort[0].Start, ShouldEqual, 1)
			So(ruleSpec.MatchDstPort[0].End, ShouldEqual, 65535)
			So(ruleSpec.Action, ShouldEqual, 0) // degenerate log-only rule
			So(ruleSpec.Log, ShouldBeTrue)
			So(ruleSpec.LogPrefix, ShouldEqual, "3617624947:5d6044b9e99572000149d650:5d60448a884e46000145cf67:incoming n_3484738895:6")
			So(ruleSpec.MatchSet, ShouldNotBeNil)
			So(ruleSpec.MatchSet, ShouldHaveLength, 2)
			So(ruleSpec.MatchSet[0].MatchSetName, ShouldEqual, "TRI-v4-ext-cUDEx1114Z2xd")
			So(ruleSpec.MatchSet[0].MatchSetNegate, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstIP, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetDstPort, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetSrcIP, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetSrcPort, ShouldBeFalse)
			So(ruleSpec.MatchSet[1].MatchSetName, ShouldEqual, "TRI-v4-TargetTCP")
			So(ruleSpec.MatchSet[1].MatchSetNegate, ShouldBeTrue)
			So(ruleSpec.MatchSet[1].MatchSetDstIP, ShouldBeTrue)
			So(ruleSpec.MatchSet[1].MatchSetDstPort, ShouldBeTrue)
			So(ruleSpec.MatchSet[1].MatchSetSrcIP, ShouldBeFalse)
			So(ruleSpec.MatchSet[1].MatchSetSrcPort, ShouldBeFalse)
		})
		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I parse an acl rule for drop or accept", t, func() {
		rsOrig := "-p 6 -m set --match-set TRI-v4-ext-cUDEx1114Z2xd dst -m state --state NEW -m set ! --match-set TRI-v4-TargetTCP dst --match multiport --dports 1:65535 -j DROP"
		ruleSpec, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		So(err, ShouldBeNil)
		Convey("I should be able to interpret it as a windows rule", func() {
			So(ruleSpec.Protocol, ShouldEqual, packet.IPProtocolTCP)
			So(ruleSpec.MatchSrcPort, ShouldHaveLength, 0)
			So(ruleSpec.MatchDstPort, ShouldHaveLength, 1)
			So(ruleSpec.MatchDstPort[0].Start, ShouldEqual, 1)
			So(ruleSpec.MatchDstPort[0].End, ShouldEqual, 65535)
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionBlock)
			So(ruleSpec.Log, ShouldBeFalse)
			So(ruleSpec.MatchSet, ShouldNotBeNil)
			So(ruleSpec.MatchSet, ShouldHaveLength, 2)
			So(ruleSpec.MatchSet[0].MatchSetName, ShouldEqual, "TRI-v4-ext-cUDEx1114Z2xd")
			So(ruleSpec.MatchSet[0].MatchSetNegate, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetDstIP, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetDstPort, ShouldBeTrue)
			So(ruleSpec.MatchSet[0].MatchSetSrcIP, ShouldBeFalse)
			So(ruleSpec.MatchSet[0].MatchSetSrcPort, ShouldBeFalse)
			So(ruleSpec.MatchSet[1].MatchSetName, ShouldEqual, "TRI-v4-TargetTCP")
			So(ruleSpec.MatchSet[1].MatchSetNegate, ShouldBeTrue)
			So(ruleSpec.MatchSet[1].MatchSetDstIP, ShouldBeTrue)
			So(ruleSpec.MatchSet[1].MatchSetDstPort, ShouldBeTrue)
			So(ruleSpec.MatchSet[1].MatchSetSrcIP, ShouldBeFalse)
			So(ruleSpec.MatchSet[1].MatchSetSrcPort, ShouldBeFalse)
		})
		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

}

// test TCP flags and options
func TestParseRuleSpecTCPFlagsAndOptions(t *testing.T) {

	Convey("When I parse tcp flags", t, func() {
		rsOrig := "--tcp-flags 18,10 -j ACCEPT_ONCE"
		ruleSpec, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		So(err, ShouldBeNil)
		Convey("I should be able to interpret it as a windows rule", func() {
			So(ruleSpec.TCPFlags, ShouldEqual, 10)
			So(ruleSpec.TCPFlagsMask, ShouldEqual, 18)
			So(ruleSpec.TCPFlagsSpecified, ShouldEqual, true)
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllowOnce)
		})
		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I parse tcp options", t, func() {
		rsOrig := "--tcp-option 34 -j ACCEPT_ONCE"
		ruleSpec, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		So(err, ShouldBeNil)
		Convey("I should be able to interpret it as a windows rule", func() {
			So(ruleSpec.TCPOption, ShouldEqual, 34)
			So(ruleSpec.TCPOptionSpecified, ShouldEqual, true)
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllowOnce)
		})
		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})
}

func TestParseRuleSpecConnmark(t *testing.T) {

	Convey("When I parse connmark", t, func() {
		rsOrig := "-m set --match-set TRI-ipset-1 srcIP -m connmark --mark 18 -j ACCEPT_ONCE"
		ruleSpec, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		So(err, ShouldBeNil)
		Convey("I should be able to interpret it as a windows rule", func() {
			So(ruleSpec.FlowMark, ShouldEqual, 18)
			So(ruleSpec.FlowMarkNoMatch, ShouldEqual, false)
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllowOnce)
		})
		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I parse ! connmark", t, func() {
		rsOrig := "-m connmark --mark ! 18 -j ACCEPT_ONCE"
		ruleSpec, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		So(err, ShouldBeNil)
		Convey("I should be able to interpret it as a windows rule", func() {
			So(ruleSpec.FlowMark, ShouldEqual, 18)
			So(ruleSpec.FlowMarkNoMatch, ShouldEqual, true)
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionAllowOnce)
		})
		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I parse connmark with invalid !", t, func() {
		rsOrig := "-m connmark --mark x 18 -j ACCEPT_ONCE"
		_, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		So(err, ShouldNotBeNil)
	})

	Convey("When I parse connmark with invalid mark", t, func() {
		rsOrig := "-m connmark --mark abc -j ACCEPT_ONCE"
		_, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		So(err, ShouldNotBeNil)
	})
}

func TestParseRuleSpecSetMark(t *testing.T) {

	Convey("When I parse setmark", t, func() {
		rsOrig := "-m connmark --mark 18 -j CONNMARK --set-mark 15"
		ruleSpec, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		So(err, ShouldBeNil)
		Convey("I should be able to interpret it as a windows rule", func() {
			So(ruleSpec.FlowMark, ShouldEqual, 18)
			So(ruleSpec.FlowMarkNoMatch, ShouldEqual, false)
			So(ruleSpec.Action, ShouldEqual, frontman.FilterActionSetMark)
			So(ruleSpec.Mark, ShouldEqual, 15)
		})
		Convey("I should be able to convert back to a string", func() {
			_, err := MakeRuleSpecText(ruleSpec, true)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I parse setmark without a mark", t, func() {
		rsOrig := "-m connmark --mark 18 -j CONNMARK"
		_, err := ParseRuleSpec(strings.Split(rsOrig, " ")...)
		So(err, ShouldNotBeNil)
	})
}
