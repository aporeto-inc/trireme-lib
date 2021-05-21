// +build !windows,!rhel6

package iptablesctrl

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/aporeto-inc/go-ipset/ipset"
	"github.com/magiconair/properties/assert"
	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/enforcerd/trireme-lib/common"
	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	tacls "go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/acls"
	provider "go.aporeto.io/enforcerd/trireme-lib/controller/pkg/aclprovider"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/ipsetmanager"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/enforcerd/trireme-lib/controller/runtime"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.aporeto.io/enforcerd/trireme-lib/utils/portspec"
)

func testICMPAllow() string {
	return "16,48 0 0 0,84 0 0 240,21 0 12 96,48 0 0 6,21 0 10 58,48 0 0 40,21 5 0 133,21 4 0 134,21 3 0 135,21 2 0 136,21 1 0 141,21 0 3 142,48 0 0 41,21 0 1 0,6 0 0 65535,6 0 0 0"
}

func TestNewInstanceV6(t *testing.T) {

	Convey("When I create a new iptables instance", t, func() {
		Convey("If I create a remote implemenetation and iptables exists", func() {
			ips := ipsetmanager.NewTestIpsetProvider()
			iptv4 := provider.NewTestIptablesProvider()
			iptv6 := provider.NewTestIptablesProvider()

			i, err := createTestInstance(ips, iptv4, iptv6, constants.RemoteContainer, policy.None)
			Convey("It should succeed", func() {
				So(i, ShouldNotBeNil)
				So(err, ShouldBeNil)
			})
		})
	})

	Convey("When I create a new iptables instance", t, func() {
		Convey("If I create a Linux server implemenetation and iptables exists", func() {
			ips := ipsetmanager.NewTestIpsetProvider()
			iptv4 := provider.NewTestIptablesProvider()
			iptv6 := provider.NewTestIptablesProvider()

			i, err := createTestInstance(ips, iptv4, iptv6, constants.LocalServer, policy.None)
			Convey("It should succeed", func() {
				So(i, ShouldNotBeNil)
				So(err, ShouldBeNil)
			})
		})
	})
}

func Test_NegativeConfigureRulesV6(t *testing.T) {

	Convey("Given a valid instance", t, func() {
		ips := ipsetmanager.NewTestIpsetProvider()
		iptv4 := provider.NewTestIptablesProvider()
		iptv6 := provider.NewTestIptablesProvider()

		i, err := createTestInstance(ips, iptv4, iptv6, constants.LocalServer, policy.None)
		So(err, ShouldBeNil)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		err = i.Run(ctx)
		So(err, ShouldBeNil)
		cfg := &runtime.Configuration{}
		i.SetTargetNetworks(cfg) // nolint

		ipl := policy.ExtendedMap{}
		policyrules := policy.NewPUPolicy(
			"Context",
			"/ns1",
			policy.Police,
			nil,
			nil,
			nil,
			nil,
			nil,
			nil,
			nil,
			nil,
			ipl,
			0,
			0,
			nil,
			nil,
			[]string{},
			policy.EnforcerMapping,
			policy.Reject|policy.Log,
			policy.Reject|policy.Log,
		)
		containerinfo := policy.NewPUInfo("Context",
			"/ns1", common.ContainerPU)
		containerinfo.Policy = policyrules
		containerinfo.Runtime = policy.NewPURuntimeWithDefaults()
		containerinfo.Runtime.SetOptions(policy.OptionsType{
			CgroupMark: "10",
		})

		Convey("When I configure the rules with no errors, it should succeed", func() {
			err := i.ConfigureRules(1,
				"ID", containerinfo)
			So(err, ShouldBeNil)
		})

		Convey("When I configure the rules and the proxy set fails, it should error", func() {
			ips.MockNewIpset(t, func(name, hash string, p *ipset.Params) (ipsetmanager.Ipset, error) {
				return nil, fmt.Errorf("error")
			})
			err := i.ConfigureRules(1,
				"ID", containerinfo)
			So(err, ShouldNotBeNil)
		})

		Convey("When I configure the rules and acls fail, it should error", func() {
			iptv6.MockAppend(t, func(table, chain string, rulespec ...string) error {
				return fmt.Errorf("error")
			})
			err := i.ConfigureRules(1,
				"ID", containerinfo)
			So(err, ShouldNotBeNil)
		})

		Convey("When I configure the rules and commit fails, it should error", func() {
			iptv6.MockCommit(t, func() error {
				return fmt.Errorf("error")
			})
			err := i.iptv6.ConfigureRules(1,
				"ID", containerinfo)
			So(err, ShouldNotBeNil)
		})
	})
}

var (
	expectedGlobalMangleChainsV6 = map[string][]string{
		"TRI-Nfq-IN": {"-j HMARK --hmark-tuple dport,sport --hmark-mod 4 --hmark-offset 67 --hmark-rnd 0xdeadbeef",
			"-m mark --mark 67 -j NFQUEUE --queue-num 0 --queue-bypass",
			"-m mark --mark 68 -j NFQUEUE --queue-num 1 --queue-bypass",
			"-m mark --mark 69 -j NFQUEUE --queue-num 2 --queue-bypass",
			"-m mark --mark 70 -j NFQUEUE --queue-num 3 --queue-bypass"},
		"TRI-Nfq-OUT": {"-j HMARK --hmark-tuple sport,dport --hmark-mod 4 --hmark-offset 0 --hmark-rnd 0xdeadbeef",
			"-m mark --mark 0 -j NFQUEUE --queue-num 0 --queue-bypass",
			"-m mark --mark 1 -j NFQUEUE --queue-num 1 --queue-bypass",
			"-m mark --mark 2 -j NFQUEUE --queue-num 2 --queue-bypass",
			"-m mark --mark 3 -j NFQUEUE --queue-num 3 --queue-bypass"},
		"INPUT": {
			"-m set ! --match-set TRI-v6-Excluded src -j TRI-Net",
		},
		"OUTPUT": {
			"-m set ! --match-set TRI-v6-Excluded dst -j TRI-App",
		},
		"TRI-App": {
			"-m mark --mark 66 -j CONNMARK --set-mark 61167", "-p tcp -m mark --mark 66 -j ACCEPT", "-p udp --dport 53 -m mark --mark 0x40 -m cgroup --cgroup 1536 -j CONNMARK --set-mark 61167", "-p udp --dport 53 -m mark --mark 0x40 -j CONNMARK --set-mark 61167", "-j TRI-Prx-App", "-m connmark --mark 61167 -j ACCEPT", "-p udp -m connmark --mark 61165 -m comment --comment Drop UDP ACL -j DROP",
			"-m connmark --mark 61166 -p tcp ! --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j ACCEPT", "-m connmark --mark 61166 -p udp -j ACCEPT", "-m mark --mark 1073741922 -j ACCEPT",
			"-p tcp -m tcp --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j TRI-Nfq-OUT", "-j TRI-Pid-App", "-j TRI-Svc-App", "-j TRI-Hst-App"},
		"TRI-Net": {
			"-j TRI-Prx-Net", "-p tcp -m mark --mark 66 -j CONNMARK --set-mark 61167", "-p tcp -m mark --mark 66 -j ACCEPT", "-m connmark --mark 61167 -p tcp ! --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j ACCEPT", "-m set --match-set TRI-v6-TargetTCP src -p tcp -m tcp --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j TRI-Nfq-IN",
			"-p udp -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -j TRI-Nfq-IN", "-p udp -m connmark --mark 61165 -m comment --comment Drop UDP ACL -j DROP",
			"-m connmark --mark 61166 -p udp -j ACCEPT", "-j TRI-Pid-Net", "-j TRI-Svc-Net", "-j TRI-Hst-Net"},
		"TRI-Pid-App": {},
		"TRI-Pid-Net": {},
		"TRI-Prx-App": {
			"-m mark --mark 0x40 -j ACCEPT",
		},
		"TRI-Prx-Net": {
			"-m mark --mark 0x40 -j ACCEPT",
		},
		"TRI-Hst-App": {},
		"TRI-Hst-Net": {},
		"TRI-Svc-App": {},
		"TRI-Svc-Net": {},
	}

	expectedGlobalNATChainsV6 = map[string][]string{
		"PREROUTING": {
			"-p tcp -m addrtype --dst-type LOCAL -m set ! --match-set TRI-v6-Excluded src -j TRI-Redir-Net",
		},
		"OUTPUT": {
			"-m set ! --match-set TRI-v6-Excluded dst -j TRI-Redir-App",
		},
		"TRI-Redir-App": {
			"-m mark --mark 0x40 -j RETURN",
		},
		"TRI-Redir-Net": {
			"-m mark --mark 0x40 -j ACCEPT",
		},
	}

	expectedMangleAfterPUInsertV6 = map[string][]string{
		"TRI-Nfq-IN": {"-j HMARK --hmark-tuple dport,sport --hmark-mod 4 --hmark-offset 67 --hmark-rnd 0xdeadbeef",
			"-m mark --mark 67 -j NFQUEUE --queue-num 0 --queue-bypass",
			"-m mark --mark 68 -j NFQUEUE --queue-num 1 --queue-bypass",
			"-m mark --mark 69 -j NFQUEUE --queue-num 2 --queue-bypass",
			"-m mark --mark 70 -j NFQUEUE --queue-num 3 --queue-bypass"},
		"TRI-Nfq-OUT": {"-j HMARK --hmark-tuple sport,dport --hmark-mod 4 --hmark-offset 0 --hmark-rnd 0xdeadbeef",
			"-m mark --mark 0 -j NFQUEUE --queue-num 0 --queue-bypass",
			"-m mark --mark 1 -j NFQUEUE --queue-num 1 --queue-bypass",
			"-m mark --mark 2 -j NFQUEUE --queue-num 2 --queue-bypass",
			"-m mark --mark 3 -j NFQUEUE --queue-num 3 --queue-bypass"},
		"INPUT": {
			"-m set ! --match-set TRI-v6-Excluded src -j TRI-Net",
		},
		"OUTPUT": {
			"-m set ! --match-set TRI-v6-Excluded dst -j TRI-App",
		},
		"TRI-App": {
			"-m mark --mark 66 -j CONNMARK --set-mark 61167", "-p tcp -m mark --mark 66 -j ACCEPT", "-p udp --dport 53 -m mark --mark 0x40 -m cgroup --cgroup 1536 -j CONNMARK --set-mark 61167", "-p udp --dport 53 -m mark --mark 0x40 -j CONNMARK --set-mark 61167", "-j TRI-Prx-App", "-m connmark --mark 61167 -j ACCEPT", "-p udp -m connmark --mark 61165 -m comment --comment Drop UDP ACL -j DROP", "-m connmark --mark 61166 -p tcp ! --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j ACCEPT",
			"-m connmark --mark 61166 -p udp -j ACCEPT", "-m mark --mark 1073741922 -j ACCEPT",
			"-p tcp -m tcp --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j TRI-Nfq-OUT", "-j TRI-Pid-App", "-j TRI-Svc-App", "-j TRI-Hst-App"},
		"TRI-Net": {
			"-j TRI-Prx-Net", "-p tcp -m mark --mark 66 -j CONNMARK --set-mark 61167", "-p tcp -m mark --mark 66 -j ACCEPT", "-m connmark --mark 61167 -p tcp ! --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j ACCEPT", "-m set --match-set TRI-v6-TargetTCP src -p tcp -m tcp --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j TRI-Nfq-IN",
			"-p udp -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -j TRI-Nfq-IN", "-p udp -m connmark --mark 61165 -m comment --comment Drop UDP ACL -j DROP",
			"-m connmark --mark 61166 -p udp -j ACCEPT", "-j TRI-Pid-Net", "-j TRI-Svc-Net", "-j TRI-Hst-Net"},
		"TRI-Pid-App": {
			"-m cgroup --cgroup 10 -m comment --comment PU-Chain -j MARK --set-mark 10",
			"-m mark --mark 10 -m comment --comment PU-Chain -j TRI-App-pu1N7uS6--0"},
		"TRI-Pid-Net": {
			"-p tcp -m multiport --destination-ports 9000 -m comment --comment PU-Chain -j TRI-Net-pu1N7uS6--0",
			"-p udp -m multiport --destination-ports 5000 -m comment --comment PU-Chain -j TRI-Net-pu1N7uS6--0",
		},
		"TRI-Prx-App": {
			"-m mark --mark 0x40 -j ACCEPT",
			"-p tcp -m tcp --sport 0 -j ACCEPT",
			"-p tcp -m set --match-set TRI-v6-Proxy-pu19gtV-srv src -j ACCEPT",
			"-p tcp -m set --match-set TRI-v6-Proxy-pu19gtV-dst dst,dst -m mark ! --mark 0x40 -j ACCEPT",
			"-p udp -m udp --sport 0 -j ACCEPT",
		},
		"TRI-Prx-Net": {
			"-m mark --mark 0x40 -j ACCEPT",
			"-p tcp -m set --match-set TRI-v6-Proxy-pu19gtV-dst src,src -j ACCEPT",
			"-p tcp -m set --match-set TRI-v6-Proxy-pu19gtV-srv src -m addrtype --src-type LOCAL -j ACCEPT",
			"-p tcp -m tcp --dport 0 -j ACCEPT",
			"-p udp -m udp --dport 0 -j ACCEPT",
		},
		"TRI-Hst-App": {},
		"TRI-Hst-Net": {},
		"TRI-Svc-App": {},
		"TRI-Svc-Net": {},

		"TRI-Net-pu1N7uS6--0": {
			"-p tcp -m tcp --tcp-option 34 -m tcp --tcp-flags FIN,RST,URG,PSH NONE -j TRI-Nfq-IN",
			"-p UDP -m set --match-set TRI-v6-ext-6zlJIvP3B68= src -m state --state ESTABLISHED -m connmark --mark 61167 -j ACCEPT",
			"-p TCP -m set --match-set TRI-v6-ext-w5frVvhsnpU= src -m state --state NEW --match multiport --dports 80 -j DROP",
			"-p UDP -m set --match-set TRI-v6-ext-IuSLsD1R-mE= src -m string ! --string n30njxq7bmiwr6dtxq --algo bm --to 128 --match multiport --dports 443 -j CONNMARK --set-mark 61167",
			"-p UDP -m set --match-set TRI-v6-ext-IuSLsD1R-mE= src -m string ! --string n30njxq7bmiwr6dtxq --algo bm --to 128 --match multiport --dports 443 -j ACCEPT",
			"-p icmpv6 -m bpf --bytecode 16,48 0 0 0,84 0 0 240,21 0 12 96,48 0 0 6,21 0 10 58,48 0 0 40,21 5 0 133,21 4 0 134,21 3 0 135,21 2 0 136,21 1 0 141,21 0 3 142,48 0 0 41,21 0 1 0,6 0 0 65535,6 0 0 0 -j ACCEPT",
			"-p tcp -m set --match-set TRI-v6-TargetTCP src -m tcp --tcp-flags SYN NONE -j TRI-Nfq-IN",
			"-p udp -m set --match-set TRI-v6-TargetUDP src --match limit --limit 1000/s -j TRI-Nfq-IN",
			"-p tcp -m state --state ESTABLISHED -m comment --comment TCP-Established-Connections -j ACCEPT",
			"-s ::/0 -m state --state NEW -j NFLOG --nflog-group 11 --nflog-prefix 913787369:default:default:6",
			"-s ::/0 -m state ! --state NEW -j NFLOG --nflog-group 11 --nflog-prefix 913787369:default:default:10",
			"-s ::/0 -j DROP",
		},
		"TRI-App-pu1N7uS6--0": {
			"-p TCP -m set --match-set TRI-v6-ext-uNdc0vdcFZA= dst -m state --state NEW --match multiport --dports 80 -j DROP", "-p UDP -m set --match-set TRI-v6-ext-6zlJIvP3B68= dst -m string ! --string n30njxq7bmiwr6dtxq --algo bm --to 128 -m set ! --match-set TRI-v6-TargetUDP dst --match multiport --dports 443 -j CONNMARK --set-mark 61167", "-p UDP -m set --match-set TRI-v6-ext-6zlJIvP3B68= dst -m string ! --string n30njxq7bmiwr6dtxq --algo bm --to 128 -m set ! --match-set TRI-v6-TargetUDP dst --match multiport --dports 443 -j ACCEPT", "-p icmpv6 -m set --match-set TRI-v6-ext-w5frVvhsnpU= dst -j ACCEPT", "-p UDP -m set --match-set TRI-v6-ext-IuSLsD1R-mE= dst -m state --state ESTABLISHED -m connmark --mark 61167 -j ACCEPT", "-p icmpv6 -m bpf --bytecode 16,48 0 0 0,84 0 0 240,21 0 12 96,48 0 0 6,21 0 10 58,48 0 0 40,21 5 0 133,21 4 0 134,21 3 0 135,21 2 0 136,21 1 0 141,21 0 3 142,48 0 0 41,21 0 1 0,6 0 0 65535,6 0 0 0 -j ACCEPT", "-m set --match-set TRI-v6-TargetTCP dst -p tcp -m tcp --tcp-flags FIN FIN -j ACCEPT", "-m set --match-set TRI-v6-TargetTCP dst -p tcp -j HMARK --hmark-tuple sport,dport --hmark-mod 4 --hmark-offset 40 --hmark-rnd 0xdeadbeef", "-p udp -m set --match-set TRI-v6-TargetUDP dst -j HMARK --hmark-tuple sport,dport --hmark-mod 4 --hmark-offset 40 --hmark-rnd 0xdeadbeef", "-m mark --mark 40 -j NFQUEUE --queue-num 0 --queue-bypass", "-m mark --mark 41 -j NFQUEUE --queue-num 1 --queue-bypass", "-m mark --mark 42 -j NFQUEUE --queue-num 2 --queue-bypass", "-m mark --mark 43 -j NFQUEUE --queue-num 3 --queue-bypass",
			"-p tcp -m state --state ESTABLISHED -m comment --comment TCP-Established-Connections -j ACCEPT", "-p udp -m state --state ESTABLISHED -m comment --comment UDP-Established-Connections -j ACCEPT",
			"-d ::/0 -m state --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 913787369:default:default:6", "-d ::/0 -m state ! --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 913787369:default:default:10", "-d ::/0 -j DROP"},
	}

	expectedNATAfterPUInsertV6 = map[string][]string{
		"PREROUTING": {
			"-p tcp -m addrtype --dst-type LOCAL -m set ! --match-set TRI-v6-Excluded src -j TRI-Redir-Net",
		},
		"OUTPUT": {
			"-m set ! --match-set TRI-v6-Excluded dst -j TRI-Redir-App",
		},
		"TRI-Redir-App": {
			"-m mark --mark 0x40 -j RETURN",
			"-p tcp -m set --match-set TRI-v6-Proxy-pu19gtV-dst dst,dst -m mark ! --mark 0x40 -m cgroup --cgroup 10 -j REDIRECT --to-ports 0",
			"-d ::/0 -p udp --dport 53 -m mark ! --mark 0x40 -m cgroup --cgroup 10 -j CONNMARK --save-mark",
			"-d ::/0 -p udp --dport 53 -m mark ! --mark 0x40 -m cgroup --cgroup 10 -j REDIRECT --to-ports 0",
		},
		"TRI-Redir-Net": {
			"-m mark --mark 0x40 -j ACCEPT",
			"-p tcp -m set --match-set TRI-v6-Proxy-pu19gtV-srv dst -m mark ! --mark 0x40 -j REDIRECT --to-ports 0",
		},
		"POSTROUTING": {
			"-p udp -m addrtype --src-type LOCAL -m multiport --source-ports 5000 -j ACCEPT",
		},
	}

	expectedMangleAfterPUUpdateV6 = map[string][]string{
		"TRI-Nfq-IN": {"-j HMARK --hmark-tuple dport,sport --hmark-mod 4 --hmark-offset 67 --hmark-rnd 0xdeadbeef",
			"-m mark --mark 67 -j NFQUEUE --queue-num 0 --queue-bypass",
			"-m mark --mark 68 -j NFQUEUE --queue-num 1 --queue-bypass",
			"-m mark --mark 69 -j NFQUEUE --queue-num 2 --queue-bypass",
			"-m mark --mark 70 -j NFQUEUE --queue-num 3 --queue-bypass"},
		"TRI-Nfq-OUT": {"-j HMARK --hmark-tuple sport,dport --hmark-mod 4 --hmark-offset 0 --hmark-rnd 0xdeadbeef",
			"-m mark --mark 0 -j NFQUEUE --queue-num 0 --queue-bypass",
			"-m mark --mark 1 -j NFQUEUE --queue-num 1 --queue-bypass",
			"-m mark --mark 2 -j NFQUEUE --queue-num 2 --queue-bypass",
			"-m mark --mark 3 -j NFQUEUE --queue-num 3 --queue-bypass"},
		"INPUT": {
			"-m set ! --match-set TRI-v6-Excluded src -j TRI-Net",
		},
		"OUTPUT": {
			"-m set ! --match-set TRI-v6-Excluded dst -j TRI-App",
		},
		"TRI-App": {
			"-m mark --mark 66 -j CONNMARK --set-mark 61167", "-p tcp -m mark --mark 66 -j ACCEPT", "-p udp --dport 53 -m mark --mark 0x40 -m cgroup --cgroup 1536 -j CONNMARK --set-mark 61167", "-p udp --dport 53 -m mark --mark 0x40 -j CONNMARK --set-mark 61167", "-j TRI-Prx-App", "-m connmark --mark 61167 -j ACCEPT", "-p udp -m connmark --mark 61165 -m comment --comment Drop UDP ACL -j DROP",
			"-m connmark --mark 61166 -p tcp ! --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j ACCEPT", "-m connmark --mark 61166 -p udp -j ACCEPT", "-m mark --mark 1073741922 -j ACCEPT",
			"-p tcp -m tcp --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j TRI-Nfq-OUT", "-j TRI-Pid-App", "-j TRI-Svc-App", "-j TRI-Hst-App"},
		"TRI-Net": {
			"-j TRI-Prx-Net", "-p tcp -m mark --mark 66 -j CONNMARK --set-mark 61167", "-p tcp -m mark --mark 66 -j ACCEPT", "-m connmark --mark 61167 -p tcp ! --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j ACCEPT", "-m set --match-set TRI-v6-TargetTCP src -p tcp -m tcp --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j TRI-Nfq-IN", "-p udp -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -j TRI-Nfq-IN", "-p udp -m connmark --mark 61165 -m comment --comment Drop UDP ACL -j DROP",
			"-m connmark --mark 61166 -p udp -j ACCEPT", "-j TRI-Pid-Net", "-j TRI-Svc-Net", "-j TRI-Hst-Net"},
		"TRI-Pid-App": {
			"-m cgroup --cgroup 10 -m comment --comment PU-Chain -j MARK --set-mark 10",
			"-m mark --mark 10 -m comment --comment PU-Chain -j TRI-App-pu1N7uS6--1"},
		"TRI-Pid-Net": {
			"-p tcp -m set --match-set TRI-v6-ProcPort-pu19gtV dst -m comment --comment PU-Chain -j TRI-Net-pu1N7uS6--1",
		},
		"TRI-Prx-App": {
			"-m mark --mark 0x40 -j ACCEPT",
			"-p tcp -m tcp --sport 0 -j ACCEPT",
			"-p tcp -m set --match-set TRI-v6-Proxy-pu19gtV-srv src -j ACCEPT",
			"-p tcp -m set --match-set TRI-v6-Proxy-pu19gtV-dst dst,dst -m mark ! --mark 0x40 -j ACCEPT",
			"-p udp -m udp --sport 0 -j ACCEPT",
		},
		"TRI-Prx-Net": {
			"-m mark --mark 0x40 -j ACCEPT",
			"-p tcp -m set --match-set TRI-v6-Proxy-pu19gtV-dst src,src -j ACCEPT",
			"-p tcp -m set --match-set TRI-v6-Proxy-pu19gtV-srv src -m addrtype --src-type LOCAL -j ACCEPT",
			"-p tcp -m tcp --dport 0 -j ACCEPT",
			"-p udp -m udp --dport 0 -j ACCEPT",
		},
		"TRI-Hst-App": {},
		"TRI-Hst-Net": {},
		"TRI-Svc-App": {},
		"TRI-Svc-Net": {},

		"TRI-Net-pu1N7uS6--1": {
			"-p tcp -m tcp --tcp-option 34 -m tcp --tcp-flags FIN,RST,URG,PSH NONE -j TRI-Nfq-IN",
			"-p TCP -m set --match-set TRI-v6-ext-w5frVvhsnpU= src -m state --state NEW --match multiport --dports 80 -j DROP",
			"-p icmpv6 -m bpf --bytecode 16,48 0 0 0,84 0 0 240,21 0 12 96,48 0 0 6,21 0 10 58,48 0 0 40,21 5 0 133,21 4 0 134,21 3 0 135,21 2 0 136,21 1 0 141,21 0 3 142,48 0 0 41,21 0 1 0,6 0 0 65535,6 0 0 0 -j ACCEPT",
			"-p tcp -m set --match-set TRI-v6-TargetTCP src -m tcp --tcp-flags SYN NONE -j TRI-Nfq-IN",
			"-p udp -m set --match-set TRI-v6-TargetUDP src --match limit --limit 1000/s -j TRI-Nfq-IN",
			"-p tcp -m state --state ESTABLISHED -m comment --comment TCP-Established-Connections -j ACCEPT",
			"-s ::/0 -m state --state NEW -j NFLOG --nflog-group 11 --nflog-prefix 913787369:default:default:6",
			"-s ::/0 -m state ! --state NEW -j NFLOG --nflog-group 11 --nflog-prefix 913787369:default:default:10",
			"-s ::/0 -j DROP"},
		"TRI-App-pu1N7uS6--1": {
			"-p TCP -m set --match-set TRI-v6-ext-uNdc0vdcFZA= dst -m state --state NEW --match multiport --dports 80 -j DROP", "-p icmpv6 -m bpf --bytecode 16,48 0 0 0,84 0 0 240,21 0 12 96,48 0 0 6,21 0 10 58,48 0 0 40,21 5 0 133,21 4 0 134,21 3 0 135,21 2 0 136,21 1 0 141,21 0 3 142,48 0 0 41,21 0 1 0,6 0 0 65535,6 0 0 0 -j ACCEPT", "-m set --match-set TRI-v6-TargetTCP dst -p tcp -m tcp --tcp-flags FIN FIN -j ACCEPT", "-m set --match-set TRI-v6-TargetTCP dst -p tcp -j HMARK --hmark-tuple sport,dport --hmark-mod 4 --hmark-offset 40 --hmark-rnd 0xdeadbeef", "-p udp -m set --match-set TRI-v6-TargetUDP dst -j HMARK --hmark-tuple sport,dport --hmark-mod 4 --hmark-offset 40 --hmark-rnd 0xdeadbeef", "-m mark --mark 40 -j NFQUEUE --queue-num 0 --queue-bypass", "-m mark --mark 41 -j NFQUEUE --queue-num 1 --queue-bypass", "-m mark --mark 42 -j NFQUEUE --queue-num 2 --queue-bypass", "-m mark --mark 43 -j NFQUEUE --queue-num 3 --queue-bypass",
			"-p tcp -m state --state ESTABLISHED -m comment --comment TCP-Established-Connections -j ACCEPT", "-p udp -m state --state ESTABLISHED -m comment --comment UDP-Established-Connections -j ACCEPT",
			"-d ::/0 -m state --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 913787369:default:default:6", "-d ::/0 -m state ! --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 913787369:default:default:10", "-d ::/0 -j DROP"},
	}
)

func Test_OperationWithLinuxServicesV6(t *testing.T) {

	Convey("Given an iptables controller with a memory backend ", t, func() {
		cfg := &runtime.Configuration{
			TCPTargetNetworks: []string{"::/0"},
			UDPTargetNetworks: []string{"1120::/64"},
			ExcludedNetworks:  []string{"::1"},
		}

		commitFunc := func(buf *bytes.Buffer) error {
			return nil
		}

		iptv4 := provider.NewCustomBatchProvider(&baseIpt{}, commitFunc, []string{"nat",
			"mangle"})
		So(iptv4, ShouldNotBeNil)

		iptv6 := provider.NewCustomBatchProvider(&baseIpt{}, commitFunc, []string{"nat",
			"mangle"})
		So(iptv6, ShouldNotBeNil)

		ips := &memoryIPSetProvider{sets: map[string]*memoryIPSet{}}
		i, err := createTestInstance(ips, iptv4, iptv6, constants.LocalServer, policy.None)
		So(err, ShouldBeNil)
		So(i, ShouldNotBeNil)

		Convey("When I start the controller, I should get the right global chains and ipsets", func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			err := i.Run(ctx)
			i.SetTargetNetworks(cfg) // nolint

			So(err, ShouldBeNil)

			t := i.iptv6.impl.RetrieveTable()
			So(t, ShouldNotBeNil)
			So(len(t), ShouldEqual, 2)
			So(t["mangle"], ShouldNotBeNil)
			So(t["nat"], ShouldNotBeNil)

			for chain, rules := range t["mangle"] {
				So(expectedGlobalMangleChainsV6, ShouldContainKey, chain)
				So(rules, ShouldResemble, expectedGlobalMangleChainsV6[chain])
			}

			for chain, rules := range t["nat"] {
				So(expectedGlobalNATChainsV6, ShouldContainKey, chain)
				So(rules, ShouldResemble, expectedGlobalNATChainsV6[chain])
			}

			Convey("When I configure a new set of rules, the ACLs must be correct", func() {

				appACLs := policy.IPRuleList{
					policy.IPRule{
						Addresses: []string{"1120::/64"},
						Ports:     []string{"80"},
						Protocols: []string{"TCP"},
						Policy: &policy.FlowPolicy{
							Action:    policy.Reject,
							ServiceID: "s1",
							PolicyID:  "1",
						},
					},
					policy.IPRule{
						Addresses: []string{"1120::/64"},
						Ports:     []string{"443"},
						Protocols: []string{"UDP"},
						Policy: &policy.FlowPolicy{
							Action:    policy.Accept,
							ServiceID: "s2",
							PolicyID:  "2",
						},
					},
					policy.IPRule{
						Addresses: []string{"1122::/64"},
						Ports:     []string{"443"},
						Protocols: []string{"icmpv6"},
						Policy: &policy.FlowPolicy{
							Action:    policy.Accept,
							ServiceID: "s3",
							PolicyID:  "3",
						},
					},
					policy.IPRule{
						Addresses: []string{"40.0.0.0/24"},
						Ports:     []string{"443"},
						Protocols: []string{"icmp"},
						Policy: &policy.FlowPolicy{
							Action:    policy.Accept,
							ServiceID: "s3",
							PolicyID:  "3",
						},
					},
				}
				netACLs := policy.IPRuleList{
					policy.IPRule{
						Addresses: []string{"1122::/64"},
						Ports:     []string{"80"},
						Protocols: []string{"TCP"},
						Policy: &policy.FlowPolicy{
							Action:    policy.Reject,
							ServiceID: "s3",
							PolicyID:  "1",
						},
					},
					policy.IPRule{
						Addresses: []string{"1122::/64"},
						Ports:     []string{"443"},
						Protocols: []string{"UDP"},
						Policy: &policy.FlowPolicy{
							Action:    policy.Accept,
							ServiceID: "s4",
							PolicyID:  "2",
						},
					},
				}
				ipl := policy.ExtendedMap{}
				policyrules := policy.NewPUPolicy(
					"Context",
					"/ns1",
					policy.Police,
					appACLs,
					netACLs,
					nil,
					nil,
					nil,
					nil,
					nil,
					nil,
					ipl,
					0,
					0,
					nil,
					nil,
					[]string{},
					policy.EnforcerMapping,
					policy.Reject|policy.Log,
					policy.Reject|policy.Log,
				)
				puInfo := policy.NewPUInfo("Context",
					"/ns1", common.LinuxProcessPU)
				puInfo.Policy = policyrules
				puInfo.Runtime.SetOptions(policy.OptionsType{
					CgroupMark: "10",
				})

				udpPortSpec, err := portspec.NewPortSpecFromString("5000", nil)
				So(err, ShouldBeNil)
				tcpPortSpec, err := portspec.NewPortSpecFromString("9000", nil)
				So(err, ShouldBeNil)

				puInfo.Runtime.SetServices([]common.Service{
					{
						Ports:    udpPortSpec,
						Protocol: 17,
					},
					{
						Ports:    tcpPortSpec,
						Protocol: 6,
					},
				})

				var iprules policy.IPRuleList
				iprules = append(iprules, puInfo.Policy.ApplicationACLs()...)
				iprules = append(iprules, puInfo.Policy.NetworkACLs()...)
				i.iptv6.ipsetmanager.RegisterExternalNets("pu1", iprules) // nolint

				err = i.ConfigureRules(0,
					"pu1", puInfo)
				So(err, ShouldBeNil)
				t := i.iptv6.impl.RetrieveTable()

				for chain, rules := range t["mangle"] {
					So(expectedMangleAfterPUInsertV6, ShouldContainKey, chain)
					So(rules, ShouldResemble, expectedMangleAfterPUInsertV6[chain])
				}

				for chain, rules := range t["nat"] {
					So(expectedNATAfterPUInsertV6, ShouldContainKey, chain)
					So(rules, ShouldResemble, expectedNATAfterPUInsertV6[chain])
				}

				Convey("When I update the policy, the update must result in correct state", func() {
					appACLs := policy.IPRuleList{
						policy.IPRule{
							Addresses: []string{"1120::/64"},
							Ports:     []string{"80"},
							Protocols: []string{"TCP"},
							Policy: &policy.FlowPolicy{
								Action:    policy.Reject,
								ServiceID: "s1",
								PolicyID:  "1",
							},
						},
					}
					netACLs := policy.IPRuleList{
						policy.IPRule{
							Addresses: []string{"1122::/64"},
							Ports:     []string{"80"},
							Protocols: []string{"TCP"},
							Policy: &policy.FlowPolicy{
								Action:    policy.Reject,
								ServiceID: "s3",
								PolicyID:  "1",
							},
						},
					}
					ipl := policy.ExtendedMap{}
					policyrules := policy.NewPUPolicy(
						"Context",
						"/ns1",
						policy.Police,
						appACLs,
						netACLs,
						nil,
						nil,
						nil,
						nil,
						nil,
						nil,
						ipl,
						0,
						0,
						nil,
						nil,
						[]string{},
						policy.EnforcerMapping,
						policy.Reject|policy.Log,
						policy.Reject|policy.Log,
					)
					puInfoUpdated := policy.NewPUInfo("Context",
						"/ns1", common.LinuxProcessPU)
					puInfoUpdated.Policy = policyrules
					puInfoUpdated.Runtime.SetOptions(policy.OptionsType{
						CgroupMark: "10",
					})

					err := i.UpdateRules(1,
						"pu1", puInfoUpdated, puInfo)
					So(err, ShouldBeNil)

					t := i.iptv6.impl.RetrieveTable()
					for chain, rules := range t["mangle"] {
						So(expectedMangleAfterPUUpdateV6, ShouldContainKey, chain)
						So(rules, ShouldResemble, expectedMangleAfterPUUpdateV6[chain])
					}

					Convey("When I delete the same rule, the chains must be restored in the global state", func() {
						err := i.DeleteRules(1,
							"pu1",
							"0",
							"5000",
							"10",
							"", puInfoUpdated)
						So(err, ShouldBeNil)

						t := i.iptv6.impl.RetrieveTable()

						So(t["mangle"], ShouldNotBeNil)
						So(t["nat"], ShouldNotBeNil)

						for chain, rules := range t["mangle"] {
							So(expectedGlobalMangleChainsV6, ShouldContainKey, chain)
							So(rules, ShouldResemble, expectedGlobalMangleChainsV6[chain])
						}

						for chain, rules := range t["nat"] {
							if len(rules) > 0 {
								So(expectedGlobalNATChainsV6, ShouldContainKey, chain)
								So(rules, ShouldResemble, expectedGlobalNATChainsV6[chain])
							}
						}
					})
				})
			})
		})
	})
}

func Test_OperationNomatchIpsetsV6(t *testing.T) {

	Convey("Given an iptables controller with a memory backend ", t, func() {
		cfg := &runtime.Configuration{
			TCPTargetNetworks: []string{"::/0",
				"!2001:db8:1234::/48"},
			UDPTargetNetworks: []string{"1120::/64"},
			ExcludedNetworks:  []string{"::1"},
		}

		commitFunc := func(buf *bytes.Buffer) error {
			return nil
		}

		iptv4 := provider.NewCustomBatchProvider(&baseIpt{}, commitFunc, []string{"nat",
			"mangle"})
		So(iptv4, ShouldNotBeNil)

		iptv6 := provider.NewCustomBatchProvider(&baseIpt{}, commitFunc, []string{"nat",
			"mangle"})
		So(iptv6, ShouldNotBeNil)

		ips := &memoryIPSetProvider{sets: map[string]*memoryIPSet{}}
		i, err := createTestInstance(ips, iptv4, iptv6, constants.LocalServer, policy.None)
		So(err, ShouldBeNil)
		So(i, ShouldNotBeNil)

		Convey("When I start the controller, I should get the right global chains and ipsets", func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			err := i.Run(ctx)
			i.SetTargetNetworks(cfg) // nolint

			So(err, ShouldBeNil)

			So(ips.sets, ShouldContainKey,
				"TRI-v6-TargetTCP")
			So(ips.sets["TRI-v6-TargetTCP"].set, ShouldContainKey,
				"2001:db8:1234::/48")
			So(ips.sets["TRI-v6-TargetTCP"].set["2001:db8:1234::/48"], ShouldBeTrue)
			So(ips.sets["TRI-v6-TargetTCP"].set, ShouldContainKey,
				"::/1")
			So(ips.sets["TRI-v6-TargetTCP"].set["::/1"], ShouldBeFalse)
			So(ips.sets["TRI-v6-TargetTCP"].set, ShouldContainKey,
				"8000::/1")
			So(ips.sets["TRI-v6-TargetTCP"].set["8000::/1"], ShouldBeFalse)
		})
	})
}

func Test_OperationNomatchIpsetsInExternalNetworksV6(t *testing.T) {

	Convey("Given an iptables controller with a memory backend ", t, func() {
		cfg := &runtime.Configuration{
			TCPTargetNetworks: []string{"::/0",
				"!2001:db8:1234::/48"},
			UDPTargetNetworks: []string{"1120::/64"},
			ExcludedNetworks:  []string{"::1"},
		}

		commitFunc := func(buf *bytes.Buffer) error {
			return nil
		}

		iptv4 := provider.NewCustomBatchProvider(&baseIpt{}, commitFunc, []string{"nat",
			"mangle"})
		So(iptv4, ShouldNotBeNil)

		iptv6 := provider.NewCustomBatchProvider(&baseIpt{}, commitFunc, []string{"nat",
			"mangle"})
		So(iptv6, ShouldNotBeNil)

		ips := &memoryIPSetProvider{sets: map[string]*memoryIPSet{}}
		i, err := createTestInstance(ips, iptv4, iptv6, constants.LocalServer, policy.None)
		So(err, ShouldBeNil)
		So(i, ShouldNotBeNil)

		Convey("When I start the controller, I should get the right global chains and ipsets", func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			err := i.Run(ctx)
			i.SetTargetNetworks(cfg) // nolint

			So(err, ShouldBeNil)

			// Setup external networks
			appACLs := policy.IPRuleList{
				policy.IPRule{
					Addresses: []string{"::/0",
						"!2001:db8:1234::/48"},
					Ports:     []string{"80"},
					Protocols: []string{constants.TCPProtoNum},
					Policy: &policy.FlowPolicy{
						Action:    policy.Accept | policy.Log,
						ServiceID: "a3",
						PolicyID:  "1234a",
					},
				},
			}
			netACLs := policy.IPRuleList{}

			policyRules := policy.NewPUPolicy("Context",
				"/ns1", policy.Police, appACLs, netACLs, nil, nil, nil, nil, nil, nil, nil, 20992, 0, nil, nil, []string{}, policy.EnforcerMapping, policy.Reject|policy.Log, policy.Reject|policy.Log)

			puInfo := policy.NewPUInfo("Context",
				"/ns1", common.HostPU)
			puInfo.Policy = policyRules
			puInfo.Runtime = policy.NewPURuntimeWithDefaults()
			puInfo.Runtime.SetPUType(common.HostPU)
			puInfo.Runtime.SetOptions(policy.OptionsType{
				CgroupMark: "10",
			})

			// configure rules
			var iprules policy.IPRuleList
			iprules = append(iprules, puInfo.Policy.ApplicationACLs()...)
			iprules = append(iprules, puInfo.Policy.NetworkACLs()...)
			err = i.iptv4.ipsetmanager.RegisterExternalNets("pu1", iprules)
			So(err, ShouldBeNil)
			err = i.iptv6.ipsetmanager.RegisterExternalNets("pu1", iprules)
			So(err, ShouldBeNil)

			err = i.ConfigureRules(0,
				"pu1", puInfo)
			So(err, ShouldBeNil)

			// Check ipsets
			setName := i.iptv6.ipsetmanager.GetACLIPsetsNames(appACLs[0:1])[0]
			So(ips.sets[setName].set, ShouldContainKey,
				"::/1")
			So(ips.sets[setName].set, ShouldContainKey,
				"8000::/1")
			So(ips.sets[setName].set, ShouldContainKey,
				"2001:db8:1234::/48")
			So(ips.sets[setName].set["::/1"], ShouldBeFalse)
			So(ips.sets[setName].set["8000::/1"], ShouldBeFalse)
			So(ips.sets[setName].set["2001:db8:1234::/48"], ShouldBeTrue)

			// Configure and check acl cache
			aclCache := tacls.NewACLCache()
			err = aclCache.AddRuleList(puInfo.Policy.ApplicationACLs())
			So(err, ShouldBeNil)
			defaultFlowPolicy := &policy.FlowPolicy{Action: policy.Reject | policy.Log, PolicyID: "default", ServiceID: "default"}

			report, _, err := aclCache.GetMatchingAction(net.ParseIP("2001:db8:5678::"), 80, packet.IPProtocolTCP, defaultFlowPolicy)
			So(err, ShouldBeNil)
			So(report.Action, ShouldEqual, policy.Accept|policy.Log)

			report, _, err = aclCache.GetMatchingAction(net.ParseIP("2001:db8:1234:5678::"), 80, packet.IPProtocolTCP, defaultFlowPolicy)
			So(err, ShouldNotBeNil)
			So(report.Action, ShouldEqual, policy.Reject|policy.Log)
		})
	})
}

var (
	expectedContainerGlobalMangleChainsV6 = map[string][]string{
		"TRI-Nfq-IN": {"-j HMARK --hmark-tuple dport,sport --hmark-mod 4 --hmark-offset 67 --hmark-rnd 0xdeadbeef",
			"-m mark --mark 67 -j NFQUEUE --queue-num 0 --queue-bypass",
			"-m mark --mark 68 -j NFQUEUE --queue-num 1 --queue-bypass",
			"-m mark --mark 69 -j NFQUEUE --queue-num 2 --queue-bypass",
			"-m mark --mark 70 -j NFQUEUE --queue-num 3 --queue-bypass"},
		"TRI-Nfq-OUT": {"-j HMARK --hmark-tuple sport,dport --hmark-mod 4 --hmark-offset 0 --hmark-rnd 0xdeadbeef",
			"-m mark --mark 0 -j NFQUEUE --queue-num 0 --queue-bypass",
			"-m mark --mark 1 -j NFQUEUE --queue-num 1 --queue-bypass",
			"-m mark --mark 2 -j NFQUEUE --queue-num 2 --queue-bypass",
			"-m mark --mark 3 -j NFQUEUE --queue-num 3 --queue-bypass"},
		"INPUT": {
			"-m set ! --match-set TRI-v6-Excluded src -j TRI-Net",
		},
		"OUTPUT": {
			"-m set ! --match-set TRI-v6-Excluded dst -j TRI-App",
		},
		"TRI-App": {
			"-m mark --mark 66 -j CONNMARK --set-mark 61167", "-p tcp -m mark --mark 66 -j ACCEPT", "-p udp --dport 53 -m mark --mark 0x40 -m cgroup --cgroup 1536 -j CONNMARK --set-mark 61167", "-p udp --dport 53 -m mark --mark 0x40 -j CONNMARK --set-mark 61167", "-j TRI-Prx-App", "-m connmark --mark 61167 -j ACCEPT", "-p udp -m connmark --mark 61165 -m comment --comment Drop UDP ACL -j DROP",
			"-m connmark --mark 61166 -p tcp ! --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j ACCEPT", "-m connmark --mark 61166 -p udp -j ACCEPT",
			"-m mark --mark 1073741922 -j ACCEPT", "-p tcp -m tcp --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j TRI-Nfq-OUT"},
		"TRI-Net": {
			"-j TRI-Prx-Net", "-p tcp -m mark --mark 66 -j CONNMARK --set-mark 61167", "-p tcp -m mark --mark 66 -j ACCEPT", "-m connmark --mark 61167 -p tcp ! --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j ACCEPT",
			"-m set --match-set TRI-v6-TargetTCP src -p tcp -m tcp --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j TRI-Nfq-IN", "-p udp -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -j TRI-Nfq-IN", "-p udp -m connmark --mark 61165 -m comment --comment Drop UDP ACL -j DROP", "-m connmark --mark 61166 -p udp -j ACCEPT",
		},
		"TRI-Prx-App": {
			"-m mark --mark 0x40 -j ACCEPT",
		},
		"TRI-Prx-Net": {
			"-m mark --mark 0x40 -j ACCEPT",
		},
	}

	expectedContainerGlobalNATChainsV6 = map[string][]string{
		"PREROUTING": {
			"-p tcp -m addrtype --dst-type LOCAL -m set ! --match-set TRI-v6-Excluded src -j TRI-Redir-Net",
		},
		"OUTPUT": {
			"-m set ! --match-set TRI-v6-Excluded dst -j TRI-Redir-App",
		},
		"TRI-Redir-App": {
			"-m mark --mark 0x40 -j RETURN",
		},
		"TRI-Redir-Net": {
			"-m mark --mark 0x40 -j ACCEPT",
		},
	}

	expectedContainerMangleAfterPUInsertV6 = map[string][]string{
		"TRI-Nfq-IN": {"-j HMARK --hmark-tuple dport,sport --hmark-mod 4 --hmark-offset 67 --hmark-rnd 0xdeadbeef",
			"-m mark --mark 67 -j NFQUEUE --queue-num 0 --queue-bypass",
			"-m mark --mark 68 -j NFQUEUE --queue-num 1 --queue-bypass",
			"-m mark --mark 69 -j NFQUEUE --queue-num 2 --queue-bypass",
			"-m mark --mark 70 -j NFQUEUE --queue-num 3 --queue-bypass"},
		"TRI-Nfq-OUT": {"-j HMARK --hmark-tuple sport,dport --hmark-mod 4 --hmark-offset 0 --hmark-rnd 0xdeadbeef",
			"-m mark --mark 0 -j NFQUEUE --queue-num 0 --queue-bypass",
			"-m mark --mark 1 -j NFQUEUE --queue-num 1 --queue-bypass",
			"-m mark --mark 2 -j NFQUEUE --queue-num 2 --queue-bypass",
			"-m mark --mark 3 -j NFQUEUE --queue-num 3 --queue-bypass"},
		"INPUT": {
			"-m set ! --match-set TRI-v6-Excluded src -j TRI-Net",
		},
		"OUTPUT": {
			"-m set ! --match-set TRI-v6-Excluded dst -j TRI-App",
		},
		"TRI-App": {
			"-m mark --mark 66 -j CONNMARK --set-mark 61167", "-p tcp -m mark --mark 66 -j ACCEPT", "-p udp --dport 53 -m mark --mark 0x40 -m cgroup --cgroup 1536 -j CONNMARK --set-mark 61167", "-p udp --dport 53 -m mark --mark 0x40 -j CONNMARK --set-mark 61167", "-j TRI-Prx-App", "-m connmark --mark 61167 -j ACCEPT", "-p udp -m connmark --mark 61165 -m comment --comment Drop UDP ACL -j DROP", "-m connmark --mark 61166 -p tcp ! --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j ACCEPT",
			"-m connmark --mark 61166 -p udp -j ACCEPT", "-m mark --mark 1073741922 -j ACCEPT",
			"-p tcp -m tcp --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j TRI-Nfq-OUT", "-m comment --comment Container-specific-chain -j TRI-App-pu1N7uS6--0"},
		"TRI-Net": {
			"-j TRI-Prx-Net", "-p tcp -m mark --mark 66 -j CONNMARK --set-mark 61167", "-p tcp -m mark --mark 66 -j ACCEPT", "-m connmark --mark 61167 -p tcp ! --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j ACCEPT", "-m set --match-set TRI-v6-TargetTCP src -p tcp -m tcp --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j TRI-Nfq-IN",
			"-p udp -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -j TRI-Nfq-IN", "-p udp -m connmark --mark 61165 -m comment --comment Drop UDP ACL -j DROP", "-m connmark --mark 61166 -p udp -j ACCEPT", "-m comment --comment Container-specific-chain -j TRI-Net-pu1N7uS6--0",
		},
		"TRI-Prx-App": {
			"-m mark --mark 0x40 -j ACCEPT",
			"-p tcp -m tcp --sport 0 -j ACCEPT",
			"-p tcp -m set --match-set TRI-v6-Proxy-pu19gtV-srv src -j ACCEPT",
			"-p tcp -m set --match-set TRI-v6-Proxy-pu19gtV-dst dst,dst -m mark ! --mark 0x40 -j ACCEPT",
			"-p udp -m udp --sport 0 -j ACCEPT",
		},
		"TRI-Prx-Net": {
			"-m mark --mark 0x40 -j ACCEPT",
			"-p tcp -m set --match-set TRI-v6-Proxy-pu19gtV-dst src,src -j ACCEPT",
			"-p tcp -m set --match-set TRI-v6-Proxy-pu19gtV-srv src -m addrtype --src-type LOCAL -j ACCEPT",
			"-p tcp -m tcp --dport 0 -j ACCEPT",
			"-p udp -m udp --dport 0 -j ACCEPT",
		},
		"TRI-Net-pu1N7uS6--0": {
			"-p tcp -m tcp --tcp-option 34 -m tcp --tcp-flags FIN,RST,URG,PSH NONE -j TRI-Nfq-IN",
			"-p UDP -m set --match-set TRI-v6-ext-6zlJIvP3B68= src -m state --state ESTABLISHED -m connmark --mark 61167 -j ACCEPT",
			"-p TCP -m set --match-set TRI-v6-ext-w5frVvhsnpU= src -m state --state NEW --match multiport --dports 80 -j DROP",
			"-p UDP -m set --match-set TRI-v6-ext-IuSLsD1R-mE= src -m string ! --string n30njxq7bmiwr6dtxq --algo bm --to 128 --match multiport --dports 443 -j CONNMARK --set-mark 61167",
			"-p UDP -m set --match-set TRI-v6-ext-IuSLsD1R-mE= src -m string ! --string n30njxq7bmiwr6dtxq --algo bm --to 128 --match multiport --dports 443 -j ACCEPT",
			"-p icmpv6 -m bpf --bytecode 16,48 0 0 0,84 0 0 240,21 0 12 96,48 0 0 6,21 0 10 58,48 0 0 40,21 5 0 133,21 4 0 134,21 3 0 135,21 2 0 136,21 1 0 141,21 0 3 142,48 0 0 41,21 0 1 0,6 0 0 65535,6 0 0 0 -j ACCEPT",
			"-p tcp -m set --match-set TRI-v6-TargetTCP src -m tcp --tcp-flags SYN NONE -j TRI-Nfq-IN",
			"-p udp -m set --match-set TRI-v6-TargetUDP src --match limit --limit 1000/s -j TRI-Nfq-IN",
			"-p tcp -m state --state ESTABLISHED -m comment --comment TCP-Established-Connections -j ACCEPT",
			"-s ::/0 -m state --state NEW -j NFLOG --nflog-group 11 --nflog-prefix 913787369:default:default:6",
			"-s ::/0 -m state ! --state NEW -j NFLOG --nflog-group 11 --nflog-prefix 913787369:default:default:10",
			"-s ::/0 -j DROP",
		},
		"TRI-App-pu1N7uS6--0": {
			"-p TCP -m set --match-set TRI-v6-ext-uNdc0vdcFZA= dst -m state --state NEW --match multiport --dports 80 -j DROP", "-p UDP -m set --match-set TRI-v6-ext-6zlJIvP3B68= dst -m string ! --string n30njxq7bmiwr6dtxq --algo bm --to 128 -m set ! --match-set TRI-v6-TargetUDP dst --match multiport --dports 443 -j CONNMARK --set-mark 61167", "-p UDP -m set --match-set TRI-v6-ext-6zlJIvP3B68= dst -m string ! --string n30njxq7bmiwr6dtxq --algo bm --to 128 -m set ! --match-set TRI-v6-TargetUDP dst --match multiport --dports 443 -j ACCEPT", "-p UDP -m set --match-set TRI-v6-ext-IuSLsD1R-mE= dst -m state --state ESTABLISHED -m connmark --mark 61167 -j ACCEPT", "-p icmpv6 -m bpf --bytecode 16,48 0 0 0,84 0 0 240,21 0 12 96,48 0 0 6,21 0 10 58,48 0 0 40,21 5 0 133,21 4 0 134,21 3 0 135,21 2 0 136,21 1 0 141,21 0 3 142,48 0 0 41,21 0 1 0,6 0 0 65535,6 0 0 0 -j ACCEPT", "-m set --match-set TRI-v6-TargetTCP dst -p tcp -m tcp --tcp-flags FIN FIN -j ACCEPT", "-m set --match-set TRI-v6-TargetTCP dst -p tcp -j TRI-Nfq-OUT",
			"-p udp -m set --match-set TRI-v6-TargetUDP dst -j TRI-Nfq-OUT", "-p tcp -m state --state ESTABLISHED -m comment --comment TCP-Established-Connections -j ACCEPT", "-p udp -m state --state ESTABLISHED -m comment --comment UDP-Established-Connections -j ACCEPT", "-d ::/0 -m state --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 913787369:default:default:6",
			"-d ::/0 -m state ! --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 913787369:default:default:10", "-d ::/0 -j DROP"},
	}

	expectedContainerNATAfterPUInsertV6 = map[string][]string{
		"PREROUTING": {
			"-p tcp -m addrtype --dst-type LOCAL -m set ! --match-set TRI-v6-Excluded src -j TRI-Redir-Net",
		},
		"OUTPUT": {
			"-m set ! --match-set TRI-v6-Excluded dst -j TRI-Redir-App",
		},
		"TRI-Redir-App": {
			"-m mark --mark 0x40 -j RETURN",
			"-p tcp -m set --match-set TRI-v6-Proxy-pu19gtV-dst dst,dst -m mark ! --mark 0x40 -m cgroup --cgroup 10 -j REDIRECT --to-ports 0",
			"-d ::/0 -p udp --dport 53 -m mark ! --mark 0x40 -m cgroup --cgroup 10 -j CONNMARK --save-mark",
			"-d ::/0 -p udp --dport 53 -m mark ! --mark 0x40 -m cgroup --cgroup 10 -j REDIRECT --to-ports 0",
		},
		"TRI-Redir-Net": {
			"-m mark --mark 0x40 -j ACCEPT",
			"-p tcp -m set --match-set TRI-v6-Proxy-pu19gtV-srv dst -m mark ! --mark 0x40 -j REDIRECT --to-ports 0",
		},
	}
)

func Test_OperationWithContainersV6(t *testing.T) {

	Convey("Given an iptables controller with a memory backend for containers ", t, func() {
		cfg := &runtime.Configuration{
			TCPTargetNetworks: []string{"::/0"},
			UDPTargetNetworks: []string{"1120::/64"},
			ExcludedNetworks:  []string{"::1"},
		}

		commitFunc := func(buf *bytes.Buffer) error {
			return nil
		}

		iptv4 := provider.NewCustomBatchProvider(&baseIpt{}, commitFunc, []string{"nat",
			"mangle"})
		So(iptv4, ShouldNotBeNil)

		iptv6 := provider.NewCustomBatchProvider(&baseIpt{}, commitFunc, []string{"nat",
			"mangle"})
		So(iptv6, ShouldNotBeNil)

		ips := &memoryIPSetProvider{sets: map[string]*memoryIPSet{}}
		i, err := createTestInstance(ips, iptv4, iptv6, constants.RemoteContainer, policy.None)
		So(err, ShouldBeNil)
		So(i, ShouldNotBeNil)

		Convey("When I start the controller, I should get the right global chains and sets", func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			err := i.Run(ctx)
			So(err, ShouldBeNil)
			i.SetTargetNetworks(cfg) // nolint

			t := i.iptv6.impl.RetrieveTable()
			So(t, ShouldNotBeNil)
			So(len(t), ShouldEqual, 2)
			So(t["mangle"], ShouldNotBeNil)
			So(t["nat"], ShouldNotBeNil)

			for chain, rules := range t["mangle"] {
				So(expectedContainerGlobalMangleChainsV6, ShouldContainKey, chain)
				So(rules, ShouldResemble, expectedContainerGlobalMangleChainsV6[chain])
			}

			for chain, rules := range t["nat"] {
				So(expectedContainerGlobalNATChainsV6, ShouldContainKey, chain)
				So(rules, ShouldResemble, expectedContainerGlobalNATChainsV6[chain])
			}

			Convey("When I configure a new set of rules, the ACLs must be correct", func() {
				appACLs := policy.IPRuleList{
					policy.IPRule{
						Addresses: []string{"1120::/64"},
						Ports:     []string{"80"},
						Protocols: []string{"TCP"},
						Policy: &policy.FlowPolicy{
							Action:    policy.Reject,
							ServiceID: "s1",
							PolicyID:  "1",
						},
					},
					policy.IPRule{
						Addresses: []string{"1120::/64"},
						Ports:     []string{"443"},
						Protocols: []string{"UDP"},
						Policy: &policy.FlowPolicy{
							Action:    policy.Accept,
							ServiceID: "s2",
							PolicyID:  "2",
						},
					},
				}
				netACLs := policy.IPRuleList{
					policy.IPRule{
						Addresses: []string{"1122::/64"},
						Ports:     []string{"80"},
						Protocols: []string{"TCP"},
						Policy: &policy.FlowPolicy{
							Action:    policy.Reject,
							ServiceID: "s3",
							PolicyID:  "1",
						},
					},
					policy.IPRule{
						Addresses: []string{"1122::/64"},
						Ports:     []string{"443"},
						Protocols: []string{"UDP"},
						Policy: &policy.FlowPolicy{
							Action:    policy.Accept,
							ServiceID: "s4",
							PolicyID:  "2",
						},
					},
				}
				ipl := policy.ExtendedMap{}
				policyrules := policy.NewPUPolicy(
					"Context",
					"/ns1",
					policy.Police,
					appACLs,
					netACLs,
					nil,
					nil,
					nil,
					nil,
					nil,
					nil,
					ipl,
					0,
					0,
					nil,
					nil,
					[]string{},
					policy.EnforcerMapping,
					policy.Reject|policy.Log,
					policy.Reject|policy.Log,
				)
				puInfo := policy.NewPUInfo("Context",
					"/ns1", common.ContainerPU)
				puInfo.Policy = policyrules
				puInfo.Runtime.SetOptions(policy.OptionsType{
					CgroupMark: "10",
				})

				var iprules policy.IPRuleList
				iprules = append(iprules, puInfo.Policy.ApplicationACLs()...)
				iprules = append(iprules, puInfo.Policy.NetworkACLs()...)
				i.iptv6.ipsetmanager.RegisterExternalNets("pu1", iprules) // nolint

				err := i.ConfigureRules(0,
					"pu1", puInfo)
				So(err, ShouldBeNil)
				t := i.iptv6.impl.RetrieveTable()

				for chain, rules := range t["mangle"] {
					So(expectedContainerMangleAfterPUInsertV6, ShouldContainKey, chain)
					So(rules, ShouldResemble, expectedContainerMangleAfterPUInsertV6[chain])
				}

				for chain, rules := range t["nat"] {
					So(expectedContainerNATAfterPUInsertV6, ShouldContainKey, chain)
					So(rules, ShouldResemble, expectedContainerNATAfterPUInsertV6[chain])
				}

				Convey("When I delete the same rule, the chains must be restored in the global state",
					func() {
						err := i.iptv6.DeleteRules(0,
							"pu1",
							"0",
							"0",
							"10",
							"", puInfo)
						So(err, ShouldBeNil)

						t := i.iptv6.impl.RetrieveTable()
						if err != nil {
							printTable(t)
						}

						So(t["mangle"], ShouldNotBeNil)
						So(t["nat"], ShouldNotBeNil)

						for chain, rules := range t["mangle"] {
							So(expectedContainerGlobalMangleChainsV6, ShouldContainKey, chain)
							So(rules, ShouldResemble, expectedContainerGlobalMangleChainsV6[chain])
						}

						for chain, rules := range t["nat"] {
							So(expectedContainerGlobalNATChainsV6, ShouldContainKey, chain)
							So(rules, ShouldResemble, expectedContainerGlobalNATChainsV6[chain])
						}
					})

			})
		})
	})
}

func TestIpv6Disable(t *testing.T) {
	ipv6Instance := &ipv6{ipv6Enabled: false}

	assert.Equal(t, ipv6Instance.Append("", "") == nil, true, "error should be nil")
	assert.Equal(t, ipv6Instance.Insert("", "", 0) == nil, true, "error should be nil")
	assert.Equal(t, ipv6Instance.ClearChain("", "") == nil, true, "error should be nil")
	assert.Equal(t, ipv6Instance.DeleteChain("", "") == nil, true, "error should be nil")
	assert.Equal(t, ipv6Instance.NewChain("", "") == nil, true, "error should be nil")
	assert.Equal(t, ipv6Instance.Commit() == nil, true, "error should be nil")
	chains, err := ipv6Instance.ListChains("")

	assert.Equal(t, chains == nil, true, "chains should be nil")
	assert.Equal(t, err == nil, true, "error should be nil")
}
