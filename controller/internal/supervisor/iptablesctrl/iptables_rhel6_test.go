// +build rhel6

package iptablesctrl

import (
	"bytes"
	"context"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/enforcerd/trireme-lib/common"
	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	provider "go.aporeto.io/enforcerd/trireme-lib/controller/pkg/aclprovider"
	"go.aporeto.io/enforcerd/trireme-lib/controller/runtime"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.aporeto.io/enforcerd/trireme-lib/utils/portspec"
)

var icmpAllow = testICMPAllow

func testICMPAllow() string {
	panic("icmp implementation for rhel6 should not call this")
}

var (
	expectedGlobalMangleChainsV4 = map[string][]string{
		"TRI-Nfq-IN": {
			"-j MARK --set-mark 67",
			"-m mark --mark 67 -j NFQUEUE --queue-balance 0:3 --queue-bypass",
		},
		"TRI-Nfq-OUT": {
			"-j MARK --set-mark 0",
			"-m mark --mark 0 -j NFQUEUE --queue-balance 0:3 --queue-bypass",
		},
		"INPUT": {
			"-m set ! --match-set TRI-v4-Excluded src -j TRI-Net",
		},
		"OUTPUT": {
			"-m set ! --match-set TRI-v4-Excluded dst -j TRI-App",
		},

		"TRI-App": {
			"-p udp --dport 53 -j ACCEPT",
			"-m mark --mark 66 -j CONNMARK --set-mark 61167",
			"-p tcp -m mark --mark 66 -j ACCEPT",
			"-p udp --dport 53 -m mark --mark 0x40 -j CONNMARK --set-mark 61167",
			"-j TRI-Prx-App",
			"-m connmark --mark 61167 -j ACCEPT",
			"-p udp -m connmark --mark 61165 -m comment --comment Drop UDP ACL -j DROP",
			"-m connmark --mark 61166 -p tcp ! --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j ACCEPT",
			"-m connmark --mark 61166 -p udp -j ACCEPT",
			"-m mark --mark 1073741922 -j ACCEPT",
			"-p tcp -m tcp --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j TRI-Nfq-OUT",
			"-j TRI-Pid-App",
			"-j TRI-Svc-App",
			"-j TRI-Hst-App",
		},
		"TRI-Net": {
			"-p udp --sport 53 -j ACCEPT",
			"-j TRI-Prx-Net",
			"-p tcp -m mark --mark 66 -j CONNMARK --set-mark 61167",
			"-p tcp -m mark --mark 66 -j ACCEPT",
			"-m connmark --mark 61167 -p tcp ! --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j ACCEPT",
			"-m set --match-set TRI-v4-TargetTCP src -p tcp -m tcp --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j TRI-Nfq-IN",
			"-p udp -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -j TRI-Nfq-IN",
			"-p udp -m connmark --mark 61165 -m comment --comment Drop UDP ACL -j DROP",
			"-m connmark --mark 61166 -p udp -j ACCEPT",
			"-j TRI-Pid-Net",
			"-j TRI-Svc-Net",
			"-j TRI-Hst-Net"},
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

	expectedGlobalNATChainsV4 = map[string][]string{
		"PREROUTING": {
			"-p tcp -m addrtype --dst-type LOCAL -m set ! --match-set TRI-v4-Excluded src -j TRI-Redir-Net",
		},
		"OUTPUT": {
			"-m set ! --match-set TRI-v4-Excluded dst -j TRI-Redir-App",
		},
		"TRI-Redir-App": {
			"-m mark --mark 0x40 -j ACCEPT",
		},
		"TRI-Redir-Net": {
			"-m mark --mark 0x40 -j ACCEPT",
		},
	}

	expectedMangleAfterPUInsertV4 = map[string][]string{
		"TRI-Nfq-IN": {
			"-j MARK --set-mark 67",
			"-m mark --mark 67 -j NFQUEUE --queue-balance 0:3 --queue-bypass",
		},
		"TRI-Nfq-OUT": {
			"-j MARK --set-mark 0",
			"-m mark --mark 0 -j NFQUEUE --queue-balance 0:3 --queue-bypass",
		},
		"INPUT": {
			"-m set ! --match-set TRI-v4-Excluded src -j TRI-Net",
		},
		"OUTPUT": {
			"-m set ! --match-set TRI-v4-Excluded dst -j TRI-App",
		},
		"TRI-App": {
			"-p udp --dport 53 -j ACCEPT",
			"-m mark --mark 66 -j CONNMARK --set-mark 61167",
			"-p tcp -m mark --mark 66 -j ACCEPT",
			"-p udp --dport 53 -m mark --mark 0x40 -j CONNMARK --set-mark 61167",
			"-j TRI-Prx-App",
			"-m connmark --mark 61167 -j ACCEPT",
			"-p udp -m connmark --mark 61165 -m comment --comment Drop UDP ACL -j DROP",
			"-m connmark --mark 61166 -p tcp ! --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j ACCEPT",
			"-m connmark --mark 61166 -p udp -j ACCEPT",
			"-m mark --mark 1073741922 -j ACCEPT",
			"-p tcp -m tcp --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j TRI-Nfq-OUT",
			"-j TRI-Pid-App",
			"-j TRI-Svc-App",
			"-j TRI-Hst-App",
		},
		"TRI-Net": {
			"-p udp --sport 53 -j ACCEPT",
			"-j TRI-Prx-Net",
			"-p tcp -m mark --mark 66 -j CONNMARK --set-mark 61167",
			"-p tcp -m mark --mark 66 -j ACCEPT",
			"-m connmark --mark 61167 -p tcp ! --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j ACCEPT",
			"-m set --match-set TRI-v4-TargetTCP src -p tcp -m tcp --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j TRI-Nfq-IN",
			"-p udp -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -j TRI-Nfq-IN",
			"-p udp -m connmark --mark 61165 -m comment --comment Drop UDP ACL -j DROP",
			"-m connmark --mark 61166 -p udp -j ACCEPT",
			"-j TRI-Pid-Net",
			"-j TRI-Svc-Net",
			"-j TRI-Hst-Net",
		},
		"TRI-Pid-App": {},
		"TRI-Pid-Net": {},
		"TRI-Prx-App": {
			"-m mark --mark 0x40 -j ACCEPT",
			"-p tcp -m tcp --sport 0 -j ACCEPT",
			"-p udp -m udp --sport 0 -j ACCEPT",
			"-p tcp -m set --match-set TRI-v4-Proxy-pu19gtV-srv src -j ACCEPT",
			"-p tcp -m set --match-set TRI-v4-Proxy-pu19gtV-dst dst,dst -m mark ! --mark 0x40 -j ACCEPT",
		},
		"TRI-Prx-Net": {
			"-m mark --mark 0x40 -j ACCEPT",
			"-p tcp -m set --match-set TRI-v4-Proxy-pu19gtV-dst src,src -j ACCEPT",
			"-p tcp -m set --match-set TRI-v4-Proxy-pu19gtV-srv src -m addrtype --src-type LOCAL -j ACCEPT",
			"-p tcp -m tcp --dport 0 -j ACCEPT",
			"-p udp -m udp --dport 0 -j ACCEPT",
		},
		"TRI-Hst-App": {},
		"TRI-Hst-Net": {},
		"TRI-Svc-App": {
			"-p icmp -m comment --comment Server-specific-chain -j MARK --set-mark 10",
			"-p tcp -m multiport --source-ports 9000 -m comment --comment Server-specific-chain -j MARK --set-mark 10",
			"-p tcp -m multiport --source-ports 9000 -m comment --comment Server-specific-chain -j TRI-App-pu1N7uS6--0",
			"-p udp -m multiport --source-ports 5000 -m comment --comment Server-specific-chain -j MARK --set-mark 10",
			"-p udp -m mark --mark 10 -m addrtype --src-type LOCAL -m addrtype --dst-type LOCAL -m state --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 913787369:default:default:3",
			"-m comment --comment traffic-same-pu -p udp -m mark --mark 10 -m addrtype --src-type LOCAL -m addrtype --dst-type LOCAL -j ACCEPT",
			"-p udp -m multiport --source-ports 5000 -m comment --comment Server-specific-chain -j TRI-App-pu1N7uS6--0",
		},
		"TRI-Svc-Net": {
			"-p tcp -m multiport --destination-ports 9000 -m comment --comment Container-specific-chain -j TRI-Net-pu1N7uS6--0",
			"-m comment --comment traffic-same-pu -p udp -m mark --mark 10 -m addrtype --src-type LOCAL -m addrtype --dst-type LOCAL -j ACCEPT",
			"-p udp -m multiport --destination-ports 5000 -m comment --comment Container-specific-chain -j TRI-Net-pu1N7uS6--0",
		},

		"TRI-Net-pu1N7uS6--0": {
			"-p tcp -m tcp --tcp-option 34 -m tcp --tcp-flags FIN,RST,URG,PSH NONE -j TRI-Nfq-IN",
			"-p UDP -m set --match-set TRI-v4-ext-6zlJIvP3B68= src -m state --state ESTABLISHED -m connmark --mark 61167 -j ACCEPT",
			"-p TCP -m set --match-set TRI-v4-ext-w5frVvhsnpU= src -m state --state NEW --match multiport --dports 80 -j DROP",
			"-p UDP -m set --match-set TRI-v4-ext-IuSLsD1R-mE= src -m string ! --string n30njxq7bmiwr6dtxq --algo bm --to 128 --match multiport --dports 443 -j CONNMARK --set-mark 61167",
			"-p UDP -m set --match-set TRI-v4-ext-IuSLsD1R-mE= src -m string ! --string n30njxq7bmiwr6dtxq --algo bm --to 128 --match multiport --dports 443 -j ACCEPT",
			"-p icmp -j NFQUEUE --queue-balance 0:3",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN NONE -j TRI-Nfq-IN",
			"-p udp -m set --match-set TRI-v4-TargetUDP src --match limit --limit 1000/s -j TRI-Nfq-IN",
			"-p tcp -m state --state ESTABLISHED -m comment --comment TCP-Established-Connections -j ACCEPT",
			"-p ALL -m set --match-set TRI-v4-ext-_qhcdC8NcJc= src -j NFLOG --nflog-group 11 --nflog-prefix 913787369:123a:a3:6",
			"-p ALL -m set --match-set TRI-v4-ext-_qhcdC8NcJc= src -j DROP",
			"-p ALL -m set --match-set TRI-v4-ext-_qhcdC8NcJc= src -j NFLOG --nflog-group 11 --nflog-prefix 913787369:123a:a3:3",
			"-p ALL -m set --match-set TRI-v4-ext-_qhcdC8NcJc= src -j ACCEPT",
			"-s 0.0.0.0/0 -m state --state NEW -j NFLOG --nflog-group 11 --nflog-prefix 913787369:default:default:6",
			"-s 0.0.0.0/0 -m state ! --state NEW -j NFLOG --nflog-group 11 --nflog-prefix 913787369:default:default:10",
			"-s 0.0.0.0/0 -j DROP",
		},
		"TRI-App-pu1N7uS6--0": {
			"-p TCP -m set --match-set TRI-v4-ext-uNdc0vdcFZA= dst -m state --state NEW --match multiport --dports 80 -j DROP",
			"-p UDP -m set --match-set TRI-v4-ext-6zlJIvP3B68= dst -m string ! --string n30njxq7bmiwr6dtxq --algo bm --to 128 -m set ! --match-set TRI-v4-TargetUDP dst --match multiport --dports 443 -j CONNMARK --set-mark 61167",
			"-p UDP -m set --match-set TRI-v4-ext-6zlJIvP3B68= dst -m string ! --string n30njxq7bmiwr6dtxq --algo bm --to 128 -m set ! --match-set TRI-v4-TargetUDP dst --match multiport --dports 443 -j ACCEPT",
			"-p UDP -m set --match-set TRI-v4-ext-IuSLsD1R-mE= dst -m state --state ESTABLISHED -m connmark --mark 61167 -j ACCEPT",
			"-p icmp -j NFQUEUE --queue-balance 0:3",
			"-m set --match-set TRI-v4-TargetTCP dst -p tcp -m tcp --tcp-flags FIN FIN -j ACCEPT",
			"-m set --match-set TRI-v4-TargetTCP dst -p tcp -j MARK --set-mark 40",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -j MARK --set-mark 40",
			"-m mark --mark 40 -j NFQUEUE --queue-balance 0:3 --queue-bypass",
			"-p tcp -m state --state ESTABLISHED -m comment --comment TCP-Established-Connections -j ACCEPT",
			"-p udp -m state --state ESTABLISHED -m comment --comment UDP-Established-Connections -j ACCEPT",
			"-p ALL -m set --match-set TRI-v4-ext-_qhcdC8NcJc= dst -j NFLOG --nflog-group 10 --nflog-prefix 913787369:123a:a3:rockstars _4090221238:6",
			"-p ALL -m set --match-set TRI-v4-ext-_qhcdC8NcJc= dst -j DROP",
			"-p ALL -m set --match-set TRI-v4-ext-_qhcdC8NcJc= dst -j NFLOG --nflog-group 10 --nflog-prefix 913787369:123a:a3:3",
			"-p ALL -m set --match-set TRI-v4-ext-_qhcdC8NcJc= dst -j ACCEPT",
			"-d 0.0.0.0/0 -m state --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 913787369:default:default:6",
			"-d 0.0.0.0/0 -m state ! --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 913787369:default:default:10",
			"-d 0.0.0.0/0 -j DROP",
		},
	}

	expectedNATAfterPUInsertV4 = map[string][]string{
		"PREROUTING": {
			"-p tcp -m addrtype --dst-type LOCAL -m set ! --match-set TRI-v4-Excluded src -j TRI-Redir-Net",
		},
		"OUTPUT": {
			"-m set ! --match-set TRI-v4-Excluded dst -j TRI-Redir-App",
		},
		"TRI-Redir-App": {
			"-m mark --mark 0x40 -j ACCEPT",
			"-p tcp -m set --match-set TRI-v4-Proxy-pu19gtV-dst dst,dst -m mark ! --mark 0x40 -m multiport --source-ports 9000 -j REDIRECT --to-ports 0",
			"-p udp --dport 53 -m mark ! --mark 0x40 -j REDIRECT --to-ports 0",
		},
		"TRI-Redir-Net": {
			"-m mark --mark 0x40 -j ACCEPT",
			"-p tcp -m set --match-set TRI-v4-Proxy-pu19gtV-srv dst -m mark ! --mark 0x40 -j REDIRECT --to-ports 0",
		},
		"POSTROUTING": {
			"-p udp -m addrtype --src-type LOCAL -m multiport --source-ports 5000 -j ACCEPT",
		},
	}

	expectedMangleAfterPUUpdateV4 = map[string][]string{
		"TRI-Nfq-IN": {
			"-j MARK --set-mark 67",
			"-m mark --mark 67 -j NFQUEUE --queue-balance 0:3 --queue-bypass",
		},
		"TRI-Nfq-OUT": {
			"-j MARK --set-mark 0",
			"-m mark --mark 0 -j NFQUEUE --queue-balance 0:3 --queue-bypass",
		},
		"INPUT": {
			"-m set ! --match-set TRI-v4-Excluded src -j TRI-Net",
		},
		"OUTPUT": {
			"-m set ! --match-set TRI-v4-Excluded dst -j TRI-App",
		},
		"TRI-App": {
			"-p udp --dport 53 -j ACCEPT",
			"-m mark --mark 66 -j CONNMARK --set-mark 61167",
			"-p tcp -m mark --mark 66 -j ACCEPT",
			"-p udp --dport 53 -m mark --mark 0x40 -j CONNMARK --set-mark 61167",
			"-j TRI-Prx-App",
			"-m connmark --mark 61167 -j ACCEPT",
			"-p udp -m connmark --mark 61165 -m comment --comment Drop UDP ACL -j DROP",
			"-m connmark --mark 61166 -p tcp ! --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j ACCEPT",
			"-m connmark --mark 61166 -p udp -j ACCEPT",
			"-m mark --mark 1073741922 -j ACCEPT",
			"-p tcp -m tcp --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j TRI-Nfq-OUT",
			"-j TRI-Pid-App",
			"-j TRI-Svc-App",
			"-j TRI-Hst-App"},
		"TRI-Net": {
			"-p udp --sport 53 -j ACCEPT",
			"-j TRI-Prx-Net",
			"-p tcp -m mark --mark 66 -j CONNMARK --set-mark 61167",
			"-p tcp -m mark --mark 66 -j ACCEPT",
			"-m connmark --mark 61167 -p tcp ! --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j ACCEPT",
			"-m set --match-set TRI-v4-TargetTCP src -p tcp -m tcp --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j TRI-Nfq-IN",
			"-p udp -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -j TRI-Nfq-IN",
			"-p udp -m connmark --mark 61165 -m comment --comment Drop UDP ACL -j DROP",
			"-m connmark --mark 61166 -p udp -j ACCEPT",
			"-j TRI-Pid-Net",
			"-j TRI-Svc-Net",
			"-j TRI-Hst-Net",
		},
		"TRI-Pid-App": {},
		"TRI-Pid-Net": {},
		"TRI-Prx-App": {
			"-m mark --mark 0x40 -j ACCEPT",
			"-p tcp -m tcp --sport 0 -j ACCEPT",
			"-p udp -m udp --sport 0 -j ACCEPT",
			"-p tcp -m set --match-set TRI-v4-Proxy-pu19gtV-srv src -j ACCEPT",
			"-p tcp -m set --match-set TRI-v4-Proxy-pu19gtV-dst dst,dst -m mark ! --mark 0x40 -j ACCEPT",
		},
		"TRI-Prx-Net": {
			"-m mark --mark 0x40 -j ACCEPT",
			"-p tcp -m set --match-set TRI-v4-Proxy-pu19gtV-dst src,src -j ACCEPT",
			"-p tcp -m set --match-set TRI-v4-Proxy-pu19gtV-srv src -m addrtype --src-type LOCAL -j ACCEPT",
			"-p tcp -m tcp --dport 0 -j ACCEPT",
			"-p udp -m udp --dport 0 -j ACCEPT",
		},
		"TRI-Hst-App": {},
		"TRI-Hst-Net": {},
		"TRI-Svc-App": {},
		"TRI-Svc-Net": {},

		"TRI-Net-pu1N7uS6--1": {
			"-p tcp -m tcp --tcp-option 34 -m tcp --tcp-flags FIN,RST,URG,PSH NONE -j TRI-Nfq-IN",
			"-p TCP -m set --match-set TRI-v4-ext-w5frVvhsnpU= src -m state --state NEW --match multiport --dports 80 -j DROP",
			"-p icmp -j NFQUEUE --queue-balance 0:3",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN NONE -j TRI-Nfq-IN",
			"-p udp -m set --match-set TRI-v4-TargetUDP src --match limit --limit 1000/s -j TRI-Nfq-IN",
			"-p tcp -m state --state ESTABLISHED -m comment --comment TCP-Established-Connections -j ACCEPT",
			"-s 0.0.0.0/0 -m state --state NEW -j NFLOG --nflog-group 11 --nflog-prefix 913787369:default:default:6",
			"-s 0.0.0.0/0 -m state ! --state NEW -j NFLOG --nflog-group 11 --nflog-prefix 913787369:default:default:10",
			"-s 0.0.0.0/0 -j DROP",
		},

		"TRI-App-pu1N7uS6--1": {
			"-p TCP -m set --match-set TRI-v4-ext-uNdc0vdcFZA= dst -m state --state NEW --match multiport --dports 80 -j DROP",
			"-p icmp -j NFQUEUE --queue-balance 0:3",
			"-m set --match-set TRI-v4-TargetTCP dst -p tcp -m tcp --tcp-flags FIN FIN -j ACCEPT",
			"-m set --match-set TRI-v4-TargetTCP dst -p tcp -j MARK --set-mark 40",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -j MARK --set-mark 40",
			"-m mark --mark 40 -j NFQUEUE --queue-balance 0:3 --queue-bypass",
			"-p tcp -m state --state ESTABLISHED -m comment --comment TCP-Established-Connections -j ACCEPT",
			"-p udp -m state --state ESTABLISHED -m comment --comment UDP-Established-Connections -j ACCEPT",
			"-d 0.0.0.0/0 -m state --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 913787369:default:default:6",
			"-d 0.0.0.0/0 -m state ! --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 913787369:default:default:10",
			"-d 0.0.0.0/0 -j DROP",
		},
	}
)

func Test_Rhel6ConfigureRulesV4(t *testing.T) {
	Convey("Given an iptables controller with a memory backend ", t, func() {
		cfg := &runtime.Configuration{
			TCPTargetNetworks: []string{"0.0.0.0/0"},
			UDPTargetNetworks: []string{"10.0.0.0/8"},
			ExcludedNetworks:  []string{"127.0.0.1"},
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

			t := i.iptv4.impl.RetrieveTable()
			So(t, ShouldNotBeNil)
			So(len(t), ShouldEqual, 2)
			So(t["mangle"], ShouldNotBeNil)
			So(t["nat"], ShouldNotBeNil)
			for chain, rules := range t["mangle"] {
				So(expectedGlobalMangleChainsV4, ShouldContainKey, chain)
				So(rules, ShouldResemble, expectedGlobalMangleChainsV4[chain])
			}

			for chain, rules := range t["nat"] {
				So(expectedGlobalNATChainsV4, ShouldContainKey, chain)
				So(rules, ShouldResemble, expectedGlobalNATChainsV4[chain])
			}

			Convey("When I configure a new set of rules, the ACLs must be correct", func() {
				appACLs := policy.IPRuleList{
					policy.IPRule{
						Addresses: []string{"60.0.0.0/24"},
						Ports:     nil,
						Protocols: []string{constants.AllProtoString},
						Policy: &policy.FlowPolicy{
							Action:    policy.Accept | policy.Log,
							ServiceID: "a3",
							PolicyID:  "123a",
						},
					},
					policy.IPRule{
						Addresses: []string{"30.0.0.0/24"},
						Ports:     []string{"80"},
						Protocols: []string{"TCP"},
						Policy: &policy.FlowPolicy{
							Action:    policy.Reject,
							ServiceID: "s1",
							PolicyID:  "1",
						},
					},
					policy.IPRule{
						Addresses: []string{"30.0.0.0/24"},
						Ports:     []string{"443"},
						Protocols: []string{"UDP"},
						Policy: &policy.FlowPolicy{
							Action:    policy.Accept,
							ServiceID: "s2",
							PolicyID:  "2",
						},
					},
					policy.IPRule{
						Addresses: []string{"50.0.0.0/24"},
						Ports:     []string{},
						Protocols: []string{"icmp"},
						Policy: &policy.FlowPolicy{
							Action:    policy.Accept,
							ServiceID: "s3",
							PolicyID:  "3",
						},
					},
					policy.IPRule{
						Addresses: []string{"60.0.0.0/24"},
						Ports:     nil,
						Protocols: []string{constants.AllProtoString},
						Policy: &policy.FlowPolicy{
							Action:    policy.Reject | policy.Log,
							ServiceID: "a3",
							PolicyID:  "123a",
							RuleName:  "rockstars forev",
						},
					},
				}
				netACLs := policy.IPRuleList{
					policy.IPRule{
						Addresses: []string{"60.0.0.0/24"},
						Ports:     nil,
						Protocols: []string{constants.AllProtoString},
						Policy: &policy.FlowPolicy{
							Action:    policy.Accept | policy.Log,
							ServiceID: "a3",
							PolicyID:  "123a",
						},
					},
					policy.IPRule{
						Addresses: []string{"40.0.0.0/24"},
						Ports:     []string{"80"},
						Protocols: []string{"TCP"},
						Policy: &policy.FlowPolicy{
							Action:    policy.Reject,
							ServiceID: "s3",
							PolicyID:  "1",
						},
					},
					policy.IPRule{
						Addresses: []string{"40.0.0.0/24"},
						Ports:     []string{"443"},
						Protocols: []string{"UDP"},
						Policy: &policy.FlowPolicy{
							Action:    policy.Accept,
							ServiceID: "s4",
							PolicyID:  "2",
						},
					},
					policy.IPRule{
						Addresses: []string{"60.0.0.0/24"},
						Ports:     nil,
						Protocols: []string{constants.AllProtoString},
						Policy: &policy.FlowPolicy{
							Action:    policy.Reject | policy.Log,
							ServiceID: "a3",
							PolicyID:  "123a",
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
					//"/ns1", common.HostPU)
					"/ns1", common.HostNetworkPU)
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
				i.iptv4.ipsetmanager.RegisterExternalNets("pu1", iprules) // nolint
				err = i.iptv4.ConfigureRules(0,
					"pu1", puInfo)
				So(err, ShouldBeNil)
				err = i.iptv4.ipsetmanager.AddPortToServerPortSet("pu1",
					"8080")
				So(err, ShouldBeNil)
				t := i.iptv4.impl.RetrieveTable()

				for chain, rules := range t["mangle"] {
					So(expectedMangleAfterPUInsertV4, ShouldContainKey, chain)
					So(rules, ShouldResemble, expectedMangleAfterPUInsertV4[chain])
				}

				for chain, rules := range t["nat"] {
					So(expectedNATAfterPUInsertV4, ShouldContainKey, chain)
					So(rules, ShouldResemble, expectedNATAfterPUInsertV4[chain])
				}

				Convey("When I update the policy, the update must result in correct state", func() {
					appACLs := policy.IPRuleList{
						policy.IPRule{
							Addresses: []string{"30.0.0.0/24"},
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
							Addresses: []string{"40.0.0.0/24"},
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
						//"/ns1", common.HostPU)
						"/ns1", common.HostNetworkPU)
					puInfoUpdated.Policy = policyrules
					puInfoUpdated.Runtime.SetOptions(policy.OptionsType{
						CgroupMark: "10",
					})

					var iprules policy.IPRuleList

					iprules = append(iprules, puInfoUpdated.Policy.ApplicationACLs()...)
					iprules = append(iprules, puInfoUpdated.Policy.NetworkACLs()...)

					i.iptv4.ipsetmanager.RegisterExternalNets("pu1", iprules) // nolint

					err := i.iptv4.UpdateRules(1,
						"pu1", puInfoUpdated, puInfo)
					So(err, ShouldBeNil)

					i.iptv4.ipsetmanager.DestroyUnusedIPsets()

					t := i.iptv4.impl.RetrieveTable()
					for chain, rules := range t["mangle"] {
						So(expectedMangleAfterPUUpdateV4, ShouldContainKey, chain)
						So(rules, ShouldResemble, expectedMangleAfterPUUpdateV4[chain])
					}

					Convey("When I delete the same rule, the chains must be restored in the global state", func() {
						err = i.iptv4.ipsetmanager.DeletePortFromServerPortSet("pu1",
							"8080")
						err := i.iptv4.DeleteRules(1,
							"pu1",
							"0",
							"5000",
							"10",
							"", puInfoUpdated)
						i.iptv4.ipsetmanager.RemoveExternalNets("pu1")
						So(err, ShouldBeNil)
						So(err, ShouldBeNil)
						t := i.iptv4.impl.RetrieveTable()
						So(t["mangle"], ShouldNotBeNil)
						So(t["nat"], ShouldNotBeNil)
						for chain, rules := range t["mangle"] {
							So(expectedGlobalMangleChainsV4, ShouldContainKey, chain)
							So(rules, ShouldResemble, expectedGlobalMangleChainsV4[chain])
						}

						for chain, rules := range t["nat"] {
							if len(rules) > 0 {
								So(expectedGlobalNATChainsV4, ShouldContainKey, chain)
								So(rules, ShouldResemble, expectedGlobalNATChainsV4[chain])
							}
						}
					})
				})
			})
		})
	})
}

var (
	expectedGlobalMangleChainsV6 = map[string][]string{
		"TRI-Nfq-IN": {
			"-j MARK --set-mark 67",
			"-m mark --mark 67 -j NFQUEUE --queue-balance 0:3 --queue-bypass",
		},
		"TRI-Nfq-OUT": {
			"-j MARK --set-mark 0",
			"-m mark --mark 0 -j NFQUEUE --queue-balance 0:3 --queue-bypass",
		},
		"INPUT": {
			"-m set ! --match-set TRI-v6-Excluded src -j TRI-Net",
		},
		"OUTPUT": {
			"-m set ! --match-set TRI-v6-Excluded dst -j TRI-App",
		},
		"TRI-App": {
			"-p udp --dport 53 -j ACCEPT",
			"-m mark --mark 66 -j CONNMARK --set-mark 61167",
			"-p tcp -m mark --mark 66 -j ACCEPT",
			"-p udp --dport 53 -m mark --mark 0x40 -j CONNMARK --set-mark 61167",
			"-j TRI-Prx-App",
			"-m connmark --mark 61167 -j ACCEPT",
			"-p udp -m connmark --mark 61165 -m comment --comment Drop UDP ACL -j DROP",
			"-m connmark --mark 61166 -p tcp ! --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j ACCEPT",
			"-m connmark --mark 61166 -p udp -j ACCEPT",
			"-m mark --mark 1073741922 -j ACCEPT",
			"-p tcp -m tcp --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j TRI-Nfq-OUT",
			"-j TRI-Pid-App",
			"-j TRI-Svc-App",
			"-j TRI-Hst-App",
		},
		"TRI-Net": {
			"-p udp --sport 53 -j ACCEPT",
			"-j TRI-Prx-Net",
			"-p tcp -m mark --mark 66 -j CONNMARK --set-mark 61167",
			"-p tcp -m mark --mark 66 -j ACCEPT",
			"-m connmark --mark 61167 -p tcp ! --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j ACCEPT",
			"-m set --match-set TRI-v6-TargetTCP src -p tcp -m tcp --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j TRI-Nfq-IN",
			"-p udp -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -j TRI-Nfq-IN",
			"-p udp -m connmark --mark 61165 -m comment --comment Drop UDP ACL -j DROP",
			"-m connmark --mark 61166 -p udp -j ACCEPT",
			"-j TRI-Pid-Net",
			"-j TRI-Svc-Net",
			"-j TRI-Hst-Net",
		},
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
			"-m mark --mark 0x40 -j ACCEPT",
		},
		"TRI-Redir-Net": {
			"-m mark --mark 0x40 -j ACCEPT",
		},
	}

	expectedMangleAfterPUInsertV6 = map[string][]string{
		"TRI-Nfq-IN": {
			"-j MARK --set-mark 67",
			"-m mark --mark 67 -j NFQUEUE --queue-balance 0:3 --queue-bypass",
		},
		"TRI-Nfq-OUT": {
			"-j MARK --set-mark 0",
			"-m mark --mark 0 -j NFQUEUE --queue-balance 0:3 --queue-bypass",
		},
		"INPUT": {
			"-m set ! --match-set TRI-v6-Excluded src -j TRI-Net",
		},
		"OUTPUT": {
			"-m set ! --match-set TRI-v6-Excluded dst -j TRI-App",
		},
		"TRI-App": {
			"-p udp --dport 53 -j ACCEPT",
			"-m mark --mark 66 -j CONNMARK --set-mark 61167",
			"-p tcp -m mark --mark 66 -j ACCEPT",
			"-p udp --dport 53 -m mark --mark 0x40 -j CONNMARK --set-mark 61167",
			"-j TRI-Prx-App", "-m connmark --mark 61167 -j ACCEPT",
			"-p udp -m connmark --mark 61165 -m comment --comment Drop UDP ACL -j DROP",
			"-m connmark --mark 61166 -p tcp ! --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j ACCEPT",
			"-m connmark --mark 61166 -p udp -j ACCEPT",
			"-m mark --mark 1073741922 -j ACCEPT",
			"-p tcp -m tcp --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j TRI-Nfq-OUT",
			"-j TRI-Pid-App",
			"-j TRI-Svc-App",
			"-j TRI-Hst-App",
		},
		"TRI-Net": {
			"-p udp --sport 53 -j ACCEPT",
			"-j TRI-Prx-Net",
			"-p tcp -m mark --mark 66 -j CONNMARK --set-mark 61167",
			"-p tcp -m mark --mark 66 -j ACCEPT",
			"-m connmark --mark 61167 -p tcp ! --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j ACCEPT",
			"-m set --match-set TRI-v6-TargetTCP src -p tcp -m tcp --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j TRI-Nfq-IN",
			"-p udp -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -j TRI-Nfq-IN",
			"-p udp -m connmark --mark 61165 -m comment --comment Drop UDP ACL -j DROP",
			"-m connmark --mark 61166 -p udp -j ACCEPT",
			"-j TRI-Pid-Net",
			"-j TRI-Svc-Net",
			"-j TRI-Hst-Net",
		},
		"TRI-Pid-App": {},
		"TRI-Pid-Net": {},
		"TRI-Prx-App": {
			"-m mark --mark 0x40 -j ACCEPT",
			"-p tcp -m tcp --sport 0 -j ACCEPT",
			"-p udp -m udp --sport 0 -j ACCEPT",
			"-p tcp -m set --match-set TRI-v6-Proxy-pu19gtV-srv src -j ACCEPT",
			"-p tcp -m set --match-set TRI-v6-Proxy-pu19gtV-dst dst,dst -m mark ! --mark 0x40 -j ACCEPT",
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
		"TRI-Svc-App": {
			"-p icmp -m comment --comment Server-specific-chain -j MARK --set-mark 10",
			"-p tcp -m multiport --source-ports 9000 -m comment --comment Server-specific-chain -j MARK --set-mark 10",
			"-p tcp -m multiport --source-ports 9000 -m comment --comment Server-specific-chain -j TRI-App-pu1N7uS6--0",
			"-p udp -m multiport --source-ports 5000 -m comment --comment Server-specific-chain -j MARK --set-mark 10",
			"-p udp -m mark --mark 10 -m addrtype --src-type LOCAL -m addrtype --dst-type LOCAL -m state --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 913787369:default:default:3",
			"-m comment --comment traffic-same-pu -p udp -m mark --mark 10 -m addrtype --src-type LOCAL -m addrtype --dst-type LOCAL -j ACCEPT",
			"-p udp -m multiport --source-ports 5000 -m comment --comment Server-specific-chain -j TRI-App-pu1N7uS6--0",
		},
		"TRI-Svc-Net": {
			"-p tcp -m multiport --destination-ports 9000 -m comment --comment Container-specific-chain -j TRI-Net-pu1N7uS6--0",
			"-m comment --comment traffic-same-pu -p udp -m mark --mark 10 -m addrtype --src-type LOCAL -m addrtype --dst-type LOCAL -j ACCEPT",
			"-p udp -m multiport --destination-ports 5000 -m comment --comment Container-specific-chain -j TRI-Net-pu1N7uS6--0",
		},

		"TRI-Net-pu1N7uS6--0": {
			"-p tcp -m tcp --tcp-option 34 -m tcp --tcp-flags FIN,RST,URG,PSH NONE -j TRI-Nfq-IN",
			"-p UDP -m set --match-set TRI-v6-ext-6zlJIvP3B68= src -m state --state ESTABLISHED -m connmark --mark 61167 -j ACCEPT",
			"-p TCP -m set --match-set TRI-v6-ext-w5frVvhsnpU= src -m state --state NEW --match multiport --dports 80 -j DROP",
			"-p UDP -m set --match-set TRI-v6-ext-IuSLsD1R-mE= src -m string ! --string n30njxq7bmiwr6dtxq --algo bm --to 128 --match multiport --dports 443 -j CONNMARK --set-mark 61167",
			"-p UDP -m set --match-set TRI-v6-ext-IuSLsD1R-mE= src -m string ! --string n30njxq7bmiwr6dtxq --algo bm --to 128 --match multiport --dports 443 -j ACCEPT",
			"-p icmp -j NFQUEUE --queue-balance 0:3",
			"-p tcp -m set --match-set TRI-v6-TargetTCP src -m tcp --tcp-flags SYN NONE -j TRI-Nfq-IN",
			"-p udp -m set --match-set TRI-v6-TargetUDP src --match limit --limit 1000/s -j TRI-Nfq-IN",
			"-p tcp -m state --state ESTABLISHED -m comment --comment TCP-Established-Connections -j ACCEPT",
			"-s ::/0 -m state --state NEW -j NFLOG --nflog-group 11 --nflog-prefix 913787369:default:default:6",
			"-s ::/0 -m state ! --state NEW -j NFLOG --nflog-group 11 --nflog-prefix 913787369:default:default:10",
			"-s ::/0 -j DROP",
		},
		"TRI-App-pu1N7uS6--0": {
			"-p TCP -m set --match-set TRI-v6-ext-uNdc0vdcFZA= dst -m state --state NEW --match multiport --dports 80 -j DROP",
			"-p UDP -m set --match-set TRI-v6-ext-6zlJIvP3B68= dst -m string ! --string n30njxq7bmiwr6dtxq --algo bm --to 128 -m set ! --match-set TRI-v6-TargetUDP dst --match multiport --dports 443 -j CONNMARK --set-mark 61167",
			"-p UDP -m set --match-set TRI-v6-ext-6zlJIvP3B68= dst -m string ! --string n30njxq7bmiwr6dtxq --algo bm --to 128 -m set ! --match-set TRI-v6-TargetUDP dst --match multiport --dports 443 -j ACCEPT",
			"-p icmpv6 -m set --match-set TRI-v6-ext-w5frVvhsnpU= dst -j ACCEPT",
			"-p UDP -m set --match-set TRI-v6-ext-IuSLsD1R-mE= dst -m state --state ESTABLISHED -m connmark --mark 61167 -j ACCEPT",
			"-p icmp -j NFQUEUE --queue-balance 0:3",
			"-m set --match-set TRI-v6-TargetTCP dst -p tcp -m tcp --tcp-flags FIN FIN -j ACCEPT",
			"-m set --match-set TRI-v6-TargetTCP dst -p tcp -j MARK --set-mark 40",
			"-p udp -m set --match-set TRI-v6-TargetUDP dst -j MARK --set-mark 40",
			"-m mark --mark 40 -j NFQUEUE --queue-balance 0:3 --queue-bypass",
			"-p tcp -m state --state ESTABLISHED -m comment --comment TCP-Established-Connections -j ACCEPT",
			"-p udp -m state --state ESTABLISHED -m comment --comment UDP-Established-Connections -j ACCEPT",
			"-d ::/0 -m state --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 913787369:default:default:6",
			"-d ::/0 -m state ! --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 913787369:default:default:10",
			"-d ::/0 -j DROP",
		},
	}

	expectedNATAfterPUInsertV6 = map[string][]string{
		"PREROUTING": {
			"-p tcp -m addrtype --dst-type LOCAL -m set ! --match-set TRI-v6-Excluded src -j TRI-Redir-Net",
		},
		"OUTPUT": {
			"-m set ! --match-set TRI-v6-Excluded dst -j TRI-Redir-App",
		},
		"TRI-Redir-App": {
			"-m mark --mark 0x40 -j ACCEPT",
			"-p tcp -m set --match-set TRI-v6-Proxy-pu19gtV-dst dst,dst -m mark ! --mark 0x40 -m multiport --source-ports 9000 -j REDIRECT --to-ports 0",
			"-p udp --dport 53 -m mark ! --mark 0x40 -j REDIRECT --to-ports 0",
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
		"TRI-Nfq-IN": {
			"-j MARK --set-mark 67",
			"-m mark --mark 67 -j NFQUEUE --queue-balance 0:3 --queue-bypass",
		},
		"TRI-Nfq-OUT": {
			"-j MARK --set-mark 0",
			"-m mark --mark 0 -j NFQUEUE --queue-balance 0:3 --queue-bypass",
		},
		"INPUT": {
			"-m set ! --match-set TRI-v6-Excluded src -j TRI-Net",
		},
		"OUTPUT": {
			"-m set ! --match-set TRI-v6-Excluded dst -j TRI-App",
		},
		"TRI-App": {
			"-p udp --dport 53 -j ACCEPT",
			"-m mark --mark 66 -j CONNMARK --set-mark 61167",
			"-p tcp -m mark --mark 66 -j ACCEPT",
			"-p udp --dport 53 -m mark --mark 0x40 -j CONNMARK --set-mark 61167",
			"-j TRI-Prx-App",
			"-m connmark --mark 61167 -j ACCEPT",
			"-p udp -m connmark --mark 61165 -m comment --comment Drop UDP ACL -j DROP",
			"-m connmark --mark 61166 -p tcp ! --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j ACCEPT",
			"-m connmark --mark 61166 -p udp -j ACCEPT",
			"-m mark --mark 1073741922 -j ACCEPT",
			"-p tcp -m tcp --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j TRI-Nfq-OUT",
			"-j TRI-Pid-App",
			"-j TRI-Svc-App",
			"-j TRI-Hst-App",
		},
		"TRI-Net": {
			"-p udp --sport 53 -j ACCEPT",
			"-j TRI-Prx-Net",
			"-p tcp -m mark --mark 66 -j CONNMARK --set-mark 61167",
			"-p tcp -m mark --mark 66 -j ACCEPT",
			"-m connmark --mark 61167 -p tcp ! --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j ACCEPT",
			"-m set --match-set TRI-v6-TargetTCP src -p tcp -m tcp --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j TRI-Nfq-IN",
			"-p udp -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -j TRI-Nfq-IN",
			"-p udp -m connmark --mark 61165 -m comment --comment Drop UDP ACL -j DROP",
			"-m connmark --mark 61166 -p udp -j ACCEPT",
			"-j TRI-Pid-Net",
			"-j TRI-Svc-Net",
			"-j TRI-Hst-Net",
		},
		"TRI-Pid-App": {},
		"TRI-Pid-Net": {},
		"TRI-Prx-App": {
			"-m mark --mark 0x40 -j ACCEPT",
			"-p tcp -m tcp --sport 0 -j ACCEPT",
			"-p udp -m udp --sport 0 -j ACCEPT",
			"-p tcp -m set --match-set TRI-v6-Proxy-pu19gtV-srv src -j ACCEPT",
			"-p tcp -m set --match-set TRI-v6-Proxy-pu19gtV-dst dst,dst -m mark ! --mark 0x40 -j ACCEPT",
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
			"-p icmp -j NFQUEUE --queue-balance 0:3",
			"-p tcp -m set --match-set TRI-v6-TargetTCP src -m tcp --tcp-flags SYN NONE -j TRI-Nfq-IN",
			"-p udp -m set --match-set TRI-v6-TargetUDP src --match limit --limit 1000/s -j TRI-Nfq-IN",
			"-p tcp -m state --state ESTABLISHED -m comment --comment TCP-Established-Connections -j ACCEPT",
			"-s ::/0 -m state --state NEW -j NFLOG --nflog-group 11 --nflog-prefix 913787369:default:default:6",
			"-s ::/0 -m state ! --state NEW -j NFLOG --nflog-group 11 --nflog-prefix 913787369:default:default:10",
			"-s ::/0 -j DROP",
		},
		"TRI-App-pu1N7uS6--1": {
			"-p TCP -m set --match-set TRI-v6-ext-uNdc0vdcFZA= dst -m state --state NEW --match multiport --dports 80 -j DROP",
			"-p icmp -j NFQUEUE --queue-balance 0:3",
			"-m set --match-set TRI-v6-TargetTCP dst -p tcp -m tcp --tcp-flags FIN FIN -j ACCEPT",
			"-m set --match-set TRI-v6-TargetTCP dst -p tcp -j MARK --set-mark 40",
			"-p udp -m set --match-set TRI-v6-TargetUDP dst -j MARK --set-mark 40",
			"-m mark --mark 40 -j NFQUEUE --queue-balance 0:3 --queue-bypass",
			"-p tcp -m state --state ESTABLISHED -m comment --comment TCP-Established-Connections -j ACCEPT",
			"-p udp -m state --state ESTABLISHED -m comment --comment UDP-Established-Connections -j ACCEPT",
			"-d ::/0 -m state --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 913787369:default:default:6",
			"-d ::/0 -m state ! --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 913787369:default:default:10",
			"-d ::/0 -j DROP",
		},
	}
)

func Test_Rhel6ConfigureRulesV6(t *testing.T) {

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
					"/ns1", common.HostNetworkPU)
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
						"/ns1", common.HostNetworkPU)
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
