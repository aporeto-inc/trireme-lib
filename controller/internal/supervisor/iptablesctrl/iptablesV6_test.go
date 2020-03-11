package iptablesctrl

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/aporeto-inc/go-ipset/ipset"
	"github.com/magiconair/properties/assert"
	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/controller/constants"
	provider "go.aporeto.io/trireme-lib/controller/pkg/aclprovider"
	"go.aporeto.io/trireme-lib/controller/runtime"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/portspec"
)

func TestNewInstanceV6(t *testing.T) {

	Convey("When I create a new iptables instance", t, func() {
		Convey("If I create a remote implemenetation and iptables exists", func() {
			ipsv4 := provider.NewTestIpsetProvider()
			ipsv6 := provider.NewTestIpsetProvider()
			iptv4 := provider.NewTestIptablesProvider()
			iptv6 := provider.NewTestIptablesProvider()

			i, err := createTestInstance(ipsv4, ipsv6, iptv4, iptv6, constants.RemoteContainer)
			Convey("It should succeed", func() {
				So(i, ShouldNotBeNil)
				So(err, ShouldBeNil)
			})
		})
	})

	Convey("When I create a new iptables instance", t, func() {
		Convey("If I create a Linux server implemenetation and iptables exists", func() {
			ipsv4 := provider.NewTestIpsetProvider()
			ipsv6 := provider.NewTestIpsetProvider()
			iptv4 := provider.NewTestIptablesProvider()
			iptv6 := provider.NewTestIptablesProvider()

			i, err := createTestInstance(ipsv4, ipsv6, iptv4, iptv6, constants.LocalServer)
			Convey("It should succeed", func() {
				So(i, ShouldNotBeNil)
				So(err, ShouldBeNil)
			})
		})
	})
}

func Test_NegativeConfigureRulesV6(t *testing.T) {

	Convey("Given a valid instance", t, func() {
		ipsv4 := provider.NewTestIpsetProvider()
		ipsv6 := provider.NewTestIpsetProvider()
		iptv4 := provider.NewTestIptablesProvider()
		iptv6 := provider.NewTestIptablesProvider()

		i, err := createTestInstance(ipsv4, ipsv6, iptv4, iptv6, constants.LocalServer)
		So(err, ShouldBeNil)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		err = i.Run(ctx)
		So(err, ShouldBeNil)
		cfg := &runtime.Configuration{}
		i.SetTargetNetworks(cfg) //nolint

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
		)
		containerinfo := policy.NewPUInfo("Context", "/ns1", common.ContainerPU)
		containerinfo.Policy = policyrules
		containerinfo.Runtime = policy.NewPURuntimeWithDefaults()
		containerinfo.Runtime.SetOptions(policy.OptionsType{
			CgroupMark: "10",
		})

		Convey("When I configure the rules with no errors, it should succeed", func() {
			err := i.ConfigureRules(1, "ID", containerinfo)
			So(err, ShouldBeNil)
		})

		Convey("When I configure the rules and the proxy set fails, it should error", func() {
			ipsv6.MockNewIpset(t, func(name, hash string, p *ipset.Params) (provider.Ipset, error) {
				return nil, fmt.Errorf("error")
			})
			err := i.ConfigureRules(1, "ID", containerinfo)
			So(err, ShouldNotBeNil)
		})

		Convey("When I configure the rules and acls fail, it should error", func() {
			iptv6.MockAppend(t, func(table, chain string, rulespec ...string) error {
				return fmt.Errorf("error")
			})
			err := i.ConfigureRules(1, "ID", containerinfo)
			So(err, ShouldNotBeNil)
		})

		Convey("When I configure the rules and commit fails, it should error", func() {
			iptv6.MockCommit(t, func() error {
				return fmt.Errorf("error")
			})
			err := i.iptv6.ConfigureRules(1, "ID", containerinfo)
			So(err, ShouldNotBeNil)
		})
	})
}

var (
	expectedGlobalMangleChainsV6 = map[string][]string{
		"INPUT": {
			"-m set ! --match-set TRI-v6-Excluded src -j TRI-Net",
		},
		"OUTPUT": {
			"-m set ! --match-set TRI-v6-Excluded dst -j TRI-App",
		},
		"TRI-App": {
			"-j TRI-Prx-App",
			"-m mark --mark 1073741922 -j ACCEPT",
			"-m connmark --mark 61167 -j ACCEPT",
			"-m connmark --mark 61166 -p tcp ! --tcp-flags SYN,ACK SYN,ACK -j ACCEPT",
			"-j TRI-UID-App",
			"-p tcp -m set --match-set TRI-v6-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -j MARK --set-mark 99",
			"-p tcp -m set --match-set TRI-v6-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-balance 8:11 --queue-bypass",
			"-j TRI-Pid-App",
			"-j TRI-Svc-App",
			"-j TRI-Hst-App",
		},
		"TRI-Net": {
			"-j TRI-Prx-Net",
			"-p udp -m set --match-set TRI-v6-TargetUDP src -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -j NFQUEUE --queue-bypass --queue-balance 24:27",
			"-m set --match-set TRI-v6-TargetTCP src -p tcp --tcp-flags ALL ACK -m tcp --tcp-option 34 -j NFQUEUE --queue-balance 20:23",
			"-m connmark --mark 61167 -j ACCEPT",
			"-m connmark --mark 61166 -p tcp ! --tcp-flags SYN,ACK SYN,ACK -j ACCEPT",
			"-j TRI-UID-Net",
			"-m set --match-set TRI-v6-TargetTCP src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-balance 24:27 --queue-bypass",
			"-p tcp -m set --match-set TRI-v6-TargetTCP src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -j NFQUEUE --queue-balance 16:19 --queue-bypass",
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
		"TRI-UID-App": {},
		"TRI-UID-Net": {},
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

	expectedGlobalIPSetsV6 = map[string][]string{
		"TRI" + "-v6-" + targetTCPNetworkSet: {"::/1", "8000::/1"},
		"TRI" + "-v6-" + targetUDPNetworkSet: {"1120::/64"},
		"TRI" + "-v6-" + excludedNetworkSet:  {"::1"},
	}

	expectedMangleAfterPUInsertV6 = map[string][]string{
		"INPUT": {
			"-m set ! --match-set TRI-v6-Excluded src -j TRI-Net",
		},
		"OUTPUT": {
			"-m set ! --match-set TRI-v6-Excluded dst -j TRI-App",
		},
		"TRI-App": {
			"-j TRI-Prx-App",
			"-m mark --mark 1073741922 -j ACCEPT",
			"-m connmark --mark 61167 -j ACCEPT",
			"-m connmark --mark 61166 -p tcp ! --tcp-flags SYN,ACK SYN,ACK -j ACCEPT",
			"-j TRI-UID-App",
			"-p tcp -m set --match-set TRI-v6-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -j MARK --set-mark 99",
			"-p tcp -m set --match-set TRI-v6-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-balance 8:11 --queue-bypass",
			"-j TRI-Pid-App",
			"-j TRI-Svc-App",
			"-j TRI-Hst-App",
		},
		"TRI-Net": {
			"-j TRI-Prx-Net",
			"-p udp -m set --match-set TRI-v6-TargetUDP src -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -j NFQUEUE --queue-bypass --queue-balance 24:27",
			"-m set --match-set TRI-v6-TargetTCP src -p tcp --tcp-flags ALL ACK -m tcp --tcp-option 34 -j NFQUEUE --queue-balance 20:23",
			"-m connmark --mark 61167 -j ACCEPT",
			"-m connmark --mark 61166 -p tcp ! --tcp-flags SYN,ACK SYN,ACK -j ACCEPT",
			"-j TRI-UID-Net",
			"-m set --match-set TRI-v6-TargetTCP src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-balance 24:27 --queue-bypass",
			"-p tcp -m set --match-set TRI-v6-TargetTCP src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -j NFQUEUE --queue-balance 16:19 --queue-bypass",
			"-j TRI-Pid-Net",
			"-j TRI-Svc-Net",
			"-j TRI-Hst-Net",
		},
		"TRI-Pid-App": {
			"-m cgroup --cgroup 10 -m comment --comment PU-Chain -j MARK --set-mark 10",
			"-m mark --mark 10 -m comment --comment PU-Chain -j TRI-App-pu1N7uS6--0",
		},
		"TRI-Pid-Net": {
			"-p tcp -m multiport --destination-ports 9000 -m comment --comment PU-Chain -j TRI-Net-pu1N7uS6--0", "-p udp -m multiport --destination-ports 5000 -m comment --comment PU-Chain -j TRI-Net-pu1N7uS6--0",
		},
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
		"TRI-UID-App": {},
		"TRI-UID-Net": {},

		"TRI-Net-pu1N7uS6--0": {
			"-p UDP -m set --match-set TRI-v6-ext-6zlJIvP3B68= src -m state --state ESTABLISHED -j ACCEPT",
			"-p TCP -m set --match-set TRI-v6-ext-w5frVvhsnpU= src -m state --state NEW -m set ! --match-set TRI-v6-TargetTCP src --match multiport --dports 80 -j DROP",
			"-p UDP -m set --match-set TRI-v6-ext-IuSLsD1R-mE= src --match multiport --dports 443 -j ACCEPT",
			"-p icmpv6 -j ACCEPT",
			"-p tcp -m set --match-set TRI-v6-TargetTCP src -m tcp --tcp-flags SYN,ACK SYN -j NFQUEUE --queue-balance 16:19",
			"-p tcp -m set --match-set TRI-v6-TargetTCP src -m tcp --tcp-flags SYN,ACK ACK -j NFQUEUE --queue-balance 20:23",
			"-p udp -m set --match-set TRI-v6-TargetUDP src --match limit --limit 1000/s -j NFQUEUE --queue-balance 16:19",
			"-p tcp -m state --state ESTABLISHED -m comment --comment TCP-Established-Connections -j ACCEPT",
			"-s ::/0 -m state --state NEW -j NFLOG --nflog-group 11 --nflog-prefix 913787369:default:default:6",
			"-s ::/0 -m state ! --state NEW -j NFLOG --nflog-group 11 --nflog-prefix 913787369:default:default:10",
			"-s ::/0 -j DROP",
		},

		"TRI-App-pu1N7uS6--0": {
			"-p TCP -m set --match-set TRI-v6-ext-uNdc0vdcFZA= dst -m state --state NEW -m set ! --match-set TRI-v6-TargetTCP dst --match multiport --dports 80 -j DROP",
			"-p UDP -m set --match-set TRI-v6-ext-6zlJIvP3B68= dst --match multiport --dports 443 -j ACCEPT",
			"-p icmpv6 -m set --match-set TRI-v6-ext-w5frVvhsnpU= dst -j ACCEPT",
			"-p UDP -m set --match-set TRI-v6-ext-IuSLsD1R-mE= dst -m state --state ESTABLISHED -j ACCEPT",
			"-p icmpv6 -j ACCEPT",
			"-p tcp -m tcp --tcp-flags SYN,ACK SYN -j NFQUEUE --queue-balance 0:3",
			"-p tcp -m tcp --tcp-flags SYN,ACK ACK -j NFQUEUE --queue-balance 4:7",
			"-p udp -m set --match-set TRI-v6-TargetUDP dst -j NFQUEUE --queue-balance 0:3",
			"-p udp -m set --match-set TRI-v6-TargetUDP dst -m state --state ESTABLISHED -m comment --comment UDP-Established-Connections -j ACCEPT",
			"-p tcp -m state --state ESTABLISHED -m comment --comment TCP-Established-Connections -j ACCEPT",
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

	expectedIPSetsAfterPUInsertV6 = map[string][]string{
		"TRI" + "-v6-" + targetTCPNetworkSet: {"::/1", "8000::/1"},
		"TRI" + "-v6-" + targetUDPNetworkSet: {"1120::/64"},
		"TRI" + "-v6-" + excludedNetworkSet:  {"::1"},
		"TRI-v6-ProcPort-pu19gtV":            {},
		"TRI-v6-ext-6zlJIvP3B68=":            {"1120::/64"},
		"TRI-v6-ext-uNdc0vdcFZA=":            {"1120::/64"},
		"TRI-v6-ext-w5frVvhsnpU=":            {"1122::/64"},
		"TRI-v6-ext-IuSLsD1R-mE=":            {"1122::/64"},
		"TRI-v6-Proxy-pu19gtV-dst":           {},
		"TRI-v6-Proxy-pu19gtV-srv":           {},
	}

	expectedMangleAfterPUUpdateV6 = map[string][]string{
		"INPUT": {
			"-m set ! --match-set TRI-v6-Excluded src -j TRI-Net",
		},
		"OUTPUT": {
			"-m set ! --match-set TRI-v6-Excluded dst -j TRI-App",
		},
		"TRI-App": {
			"-j TRI-Prx-App",
			"-m mark --mark 1073741922 -j ACCEPT",
			"-m connmark --mark 61167 -j ACCEPT",
			"-m connmark --mark 61166 -p tcp ! --tcp-flags SYN,ACK SYN,ACK -j ACCEPT",
			"-j TRI-UID-App",
			"-p tcp -m set --match-set TRI-v6-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -j MARK --set-mark 99",
			"-p tcp -m set --match-set TRI-v6-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-balance 8:11 --queue-bypass",
			"-j TRI-Pid-App",
			"-j TRI-Svc-App",
			"-j TRI-Hst-App",
		},
		"TRI-Net": {
			"-j TRI-Prx-Net",
			"-p udp -m set --match-set TRI-v6-TargetUDP src -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -j NFQUEUE --queue-bypass --queue-balance 24:27",
			"-m set --match-set TRI-v6-TargetTCP src -p tcp --tcp-flags ALL ACK -m tcp --tcp-option 34 -j NFQUEUE --queue-balance 20:23",
			"-m connmark --mark 61167 -j ACCEPT",
			"-m connmark --mark 61166 -p tcp ! --tcp-flags SYN,ACK SYN,ACK -j ACCEPT",
			"-j TRI-UID-Net",
			"-m set --match-set TRI-v6-TargetTCP src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-balance 24:27 --queue-bypass",
			"-p tcp -m set --match-set TRI-v6-TargetTCP src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -j NFQUEUE --queue-balance 16:19 --queue-bypass",
			"-j TRI-Pid-Net",
			"-j TRI-Svc-Net",
			"-j TRI-Hst-Net",
		},
		"TRI-Pid-App": {
			"-m cgroup --cgroup 10 -m comment --comment PU-Chain -j MARK --set-mark 10",
			"-m mark --mark 10 -m comment --comment PU-Chain -j TRI-App-pu1N7uS6--1",
		},
		"TRI-Pid-Net": {
			"-p tcp -m set --match-set TRI-v6-ProcPort-pu19gtV dst -m comment --comment PU-Chain -j TRI-Net-pu1N7uS6--1",
		},
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
		"TRI-UID-App": {},
		"TRI-UID-Net": {},

		"TRI-Net-pu1N7uS6--1": {
			"-p TCP -m set --match-set TRI-v6-ext-w5frVvhsnpU= src -m state --state NEW -m set ! --match-set TRI-v6-TargetTCP src --match multiport --dports 80 -j DROP",
			"-p icmpv6 -j ACCEPT",
			"-p tcp -m set --match-set TRI-v6-TargetTCP src -m tcp --tcp-flags SYN,ACK SYN -j NFQUEUE --queue-balance 16:19",
			"-p tcp -m set --match-set TRI-v6-TargetTCP src -m tcp --tcp-flags SYN,ACK ACK -j NFQUEUE --queue-balance 20:23",
			"-p udp -m set --match-set TRI-v6-TargetUDP src --match limit --limit 1000/s -j NFQUEUE --queue-balance 16:19",
			"-p tcp -m state --state ESTABLISHED -m comment --comment TCP-Established-Connections -j ACCEPT",
			"-s ::/0 -m state --state NEW -j NFLOG --nflog-group 11 --nflog-prefix 913787369:default:default:6",
			"-s ::/0 -m state ! --state NEW -j NFLOG --nflog-group 11 --nflog-prefix 913787369:default:default:10",
			"-s ::/0 -j DROP",
		},

		"TRI-App-pu1N7uS6--1": {
			"-p TCP -m set --match-set TRI-v6-ext-uNdc0vdcFZA= dst -m state --state NEW -m set ! --match-set TRI-v6-TargetTCP dst --match multiport --dports 80 -j DROP",
			"-p icmpv6 -j ACCEPT",
			"-p tcp -m tcp --tcp-flags SYN,ACK SYN -j NFQUEUE --queue-balance 0:3",
			"-p tcp -m tcp --tcp-flags SYN,ACK ACK -j NFQUEUE --queue-balance 4:7",
			"-p udp -m set --match-set TRI-v6-TargetUDP dst -j NFQUEUE --queue-balance 0:3",
			"-p udp -m set --match-set TRI-v6-TargetUDP dst -m state --state ESTABLISHED -m comment --comment UDP-Established-Connections -j ACCEPT",
			"-p tcp -m state --state ESTABLISHED -m comment --comment TCP-Established-Connections -j ACCEPT",
			"-d ::/0 -m state --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 913787369:default:default:6",
			"-d ::/0 -m state ! --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 913787369:default:default:10",
			"-d ::/0 -j DROP",
		},
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

		iptv4 := provider.NewCustomBatchProvider(&baseIpt{}, commitFunc, []string{"nat", "mangle"})
		So(iptv4, ShouldNotBeNil)

		iptv6 := provider.NewCustomBatchProvider(&baseIpt{}, commitFunc, []string{"nat", "mangle"})
		So(iptv6, ShouldNotBeNil)

		ipsv4 := &memoryIPSetProvider{sets: map[string]*memoryIPSet{}}
		ipsv6 := &memoryIPSetProvider{sets: map[string]*memoryIPSet{}}

		i, err := createTestInstance(ipsv4, ipsv6, iptv4, iptv6, constants.LocalServer)
		So(err, ShouldBeNil)
		So(i, ShouldNotBeNil)

		Convey("When I start the controller, I should get the right global chains and ipsets", func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			err := i.Run(ctx)
			i.SetTargetNetworks(cfg) //nolint

			So(err, ShouldBeNil)

			for set, targets := range ipsv6.sets {
				So(expectedGlobalIPSetsV6, ShouldContainKey, set)
				for target := range targets.set {
					So(expectedGlobalIPSetsV6[set], ShouldContain, target)
				}
			}

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
				)
				puInfo := policy.NewPUInfo("Context", "/ns1", common.LinuxProcessPU)
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
				i.iptv6.aclmanager.RegisterExternalNets("pu1", iprules) //nolint

				err = i.ConfigureRules(0, "pu1", puInfo)
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

				for set, targets := range ipsv6.sets {

					So(expectedIPSetsAfterPUInsertV6, ShouldContainKey, set)
					for target := range targets.set {
						So(expectedIPSetsAfterPUInsertV6[set], ShouldContain, target)
					}
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
					)
					puInfoUpdated := policy.NewPUInfo("Context", "/ns1", common.LinuxProcessPU)
					puInfoUpdated.Policy = policyrules
					puInfoUpdated.Runtime.SetOptions(policy.OptionsType{
						CgroupMark: "10",
					})

					err := i.UpdateRules(1, "pu1", puInfoUpdated, puInfo)
					So(err, ShouldBeNil)

					t := i.iptv6.impl.RetrieveTable()
					for chain, rules := range t["mangle"] {
						So(expectedMangleAfterPUUpdateV6, ShouldContainKey, chain)
						So(rules, ShouldResemble, expectedMangleAfterPUUpdateV6[chain])
					}

					Convey("When I delete the same rule, the chains must be restored in the global state", func() {
						err := i.DeleteRules(1, "pu1", "0", "5000", "10", "", "0", "0", common.LinuxProcessPU)
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

var (
	expectedContainerGlobalMangleChainsV6 = map[string][]string{
		"INPUT": {
			"-m set ! --match-set TRI-v6-Excluded src -j TRI-Net",
		},
		"OUTPUT": {
			"-m set ! --match-set TRI-v6-Excluded dst -j TRI-App",
		},
		"TRI-App": {
			"-j TRI-Prx-App",
			"-m mark --mark 1073741922 -j ACCEPT",
			"-m connmark --mark 61167 -j ACCEPT",
			"-m connmark --mark 61166 -p tcp ! --tcp-flags SYN,ACK SYN,ACK -j ACCEPT",
			"-p tcp -m set --match-set TRI-v6-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -j MARK --set-mark 99",
			"-p tcp -m set --match-set TRI-v6-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-balance 8:11 --queue-bypass",
		},
		"TRI-Net": {
			"-j TRI-Prx-Net",
			"-p udp -m set --match-set TRI-v6-TargetUDP src -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -j NFQUEUE --queue-bypass --queue-balance 24:27",
			"-m set --match-set TRI-v6-TargetTCP src -p tcp --tcp-flags ALL ACK -m tcp --tcp-option 34 -j NFQUEUE --queue-balance 20:23",
			"-m connmark --mark 61167 -j ACCEPT",
			"-m connmark --mark 61166 -p tcp ! --tcp-flags SYN,ACK SYN,ACK -j ACCEPT",
			"-m set --match-set TRI-v6-TargetTCP src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-balance 24:27 --queue-bypass",
			"-p tcp -m set --match-set TRI-v6-TargetTCP src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -j NFQUEUE --queue-balance 16:19 --queue-bypass",
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
			"-m mark --mark 0x40 -j ACCEPT",
		},
		"TRI-Redir-Net": {
			"-m mark --mark 0x40 -j ACCEPT",
		},
	}

	expectedContainerGlobalIPSetsV6 = map[string][]string{
		"TRI" + "-v6-" + targetTCPNetworkSet: {"::/1", "8000::/1"},
		"TRI" + "-v6-" + targetUDPNetworkSet: {"1120::/64"},
		"TRI" + "-v6-" + excludedNetworkSet:  {"::1"},
	}

	expectedContainerMangleAfterPUInsertV6 = map[string][]string{
		"INPUT": {
			"-m set ! --match-set TRI-v6-Excluded src -j TRI-Net",
		},
		"OUTPUT": {
			"-m set ! --match-set TRI-v6-Excluded dst -j TRI-App",
		},
		"TRI-App": {
			"-j TRI-Prx-App",
			"-m mark --mark 1073741922 -j ACCEPT",
			"-m connmark --mark 61167 -j ACCEPT",
			"-m connmark --mark 61166 -p tcp ! --tcp-flags SYN,ACK SYN,ACK -j ACCEPT",
			"-p tcp -m set --match-set TRI-v6-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -j MARK --set-mark 99",
			"-p tcp -m set --match-set TRI-v6-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-balance 8:11 --queue-bypass",
			"-m comment --comment Container-specific-chain -j TRI-App-pu1N7uS6--0",
		},
		"TRI-Net": {
			"-j TRI-Prx-Net",
			"-p udp -m set --match-set TRI-v6-TargetUDP src -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -j NFQUEUE --queue-bypass --queue-balance 24:27",
			"-m set --match-set TRI-v6-TargetTCP src -p tcp --tcp-flags ALL ACK -m tcp --tcp-option 34 -j NFQUEUE --queue-balance 20:23",
			"-m connmark --mark 61167 -j ACCEPT",
			"-m connmark --mark 61166 -p tcp ! --tcp-flags SYN,ACK SYN,ACK -j ACCEPT",
			"-m set --match-set TRI-v6-TargetTCP src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-balance 24:27 --queue-bypass",
			"-p tcp -m set --match-set TRI-v6-TargetTCP src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -j NFQUEUE --queue-balance 16:19 --queue-bypass",
			"-m comment --comment Container-specific-chain -j TRI-Net-pu1N7uS6--0",
		},
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
		"TRI-Net-pu1N7uS6--0": {
			"-p UDP -m set --match-set TRI-v6-ext-6zlJIvP3B68= src -m state --state ESTABLISHED -j ACCEPT",
			"-p TCP -m set --match-set TRI-v6-ext-w5frVvhsnpU= src -m state --state NEW -m set ! --match-set TRI-v6-TargetTCP src --match multiport --dports 80 -j DROP",
			"-p UDP -m set --match-set TRI-v6-ext-IuSLsD1R-mE= src --match multiport --dports 443 -j ACCEPT",
			"-p icmpv6 -j ACCEPT",
			"-p tcp -m set --match-set TRI-v6-TargetTCP src -m tcp --tcp-flags SYN,ACK SYN -j NFQUEUE --queue-balance 16:19",
			"-p tcp -m set --match-set TRI-v6-TargetTCP src -m tcp --tcp-flags SYN,ACK ACK -j NFQUEUE --queue-balance 20:23",
			"-p udp -m set --match-set TRI-v6-TargetUDP src --match limit --limit 1000/s -j NFQUEUE --queue-balance 16:19",
			"-p tcp -m state --state ESTABLISHED -m comment --comment TCP-Established-Connections -j ACCEPT",
			"-s ::/0 -m state --state NEW -j NFLOG --nflog-group 11 --nflog-prefix 913787369:default:default:6",
			"-s ::/0 -m state ! --state NEW -j NFLOG --nflog-group 11 --nflog-prefix 913787369:default:default:10",
			"-s ::/0 -j DROP",
		},

		"TRI-App-pu1N7uS6--0": {
			"-p TCP -m set --match-set TRI-v6-ext-uNdc0vdcFZA= dst -m state --state NEW -m set ! --match-set TRI-v6-TargetTCP dst --match multiport --dports 80 -j DROP",
			"-p UDP -m set --match-set TRI-v6-ext-6zlJIvP3B68= dst --match multiport --dports 443 -j ACCEPT",
			"-p UDP -m set --match-set TRI-v6-ext-IuSLsD1R-mE= dst -m state --state ESTABLISHED -j ACCEPT",
			"-p icmpv6 -j ACCEPT",
			"-p tcp -m tcp --tcp-flags SYN,ACK SYN -j NFQUEUE --queue-balance 0:3",
			"-p tcp -m tcp --tcp-flags SYN,ACK ACK -j NFQUEUE --queue-balance 4:7",
			"-p udp -m set --match-set TRI-v6-TargetUDP dst -j NFQUEUE --queue-balance 0:3",
			"-p udp -m set --match-set TRI-v6-TargetUDP dst -m state --state ESTABLISHED -m comment --comment UDP-Established-Connections -j ACCEPT",
			"-p tcp -m state --state ESTABLISHED -m comment --comment TCP-Established-Connections -j ACCEPT",
			"-d ::/0 -m state --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 913787369:default:default:6",
			"-d ::/0 -m state ! --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 913787369:default:default:10",
			"-d ::/0 -j DROP",
		},
	}

	expectedContainerNATAfterPUInsertV6 = map[string][]string{
		"PREROUTING": {
			"-p tcp -m addrtype --dst-type LOCAL -m set ! --match-set TRI-v6-Excluded src -j TRI-Redir-Net",
		},
		"OUTPUT": {
			"-m set ! --match-set TRI-v6-Excluded dst -j TRI-Redir-App",
		},
		"TRI-Redir-App": {
			"-m mark --mark 0x40 -j ACCEPT",
			"-p tcp -m set --match-set TRI-v6-Proxy-pu19gtV-dst dst,dst -m mark ! --mark 0x40 -m cgroup --cgroup 10 -j REDIRECT --to-ports 0",
			"-d ::/0 -p udp --dport 53 -m mark ! --mark 0x40 -m cgroup --cgroup 10 -j CONNMARK --save-mark",
			"-d ::/0 -p udp --dport 53 -m mark ! --mark 0x40 -m cgroup --cgroup 10 -j REDIRECT --to-ports 0",
		},
		"TRI-Redir-Net": {
			"-m mark --mark 0x40 -j ACCEPT",
			"-p tcp -m set --match-set TRI-v6-Proxy-pu19gtV-srv dst -m mark ! --mark 0x40 -j REDIRECT --to-ports 0",
		},
	}

	expectedContainerIPSetsAfterPUInsertV6 = map[string][]string{
		"TRI-v6-" + targetTCPNetworkSet: {"::/1", "8000::/1"},
		"TRI-v6-" + targetUDPNetworkSet: {"1120::/64"},
		"TRI-v6-" + excludedNetworkSet:  {"::1"},
		"TRI-v6-ProcPort-pu19gtV":       {},
		"TRI-v6-ext-6zlJIvP3B68=":       {"1120::/64"},
		"TRI-v6-ext-uNdc0vdcFZA=":       {"1120::/64"},
		"TRI-v6-ext-w5frVvhsnpU=":       {"1122::/64"},
		"TRI-v6-ext-IuSLsD1R-mE=":       {"1122::/64"},
		"TRI-v6-Proxy-pu19gtV-dst":      {},
		"TRI-v6-Proxy-pu19gtV-srv":      {},
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

		iptv4 := provider.NewCustomBatchProvider(&baseIpt{}, commitFunc, []string{"nat", "mangle"})
		So(iptv4, ShouldNotBeNil)

		iptv6 := provider.NewCustomBatchProvider(&baseIpt{}, commitFunc, []string{"nat", "mangle"})
		So(iptv6, ShouldNotBeNil)

		ipsv4 := &memoryIPSetProvider{sets: map[string]*memoryIPSet{}}
		ipsv6 := &memoryIPSetProvider{sets: map[string]*memoryIPSet{}}

		i, err := createTestInstance(ipsv4, ipsv6, iptv4, iptv6, constants.RemoteContainer)
		So(err, ShouldBeNil)
		So(i, ShouldNotBeNil)

		Convey("When I start the controller, I should get the right global chains and sets", func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			err := i.Run(ctx)
			So(err, ShouldBeNil)
			i.SetTargetNetworks(cfg) //nolint

			for set, targets := range ipsv6.sets {
				So(expectedContainerGlobalIPSetsV6, ShouldContainKey, set)
				for target := range targets.set {
					So(expectedContainerGlobalIPSetsV6[set], ShouldContain, target)
				}
			}

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
				)
				puInfo := policy.NewPUInfo("Context", "/ns1", common.ContainerPU)
				puInfo.Policy = policyrules
				puInfo.Runtime.SetOptions(policy.OptionsType{
					CgroupMark: "10",
				})

				var iprules policy.IPRuleList
				iprules = append(iprules, puInfo.Policy.ApplicationACLs()...)
				iprules = append(iprules, puInfo.Policy.NetworkACLs()...)
				i.iptv6.aclmanager.RegisterExternalNets("pu1", iprules) //nolint

				err := i.ConfigureRules(0, "pu1", puInfo)
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

				for set, targets := range ipsv6.sets {
					So(expectedContainerIPSetsAfterPUInsertV6, ShouldContainKey, set)
					for target := range targets.set {
						So(expectedContainerIPSetsAfterPUInsertV6[set], ShouldContain, target)
					}
				}

				Convey("When I delete the same rule, the chains must be restored in the global state", func() {
					err := i.iptv6.DeleteRules(0, "pu1", "0", "0", "10", "", "0", "0", common.ContainerPU)
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
