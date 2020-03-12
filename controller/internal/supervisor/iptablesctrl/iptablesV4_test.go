// +build !windows

package iptablesctrl

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/aporeto-inc/go-ipset/ipset"
	"github.com/magiconair/properties/assert"
	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/controller/constants"
	provider "go.aporeto.io/trireme-lib/controller/pkg/aclprovider"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/controller/pkg/ipsetmanager"
	"go.aporeto.io/trireme-lib/controller/runtime"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/portspec"
)

func createTestInstance(ipsv4 provider.IpsetProvider, ipsv6 provider.IpsetProvider, iptv4 provider.IptablesProvider, iptv6 provider.IptablesProvider, mode constants.ModeType) (*Instance, error) {

	ipv4Impl := &ipv4{ipt: iptv4}
	ipv6Impl := &ipv6{ipt: iptv6, ipv6Enabled: true}

	fq := fqconfig.NewFilterQueueWithDefaults()
	fq.DNSServerAddress = []string{"0.0.0.0/0", "::/0"}

	aclmanager := ipsetmanager.CreateIPsetManager(ipsv4, ipsv6)
	iptInstanceV4 := createIPInstance(ipv4Impl, ipsv4, fq, mode, aclmanager, nil)
	iptInstanceV6 := createIPInstance(ipv6Impl, ipsv6, fq, mode, aclmanager, nil)

	iptInstanceV4.conntrackCmd = func([]string) {}
	iptInstanceV6.conntrackCmd = func([]string) {}

	return newInstanceWithProviders(iptInstanceV4, iptInstanceV6)
}

// Fake iptables controller that always returns succes.
type baseIpt struct{}

// Append apends a rule to chain of table
func (b *baseIpt) Append(table, chain string, rulespec ...string) error { return nil }

// Insert inserts a rule to a chain of table at the required pos
func (b *baseIpt) Insert(table, chain string, pos int, rulespec ...string) error { return nil }

// Delete deletes a rule of a chain in the given table
func (b *baseIpt) Delete(table, chain string, rulespec ...string) error { return nil }

// ListChains lists all the chains associated with a table
func (b *baseIpt) ListChains(table string) ([]string, error) { return nil, nil }

// ClearChain clears a chain in a table
func (b *baseIpt) ClearChain(table, chain string) error { return nil }

// DeleteChain deletes a chain in the table. There should be no references to this chain
func (b *baseIpt) DeleteChain(table, chain string) error { return nil }

// NewChain creates a new chain
func (b *baseIpt) NewChain(table, chain string) error { return nil }

// Fake memory IPset that will tell us if we are deleting or installing
// bad things.
type memoryIPSet struct {
	set map[string]struct{}
}

func (m *memoryIPSet) Add(entry string, timeout int) error {
	m.set[entry] = struct{}{}
	return nil
}

func (m *memoryIPSet) AddOption(entry string, option string, timeout int) error {
	return nil
}

func (m *memoryIPSet) Del(entry string) error {
	if _, ok := m.set[entry]; !ok {
		return fmt.Errorf("not found")
	}
	delete(m.set, entry)
	return nil
}

func (m *memoryIPSet) Destroy() error {
	m.set = map[string]struct{}{}
	return nil
}

func (m *memoryIPSet) Flush() error {
	m.set = map[string]struct{}{}
	return nil
}

func (m *memoryIPSet) Test(entry string) (bool, error) {
	_, ok := m.set[entry]
	return ok, nil
}

// Fake IpSetProvider that will use memory and allow us to
// to simulate the system.
type memoryIPSetProvider struct {
	sets map[string]*memoryIPSet
}

func (m *memoryIPSetProvider) NewIpset(name string, hasht string, p *ipset.Params) (provider.Ipset, error) {

	if m.sets == nil {
		return nil, fmt.Errorf("error")
	}

	_, ok := m.sets[name]
	if ok {
		return nil, fmt.Errorf("set exists")
	}

	newSet := &memoryIPSet{set: map[string]struct{}{}}
	m.sets[name] = newSet
	return newSet, nil
}

func (m *memoryIPSetProvider) GetIpset(name string) provider.Ipset {
	return m.sets[name]
}

func (m *memoryIPSetProvider) DestroyAll(prefix string) error {
	for set := range m.sets {
		if strings.HasPrefix(set, prefix) {
			delete(m.sets, set)
		}
	}
	return nil
}

func (m *memoryIPSetProvider) ListIPSets() ([]string, error) {
	allSets := []string{}
	for set := range m.sets {
		allSets = append(allSets, set)
	}
	return allSets, nil
}

func TestNewInstanceV4(t *testing.T) {
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

func Test_NegativeConfigureRulesV4(t *testing.T) {
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
		So(err, ShouldBeNil)

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
			err := i.iptv4.ConfigureRules(1, "ID", containerinfo)
			So(err, ShouldBeNil)
		})

		Convey("When I configure the rules and the proxy set fails, it should error", func() {
			ipsv4.MockNewIpset(t, func(name, hash string, p *ipset.Params) (provider.Ipset, error) {
				return nil, fmt.Errorf("error")
			})
			err := i.iptv4.ConfigureRules(1, "ID", containerinfo)
			So(err, ShouldNotBeNil)
		})

		Convey("When I configure the rules and acls fail, it should error", func() {
			iptv4.MockAppend(t, func(table, chain string, rulespec ...string) error {
				return fmt.Errorf("error")
			})
			err := i.iptv4.ConfigureRules(1, "ID", containerinfo)
			So(err, ShouldNotBeNil)
		})

		Convey("When I configure the rules and commit fails, it should error", func() {
			iptv4.MockCommit(t, func() error {
				return fmt.Errorf("error")
			})
			err := i.iptv4.ConfigureRules(1, "ID", containerinfo)
			So(err, ShouldNotBeNil)
		})
	})
}

var (
	expectedGlobalMangleChainsV4 = map[string][]string{
		"INPUT": {
			"-m set ! --match-set TRI-v4-Excluded src -j TRI-Net",
		},
		"OUTPUT": {
			"-m set ! --match-set TRI-v4-Excluded dst -j TRI-App",
		},
		"TRI-App": {
			"-j TRI-Prx-App",
			"-m mark --mark 1073741922 -j ACCEPT",
			"-m connmark --mark 61167 -j ACCEPT",
			"-m connmark --mark 61166 -p tcp ! --tcp-flags SYN,ACK SYN,ACK -j ACCEPT",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -j HMARK --hmark-tuple dst,dport,src,sport --hmark-offset 0x1 --hmark-rnd 0xdeafbee1 --hmark-mod 4",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -j HMARK --hmark-tuple dst,dport,src,sport --hmark-offset 0x1 --hmark-rnd 0xdeafbee1 --hmark-mod 4",
			"-j TRI-UID-App",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -j MARK --set-mark 0/0xfffffc00",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 8 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 9 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 10 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 11 --queue-bypass",
			"-j TRI-Pid-App",
			"-j TRI-Svc-App",
			"-j TRI-Hst-App",
		},
		"TRI-Net": {
			"-j TRI-Prx-Net",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -j HMARK --hmark-tuple src,sport,dst,dport --hmark-offset 0x1 --hmark-rnd 0xdeafbee1 --hmark-mod 4",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -m mark --mark 1/0x3ff -j NFQUEUE --queue-bypass --queue-num 24",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -m mark --mark 2/0x3ff -j NFQUEUE --queue-bypass --queue-num 25",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -m mark --mark 3/0x3ff -j NFQUEUE --queue-bypass --queue-num 26",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -m mark --mark 4/0x3ff -j NFQUEUE --queue-bypass --queue-num 27",
			"-m connmark --mark 61167 -j ACCEPT",
			"-m connmark --mark 61166 -p tcp ! --tcp-flags SYN,ACK SYN,ACK -j ACCEPT",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -j HMARK --hmark-tuple src,sport,dst,dport --hmark-offset 0x1 --hmark-rnd 0xdeafbee1 --hmark-mod 4",
			"-j TRI-UID-Net",
			"-m set --match-set TRI-v4-TargetTCP src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 24 --queue-bypass",
			"-m set --match-set TRI-v4-TargetTCP src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 25 --queue-bypass",
			"-m set --match-set TRI-v4-TargetTCP src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 26 --queue-bypass",
			"-m set --match-set TRI-v4-TargetTCP src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 27 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 16 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 17 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 18 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 19 --queue-bypass",
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

	expectedGlobalIPSetsV4 = map[string][]string{
		"TRI" + "-v4-" + targetTCPNetworkSet: {"0.0.0.0/1", "128.0.0.0/1"},
		"TRI" + "-v4-" + targetUDPNetworkSet: {"10.0.0.0/8"},
		"TRI" + "-v4-" + excludedNetworkSet:  {"127.0.0.1"},
	}

	expectedMangleAfterPUInsertV4 = map[string][]string{
		"INPUT": {
			"-m set ! --match-set TRI-v4-Excluded src -j TRI-Net",
		},
		"OUTPUT": {
			"-m set ! --match-set TRI-v4-Excluded dst -j TRI-App",
		},
		"TRI-App": {
			"-j TRI-Prx-App",
			"-m mark --mark 1073741922 -j ACCEPT",
			"-m connmark --mark 61167 -j ACCEPT",
			"-m connmark --mark 61166 -p tcp ! --tcp-flags SYN,ACK SYN,ACK -j ACCEPT",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -j HMARK --hmark-tuple dst,dport,src,sport --hmark-offset 0x1 --hmark-rnd 0xdeafbee1 --hmark-mod 4",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -j HMARK --hmark-tuple dst,dport,src,sport --hmark-offset 0x1 --hmark-rnd 0xdeafbee1 --hmark-mod 4",
			"-j TRI-UID-App",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -j MARK --set-mark 0/0xfffffc00",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 8 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 9 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 10 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 11 --queue-bypass",
			"-j TRI-Pid-App",
			"-j TRI-Svc-App",
			"-j TRI-Hst-App",
		},
		"TRI-Net": {
			"-j TRI-Prx-Net",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -j HMARK --hmark-tuple src,sport,dst,dport --hmark-offset 0x1 --hmark-rnd 0xdeafbee1 --hmark-mod 4",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -m mark --mark 1/0x3ff -j NFQUEUE --queue-bypass --queue-num 24",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -m mark --mark 2/0x3ff -j NFQUEUE --queue-bypass --queue-num 25",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -m mark --mark 3/0x3ff -j NFQUEUE --queue-bypass --queue-num 26",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -m mark --mark 4/0x3ff -j NFQUEUE --queue-bypass --queue-num 27",
			"-m connmark --mark 61167 -j ACCEPT",
			"-m connmark --mark 61166 -p tcp ! --tcp-flags SYN,ACK SYN,ACK -j ACCEPT",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -j HMARK --hmark-tuple src,sport,dst,dport --hmark-offset 0x1 --hmark-rnd 0xdeafbee1 --hmark-mod 4",
			"-j TRI-UID-Net",
			"-m set --match-set TRI-v4-TargetTCP src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 24 --queue-bypass",
			"-m set --match-set TRI-v4-TargetTCP src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 25 --queue-bypass",
			"-m set --match-set TRI-v4-TargetTCP src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 26 --queue-bypass",
			"-m set --match-set TRI-v4-TargetTCP src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 27 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 16 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 17 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 18 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 19 --queue-bypass",
			"-j TRI-Pid-Net",
			"-j TRI-Svc-Net",
			"-j TRI-Hst-Net",
		},
		"TRI-Pid-App": {
			"-m cgroup --cgroup 10 -m comment --comment PU-Chain -j MARK --set-mark 10485760/0xfffffc00",
			"-m mark --mark 10485760/0xfffffc00 -m comment --comment PU-Chain -j TRI-App-pu1N7uS6--0",
		},
		"TRI-Pid-Net": {
			"-p tcp -m multiport --destination-ports 9000 -m comment --comment PU-Chain -j TRI-Net-pu1N7uS6--0", "-p udp -m multiport --destination-ports 5000 -m comment --comment PU-Chain -j TRI-Net-pu1N7uS6--0",
		},
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
		"TRI-UID-App": {},
		"TRI-UID-Net": {},

		"TRI-Net-pu1N7uS6--0": {
			"-p UDP -m set --match-set TRI-v4-ext-6zlJIvP3B68= src -m state --state ESTABLISHED -j ACCEPT",
			"-p TCP -m set --match-set TRI-v4-ext-w5frVvhsnpU= src -m state --state NEW -m set ! --match-set TRI-v4-TargetTCP src --match multiport --dports 80 -j DROP",
			"-p UDP -m set --match-set TRI-v4-ext-IuSLsD1R-mE= src --match multiport --dports 443 -j ACCEPT",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 16",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 17",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 18",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 19",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 20",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 21",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 22",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 23",
			"-p udp -m set --match-set TRI-v4-TargetUDP src --match limit --limit 1000/s -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 16",
			"-p udp -m set --match-set TRI-v4-TargetUDP src --match limit --limit 1000/s -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 17",
			"-p udp -m set --match-set TRI-v4-TargetUDP src --match limit --limit 1000/s -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 18",
			"-p udp -m set --match-set TRI-v4-TargetUDP src --match limit --limit 1000/s -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 19",
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

			"-p TCP -m set --match-set TRI-v4-ext-uNdc0vdcFZA= dst -m state --state NEW -m set ! --match-set TRI-v4-TargetTCP dst --match multiport --dports 80 -j DROP",
			"-p UDP -m set --match-set TRI-v4-ext-6zlJIvP3B68= dst --match multiport --dports 443 -j ACCEPT",
			"-p icmp -m set --match-set TRI-v4-ext-w5frVvhsnpU= dst -j ACCEPT",
			"-p UDP -m set --match-set TRI-v4-ext-IuSLsD1R-mE= dst -m state --state ESTABLISHED -j ACCEPT",
			"-p tcp -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 0",
			"-p tcp -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 1",
			"-p tcp -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 2",
			"-p tcp -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 3",
			"-p tcp -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 4",
			"-p tcp -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 5",
			"-p tcp -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 6",
			"-p tcp -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 7",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 0",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 1",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 2",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 3",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -m state --state ESTABLISHED -m comment --comment UDP-Established-Connections -j ACCEPT",
			"-p tcp -m state --state ESTABLISHED -m comment --comment TCP-Established-Connections -j ACCEPT",
			"-p ALL -m set --match-set TRI-v4-ext-_qhcdC8NcJc= dst -j NFLOG --nflog-group 10 --nflog-prefix 913787369:123a:a3:6",
			"-p ALL -m set --match-set TRI-v4-ext-_qhcdC8NcJc= dst -j DROP",
			"-p ALL -m set --match-set TRI-v4-ext-_qhcdC8NcJc= dst -j NFLOG --nflog-group 10 --nflog-prefix 913787369:123a:a3:3",
			"-p ALL -m set --match-set TRI-v4-ext-_qhcdC8NcJc= dst -j ACCEPT",
			"-d 0.0.0.0/0 -m state --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 913787369:default:default:6",
			"-d 0.0.0.0/0 -m state ! --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 913787369:default:default:10",
			"-d 0.0.0.0/0 -j DROP",
		},
	}

	expectedMangleAfterPUInsertWithLogV4 = map[string][]string{
		"INPUT": {
			"-m set ! --match-set TRI-v4-Excluded src -j TRI-Net",
		},
		"OUTPUT": {
			"-m set ! --match-set TRI-v4-Excluded dst -j TRI-App",
		},
		"TRI-App": {
			"-j TRI-Prx-App",
			"-m mark --mark 1073741922 -j ACCEPT",
			"-m connmark --mark 61167 -j ACCEPT",
			"-m connmark --mark 61166 -p tcp ! --tcp-flags SYN,ACK SYN,ACK -j ACCEPT",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -j HMARK --hmark-tuple dst,dport,src,sport --hmark-offset 0x1 --hmark-rnd 0xdeafbee1 --hmark-mod 4",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -j HMARK --hmark-tuple dst,dport,src,sport --hmark-offset 0x1 --hmark-rnd 0xdeafbee1 --hmark-mod 4",
			"-j TRI-UID-App",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -j MARK --set-mark 0/0xfffffc00",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 8 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 9 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 10 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 11 --queue-bypass",
			"-j TRI-Pid-App",
			"-j TRI-Svc-App",
			"-j TRI-Hst-App",
		},
		"TRI-Net": {
			"-j TRI-Prx-Net",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -j HMARK --hmark-tuple src,sport,dst,dport --hmark-offset 0x1 --hmark-rnd 0xdeafbee1 --hmark-mod 4",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -m mark --mark 1/0x3ff -j NFQUEUE --queue-bypass --queue-num 24",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -m mark --mark 2/0x3ff -j NFQUEUE --queue-bypass --queue-num 25",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -m mark --mark 3/0x3ff -j NFQUEUE --queue-bypass --queue-num 26",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -m mark --mark 4/0x3ff -j NFQUEUE --queue-bypass --queue-num 27",
			"-m connmark --mark 61167 -j ACCEPT",
			"-m connmark --mark 61166 -p tcp ! --tcp-flags SYN,ACK SYN,ACK -j ACCEPT",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -j HMARK --hmark-tuple src,sport,dst,dport --hmark-offset 0x1 --hmark-rnd 0xdeafbee1 --hmark-mod 4",
			"-j TRI-UID-Net",
			"-m set --match-set TRI-v4-TargetTCP src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 24 --queue-bypass",
			"-m set --match-set TRI-v4-TargetTCP src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 25 --queue-bypass",
			"-m set --match-set TRI-v4-TargetTCP src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 26 --queue-bypass",
			"-m set --match-set TRI-v4-TargetTCP src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 27 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 16 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 17 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 18 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 19 --queue-bypass",
			"-j TRI-Pid-Net",
			"-j TRI-Svc-Net",
			"-j TRI-Hst-Net",
		},

		"TRI-Pid-App": {
			"-m cgroup --cgroup 10 -m comment --comment PU-Chain -j MARK --set-mark 10485760/0xfffffc00",
			"-m mark --mark 10485760/0xfffffc00 -m comment --comment PU-Chain -j TRI-App-pu1N7uS6--0",
		},
		"TRI-Pid-Net": {
			"-p tcp -m multiport --destination-ports 9000 -m comment --comment PU-Chain -j TRI-Net-pu1N7uS6--0", "-p udp -m multiport --destination-ports 5000 -m comment --comment PU-Chain -j TRI-Net-pu1N7uS6--0",
		},
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
		"TRI-UID-App": {},
		"TRI-UID-Net": {},

		"TRI-Net-pu1N7uS6--0": {
			"-p UDP -m set --match-set TRI-v4-ext-6zlJIvP3B68= src -m state --state ESTABLISHED -j ACCEPT",
			"-p TCP -m set --match-set TRI-v4-ext-w5frVvhsnpU= src -m state --state NEW -m set ! --match-set TRI-v4-TargetTCP src --match multiport --dports 80 -j DROP",
			"-p UDP -m set --match-set TRI-v4-ext-IuSLsD1R-mE= src --match multiport --dports 443 -j ACCEPT",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 16",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 17",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 18",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 19",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 20",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 21",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 22",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 23",
			"-p udp -m set --match-set TRI-v4-TargetUDP src --match limit --limit 1000/s -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 16",
			"-p udp -m set --match-set TRI-v4-TargetUDP src --match limit --limit 1000/s -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 17",
			"-p udp -m set --match-set TRI-v4-TargetUDP src --match limit --limit 1000/s -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 18",
			"-p udp -m set --match-set TRI-v4-TargetUDP src --match limit --limit 1000/s -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 19",
			"-p tcp -m state --state ESTABLISHED -m comment --comment TCP-Established-Connections -j ACCEPT",
			"-s 0.0.0.0/0 -m state --state NEW -j NFLOG --nflog-group 11 --nflog-prefix 913787369:default:default:6",
			"-s 0.0.0.0/0 -m state ! --state NEW -j NFLOG --nflog-group 11 --nflog-prefix 913787369:default:default:10",
			"-s 0.0.0.0/0 -j DROP",
		},

		"TRI-App-pu1N7uS6--0": {
			"-p TCP -m set --match-set TRI-v4-ext-uNdc0vdcFZA= dst -m state --state NEW -m set ! --match-set TRI-v4-TargetTCP dst --match multiport --dports 80 -j DROP",
			"-p UDP -m set --match-set TRI-v4-ext-6zlJIvP3B68= dst --match multiport --dports 443 -m state --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 913787369:2:s2:3",
			"-p UDP -m set --match-set TRI-v4-ext-6zlJIvP3B68= dst --match multiport --dports 443 -j ACCEPT",
			"-p icmp -m set --match-set TRI-v4-ext-w5frVvhsnpU= dst -j ACCEPT",
			"-p UDP -m set --match-set TRI-v4-ext-IuSLsD1R-mE= dst -m state --state ESTABLISHED -j ACCEPT",
			"-p tcp -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 0",
			"-p tcp -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 1",
			"-p tcp -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 2",
			"-p tcp -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 3",
			"-p tcp -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 4",
			"-p tcp -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 5",
			"-p tcp -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 6",
			"-p tcp -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 7",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 0",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 1",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 2",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 3",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -m state --state ESTABLISHED -m comment --comment UDP-Established-Connections -j ACCEPT",
			"-p tcp -m state --state ESTABLISHED -m comment --comment TCP-Established-Connections -j ACCEPT",
			"-d 0.0.0.0/0 -m state --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 913787369:default:default:6",
			"-d 0.0.0.0/0 -m state ! --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 913787369:default:default:10",
			"-d 0.0.0.0/0 -j DROP",
		},
	}

	expectedMangleAfterPUInsertWithExtensionsV4 = map[string][]string{
		"INPUT": {
			"-m set ! --match-set TRI-v4-Excluded src -j TRI-Net",
		},
		"OUTPUT": {
			"-m set ! --match-set TRI-v4-Excluded dst -j TRI-App",
		},
		"TRI-App": {
			"-j TRI-Prx-App",
			"-m mark --mark 1073741922 -j ACCEPT",
			"-m connmark --mark 61167 -j ACCEPT",
			"-m connmark --mark 61166 -p tcp ! --tcp-flags SYN,ACK SYN,ACK -j ACCEPT",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -j HMARK --hmark-tuple dst,dport,src,sport --hmark-offset 0x1 --hmark-rnd 0xdeafbee1 --hmark-mod 4",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -j HMARK --hmark-tuple dst,dport,src,sport --hmark-offset 0x1 --hmark-rnd 0xdeafbee1 --hmark-mod 4",
			"-j TRI-UID-App",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -j MARK --set-mark 0/0xfffffc00",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 8 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 9 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 10 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 11 --queue-bypass",
			"-j TRI-Pid-App",
			"-j TRI-Svc-App",
			"-j TRI-Hst-App",
		},
		"TRI-Net": {
			"-j TRI-Prx-Net",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -j HMARK --hmark-tuple src,sport,dst,dport --hmark-offset 0x1 --hmark-rnd 0xdeafbee1 --hmark-mod 4",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -m mark --mark 1/0x3ff -j NFQUEUE --queue-bypass --queue-num 24",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -m mark --mark 2/0x3ff -j NFQUEUE --queue-bypass --queue-num 25",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -m mark --mark 3/0x3ff -j NFQUEUE --queue-bypass --queue-num 26",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -m mark --mark 4/0x3ff -j NFQUEUE --queue-bypass --queue-num 27",
			"-m connmark --mark 61167 -j ACCEPT",
			"-m connmark --mark 61166 -p tcp ! --tcp-flags SYN,ACK SYN,ACK -j ACCEPT",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -j HMARK --hmark-tuple src,sport,dst,dport --hmark-offset 0x1 --hmark-rnd 0xdeafbee1 --hmark-mod 4",
			"-j TRI-UID-Net",
			"-m set --match-set TRI-v4-TargetTCP src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 24 --queue-bypass",
			"-m set --match-set TRI-v4-TargetTCP src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 25 --queue-bypass",
			"-m set --match-set TRI-v4-TargetTCP src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 26 --queue-bypass",
			"-m set --match-set TRI-v4-TargetTCP src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 27 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 16 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 17 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 18 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 19 --queue-bypass",
			"-j TRI-Pid-Net",
			"-j TRI-Svc-Net",
			"-j TRI-Hst-Net",
		},

		"TRI-Pid-App": {
			"-m cgroup --cgroup 10 -m comment --comment PU-Chain -j MARK --set-mark 10485760/0xfffffc00",
			"-m mark --mark 10485760/0xfffffc00 -m comment --comment PU-Chain -j TRI-App-pu1N7uS6--0",
		},
		"TRI-Pid-Net": {
			"-p tcp -m multiport --destination-ports 9000 -m comment --comment PU-Chain -j TRI-Net-pu1N7uS6--0", "-p udp -m multiport --destination-ports 5000 -m comment --comment PU-Chain -j TRI-Net-pu1N7uS6--0",
		},
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
		"TRI-UID-App": {},
		"TRI-UID-Net": {},

		"TRI-Net-pu1N7uS6--0": {
			"-p UDP -m set --match-set TRI-v4-ext-6zlJIvP3B68= src -m state --state ESTABLISHED -j ACCEPT",
			"-p TCP -m set --match-set TRI-v4-ext-w5frVvhsnpU= src -m state --state NEW -m set ! --match-set TRI-v4-TargetTCP src --match multiport --dports 80 -j DROP",
			"-p UDP -m set --match-set TRI-v4-ext-IuSLsD1R-mE= src --match multiport --dports 443 -j ACCEPT",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 16",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 17",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 18",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 19",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 20",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 21",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 22",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 23",
			"-p udp -m set --match-set TRI-v4-TargetUDP src --match limit --limit 1000/s -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 16",
			"-p udp -m set --match-set TRI-v4-TargetUDP src --match limit --limit 1000/s -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 17",
			"-p udp -m set --match-set TRI-v4-TargetUDP src --match limit --limit 1000/s -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 18",
			"-p udp -m set --match-set TRI-v4-TargetUDP src --match limit --limit 1000/s -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 19",
			"-p tcp -m state --state ESTABLISHED -m comment --comment TCP-Established-Connections -j ACCEPT",
			"-s 0.0.0.0/0 -m state --state NEW -j NFLOG --nflog-group 11 --nflog-prefix 913787369:default:default:6",
			"-s 0.0.0.0/0 -m state ! --state NEW -j NFLOG --nflog-group 11 --nflog-prefix 913787369:default:default:10",
			"-s 0.0.0.0/0 -j DROP",
		},

		"TRI-App-pu1N7uS6--0": {
			"-p UDP -m set --match-set TRI-v4-ext-6zlJIvP3B68= dst --match multiport --dports 443 -m bpf --bytecode 20,0 0 0 0,177 0 0 0,12 0 0 0,7 0 0 0,72 0 0 4,53 0 13 29,135 0 0 0,4 0 0 8,7 0 0 0,72 0 0 2,84 0 0 64655,21 0 7 0,72 0 0 4,21 0 5 1,64 0 0 6,21 0 3 0,72 0 0 10,37 1 0 1,6 0 0 0,6 0 0 65535 -j DROP",
			"-p TCP -m set --match-set TRI-v4-ext-uNdc0vdcFZA= dst -m state --state NEW -m set ! --match-set TRI-v4-TargetTCP dst --match multiport --dports 80 -j DROP",
			"-p UDP -m set --match-set TRI-v4-ext-6zlJIvP3B68= dst --match multiport --dports 443 -j ACCEPT",
			"-p icmp -m set --match-set TRI-v4-ext-w5frVvhsnpU= dst -j ACCEPT",
			"-p UDP -m set --match-set TRI-v4-ext-IuSLsD1R-mE= dst -m state --state ESTABLISHED -j ACCEPT",
			"-p tcp -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 0",
			"-p tcp -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 1",
			"-p tcp -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 2",
			"-p tcp -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 3",
			"-p tcp -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 4",
			"-p tcp -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 5",
			"-p tcp -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 6",
			"-p tcp -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 7",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 0",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 1",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 2",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 3",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -m state --state ESTABLISHED -m comment --comment UDP-Established-Connections -j ACCEPT",
			"-p tcp -m state --state ESTABLISHED -m comment --comment TCP-Established-Connections -j ACCEPT",
			"-d 0.0.0.0/0 -m state --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 913787369:default:default:6",
			"-d 0.0.0.0/0 -m state ! --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 913787369:default:default:10",
			"-d 0.0.0.0/0 -j DROP",
		},
	}

	expectedMangleAfterPUInsertWithExtensionsAndLogV4 = map[string][]string{
		"INPUT": {
			"-m set ! --match-set TRI-v4-Excluded src -j TRI-Net",
		},
		"OUTPUT": {
			"-m set ! --match-set TRI-v4-Excluded dst -j TRI-App",
		},
		"TRI-App": {
			"-j TRI-Prx-App",
			"-m mark --mark 1073741922 -j ACCEPT",
			"-m connmark --mark 61167 -j ACCEPT",
			"-m connmark --mark 61166 -p tcp ! --tcp-flags SYN,ACK SYN,ACK -j ACCEPT",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -j HMARK --hmark-tuple dst,dport,src,sport --hmark-offset 0x1 --hmark-rnd 0xdeafbee1 --hmark-mod 4",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -j HMARK --hmark-tuple dst,dport,src,sport --hmark-offset 0x1 --hmark-rnd 0xdeafbee1 --hmark-mod 4",
			"-j TRI-UID-App",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -j MARK --set-mark 0/0xfffffc00",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 8 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 9 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 10 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 11 --queue-bypass",
			"-j TRI-Pid-App",
			"-j TRI-Svc-App",
			"-j TRI-Hst-App",
		},
		"TRI-Net": {
			"-j TRI-Prx-Net",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -j HMARK --hmark-tuple src,sport,dst,dport --hmark-offset 0x1 --hmark-rnd 0xdeafbee1 --hmark-mod 4",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -m mark --mark 1/0x3ff -j NFQUEUE --queue-bypass --queue-num 24",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -m mark --mark 2/0x3ff -j NFQUEUE --queue-bypass --queue-num 25",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -m mark --mark 3/0x3ff -j NFQUEUE --queue-bypass --queue-num 26",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -m mark --mark 4/0x3ff -j NFQUEUE --queue-bypass --queue-num 27",
			"-m connmark --mark 61167 -j ACCEPT",
			"-m connmark --mark 61166 -p tcp ! --tcp-flags SYN,ACK SYN,ACK -j ACCEPT",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -j HMARK --hmark-tuple src,sport,dst,dport --hmark-offset 0x1 --hmark-rnd 0xdeafbee1 --hmark-mod 4",
			"-j TRI-UID-Net",
			"-m set --match-set TRI-v4-TargetTCP src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 24 --queue-bypass",
			"-m set --match-set TRI-v4-TargetTCP src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 25 --queue-bypass",
			"-m set --match-set TRI-v4-TargetTCP src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 26 --queue-bypass",
			"-m set --match-set TRI-v4-TargetTCP src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 27 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 16 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 17 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 18 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 19 --queue-bypass",
			"-j TRI-Pid-Net",
			"-j TRI-Svc-Net",
			"-j TRI-Hst-Net",
		},
		"TRI-Pid-App": {
			"-m cgroup --cgroup 10 -m comment --comment PU-Chain -j MARK --set-mark 10485760/0xfffffc00",
			"-m mark --mark 10485760/0xfffffc00 -m comment --comment PU-Chain -j TRI-App-pu1N7uS6--0",
		},
		"TRI-Pid-Net": {
			"-p tcp -m multiport --destination-ports 9000 -m comment --comment PU-Chain -j TRI-Net-pu1N7uS6--0", "-p udp -m multiport --destination-ports 5000 -m comment --comment PU-Chain -j TRI-Net-pu1N7uS6--0",
		},
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
		"TRI-UID-App": {},
		"TRI-UID-Net": {},

		"TRI-Net-pu1N7uS6--0": {
			"-p UDP -m set --match-set TRI-v4-ext-6zlJIvP3B68= src -m state --state ESTABLISHED -j ACCEPT",
			"-p TCP -m set --match-set TRI-v4-ext-w5frVvhsnpU= src -m state --state NEW -m set ! --match-set TRI-v4-TargetTCP src --match multiport --dports 80 -j DROP",
			"-p UDP -m set --match-set TRI-v4-ext-IuSLsD1R-mE= src --match multiport --dports 443 -j ACCEPT",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 16",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 17",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 18",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 19",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 20",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 21",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 22",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 23",
			"-p udp -m set --match-set TRI-v4-TargetUDP src --match limit --limit 1000/s -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 16",
			"-p udp -m set --match-set TRI-v4-TargetUDP src --match limit --limit 1000/s -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 17",
			"-p udp -m set --match-set TRI-v4-TargetUDP src --match limit --limit 1000/s -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 18",
			"-p udp -m set --match-set TRI-v4-TargetUDP src --match limit --limit 1000/s -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 19",
			"-p tcp -m state --state ESTABLISHED -m comment --comment TCP-Established-Connections -j ACCEPT",
			"-s 0.0.0.0/0 -m state --state NEW -j NFLOG --nflog-group 11 --nflog-prefix 913787369:default:default:6",
			"-s 0.0.0.0/0 -m state ! --state NEW -j NFLOG --nflog-group 11 --nflog-prefix 913787369:default:default:10",
			"-s 0.0.0.0/0 -j DROP",
		},

		"TRI-App-pu1N7uS6--0": {
			"-p UDP -m set --match-set TRI-v4-ext-6zlJIvP3B68= dst --match multiport --dports 443 -m bpf --bytecode 20,0 0 0 0,177 0 0 0,12 0 0 0,7 0 0 0,72 0 0 4,53 0 13 29,135 0 0 0,4 0 0 8,7 0 0 0,72 0 0 2,84 0 0 64655,21 0 7 0,72 0 0 4,21 0 5 1,64 0 0 6,21 0 3 0,72 0 0 10,37 1 0 1,6 0 0 0,6 0 0 65535 -m state --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 913787369:2:s2:6",
			"-p UDP -m set --match-set TRI-v4-ext-6zlJIvP3B68= dst --match multiport --dports 443 -m bpf --bytecode 20,0 0 0 0,177 0 0 0,12 0 0 0,7 0 0 0,72 0 0 4,53 0 13 29,135 0 0 0,4 0 0 8,7 0 0 0,72 0 0 2,84 0 0 64655,21 0 7 0,72 0 0 4,21 0 5 1,64 0 0 6,21 0 3 0,72 0 0 10,37 1 0 1,6 0 0 0,6 0 0 65535 -j DROP",
			"-p TCP -m set --match-set TRI-v4-ext-uNdc0vdcFZA= dst -m state --state NEW -m set ! --match-set TRI-v4-TargetTCP dst --match multiport --dports 80 -j DROP",
			"-p UDP -m set --match-set TRI-v4-ext-6zlJIvP3B68= dst --match multiport --dports 443 -m state --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 913787369:2:s2:3",
			"-p UDP -m set --match-set TRI-v4-ext-6zlJIvP3B68= dst --match multiport --dports 443 -j ACCEPT",
			"-p icmp -m set --match-set TRI-v4-ext-w5frVvhsnpU= dst -j ACCEPT",
			"-p UDP -m set --match-set TRI-v4-ext-IuSLsD1R-mE= dst -m state --state ESTABLISHED -j ACCEPT",
			"-p tcp -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 0",
			"-p tcp -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 1",
			"-p tcp -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 2",
			"-p tcp -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 3",
			"-p tcp -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 4",
			"-p tcp -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 5",
			"-p tcp -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 6",
			"-p tcp -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 7",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 0",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 1",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 2",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 3",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -m state --state ESTABLISHED -m comment --comment UDP-Established-Connections -j ACCEPT",
			"-p tcp -m state --state ESTABLISHED -m comment --comment TCP-Established-Connections -j ACCEPT",
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
			"-p tcp -m set --match-set TRI-v4-Proxy-pu19gtV-dst dst,dst -m mark ! --mark 0x40 -m cgroup --cgroup 10 -j REDIRECT --to-ports 0",
			"-d 0.0.0.0/0 -p udp --dport 53 -m mark ! --mark 0x40 -m cgroup --cgroup 10 -j CONNMARK --save-mark",
			"-d 0.0.0.0/0 -p udp --dport 53 -m mark ! --mark 0x40 -m cgroup --cgroup 10 -j REDIRECT --to-ports 0",
		},
		"TRI-Redir-Net": {
			"-m mark --mark 0x40 -j ACCEPT",
			"-p tcp -m set --match-set TRI-v4-Proxy-pu19gtV-srv dst -m mark ! --mark 0x40 -j REDIRECT --to-ports 0",
		},
		"POSTROUTING": {
			"-p udp -m addrtype --src-type LOCAL -m multiport --source-ports 5000 -j ACCEPT",
		},
	}

	expectedIPSetsAfterPUInsertV4 = map[string][]string{
		"TRI" + "-v4-" + targetTCPNetworkSet: {"0.0.0.0/1", "128.0.0.0/1"},
		"TRI" + "-v4-" + targetUDPNetworkSet: {"10.0.0.0/8"},
		"TRI" + "-v4-" + excludedNetworkSet:  {"127.0.0.1"},
		"TRI-v4-ProcPort-pu19gtV":            {"8080"},
		"TRI-v4-ext-6zlJIvP3B68=":            {"30.0.0.0/24"},
		"TRI-v4-ext-uNdc0vdcFZA=":            {"30.0.0.0/24"},
		"TRI-v4-ext-w5frVvhsnpU=":            {"40.0.0.0/24"},
		"TRI-v4-ext-IuSLsD1R-mE=":            {"40.0.0.0/24"},
		"TRI-v4-ext-_qhcdC8NcJc=":            {"60.0.0.0/24"},
		"TRI-v4-Proxy-pu19gtV-dst":           {},
		"TRI-v4-Proxy-pu19gtV-srv":           {},
	}

	expectedMangleAfterPUUpdateV4 = map[string][]string{
		"INPUT": {
			"-m set ! --match-set TRI-v4-Excluded src -j TRI-Net",
		},
		"OUTPUT": {
			"-m set ! --match-set TRI-v4-Excluded dst -j TRI-App",
		},
		"TRI-App": {
			"-j TRI-Prx-App",
			"-m mark --mark 1073741922 -j ACCEPT",
			"-m connmark --mark 61167 -j ACCEPT",
			"-m connmark --mark 61166 -p tcp ! --tcp-flags SYN,ACK SYN,ACK -j ACCEPT",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -j HMARK --hmark-tuple dst,dport,src,sport --hmark-offset 0x1 --hmark-rnd 0xdeafbee1 --hmark-mod 4",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -j HMARK --hmark-tuple dst,dport,src,sport --hmark-offset 0x1 --hmark-rnd 0xdeafbee1 --hmark-mod 4",
			"-j TRI-UID-App",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -j MARK --set-mark 0/0xfffffc00",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 8 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 9 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 10 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 11 --queue-bypass",
			"-j TRI-Pid-App",
			"-j TRI-Svc-App",
			"-j TRI-Hst-App",
		},
		"TRI-Net": {
			"-j TRI-Prx-Net",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -j HMARK --hmark-tuple src,sport,dst,dport --hmark-offset 0x1 --hmark-rnd 0xdeafbee1 --hmark-mod 4",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -m mark --mark 1/0x3ff -j NFQUEUE --queue-bypass --queue-num 24",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -m mark --mark 2/0x3ff -j NFQUEUE --queue-bypass --queue-num 25",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -m mark --mark 3/0x3ff -j NFQUEUE --queue-bypass --queue-num 26",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -m mark --mark 4/0x3ff -j NFQUEUE --queue-bypass --queue-num 27",
			"-m connmark --mark 61167 -j ACCEPT",
			"-m connmark --mark 61166 -p tcp ! --tcp-flags SYN,ACK SYN,ACK -j ACCEPT",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -j HMARK --hmark-tuple src,sport,dst,dport --hmark-offset 0x1 --hmark-rnd 0xdeafbee1 --hmark-mod 4",
			"-j TRI-UID-Net",
			"-m set --match-set TRI-v4-TargetTCP src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 24 --queue-bypass",
			"-m set --match-set TRI-v4-TargetTCP src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 25 --queue-bypass",
			"-m set --match-set TRI-v4-TargetTCP src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 26 --queue-bypass",
			"-m set --match-set TRI-v4-TargetTCP src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 27 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 16 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 17 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 18 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 19 --queue-bypass",
			"-j TRI-Pid-Net",
			"-j TRI-Svc-Net",
			"-j TRI-Hst-Net",
		},
		"TRI-Pid-App": {
			"-m cgroup --cgroup 10 -m comment --comment PU-Chain -j MARK --set-mark 10485760/0xfffffc00",
			"-m mark --mark 10485760/0xfffffc00 -m comment --comment PU-Chain -j TRI-App-pu1N7uS6--1",
		},
		"TRI-Pid-Net": {
			"-p tcp -m set --match-set TRI-v4-ProcPort-pu19gtV dst -m comment --comment PU-Chain -j TRI-Net-pu1N7uS6--1",
		},
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
		"TRI-UID-App": {},
		"TRI-UID-Net": {},

		"TRI-Net-pu1N7uS6--1": {
			"-p TCP -m set --match-set TRI-v4-ext-w5frVvhsnpU= src -m state --state NEW -m set ! --match-set TRI-v4-TargetTCP src --match multiport --dports 80 -j DROP",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 16",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 17",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 18",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 19",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 20",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 21",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 22",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 23",
			"-p udp -m set --match-set TRI-v4-TargetUDP src --match limit --limit 1000/s -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 16",
			"-p udp -m set --match-set TRI-v4-TargetUDP src --match limit --limit 1000/s -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 17",
			"-p udp -m set --match-set TRI-v4-TargetUDP src --match limit --limit 1000/s -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 18",
			"-p udp -m set --match-set TRI-v4-TargetUDP src --match limit --limit 1000/s -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 19",
			"-p tcp -m state --state ESTABLISHED -m comment --comment TCP-Established-Connections -j ACCEPT",
			"-s 0.0.0.0/0 -m state --state NEW -j NFLOG --nflog-group 11 --nflog-prefix 913787369:default:default:6",
			"-s 0.0.0.0/0 -m state ! --state NEW -j NFLOG --nflog-group 11 --nflog-prefix 913787369:default:default:10",
			"-s 0.0.0.0/0 -j DROP",
		},

		"TRI-App-pu1N7uS6--1": {
			"-p TCP -m set --match-set TRI-v4-ext-uNdc0vdcFZA= dst -m state --state NEW -m set ! --match-set TRI-v4-TargetTCP dst --match multiport --dports 80 -j DROP",
			"-p tcp -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 0",
			"-p tcp -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 1",
			"-p tcp -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 2",
			"-p tcp -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 3",
			"-p tcp -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 4",
			"-p tcp -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 5",
			"-p tcp -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 6",
			"-p tcp -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 7",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 0",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 1",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 2",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 3",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -m state --state ESTABLISHED -m comment --comment UDP-Established-Connections -j ACCEPT",
			"-p tcp -m state --state ESTABLISHED -m comment --comment TCP-Established-Connections -j ACCEPT",
			"-d 0.0.0.0/0 -m state --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 913787369:default:default:6",
			"-d 0.0.0.0/0 -m state ! --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 913787369:default:default:10",
			"-d 0.0.0.0/0 -j DROP",
		},
	}
)

func Test_OperationWithLinuxServicesV4(t *testing.T) {
	Convey("Given an iptables controller with a memory backend ", t, func() {
		cfg := &runtime.Configuration{
			TCPTargetNetworks: []string{"0.0.0.0/0"},
			UDPTargetNetworks: []string{"10.0.0.0/8"},
			ExcludedNetworks:  []string{"127.0.0.1"},
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

			for set, targets := range ipsv4.sets {
				So(expectedGlobalIPSetsV4, ShouldContainKey, set)
				for target := range targets.set {
					So(expectedGlobalIPSetsV4[set], ShouldContain, target)
				}
			}

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
						Ports:     []string{"443"},
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
				i.iptv4.aclmanager.RegisterExternalNets("pu1", iprules) //nolint

				err = i.iptv4.ConfigureRules(0, "pu1", puInfo)
				So(err, ShouldBeNil)
				err = i.AddPortToPortSet("pu1", "8080")
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

				for set, targets := range ipsv4.sets {
					So(expectedIPSetsAfterPUInsertV4, ShouldContainKey, set)
					for target := range targets.set {
						So(expectedIPSetsAfterPUInsertV4[set], ShouldContain, target)
					}
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
					)
					puInfoUpdated := policy.NewPUInfo("Context", "/ns1", common.LinuxProcessPU)
					puInfoUpdated.Policy = policyrules
					puInfoUpdated.Runtime.SetOptions(policy.OptionsType{
						CgroupMark: "10",
					})

					var iprules policy.IPRuleList

					iprules = append(iprules, puInfoUpdated.Policy.ApplicationACLs()...)
					iprules = append(iprules, puInfoUpdated.Policy.NetworkACLs()...)

					i.iptv4.aclmanager.RegisterExternalNets("pu1", iprules) //nolint

					err := i.iptv4.UpdateRules(1, "pu1", puInfoUpdated, puInfo)
					So(err, ShouldBeNil)
					i.iptv4.aclmanager.DestroyUnusedIPsets()

					t := i.iptv4.impl.RetrieveTable()
					for chain, rules := range t["mangle"] {
						So(expectedMangleAfterPUUpdateV4, ShouldContainKey, chain)
						So(rules, ShouldResemble, expectedMangleAfterPUUpdateV4[chain])
					}
					Convey("When I delete the same rule, the chains must be restored in the global state", func() {
						err := i.iptv4.DeleteRules(1, "pu1", "0", "5000", "10", "", puInfoUpdated)
						i.iptv4.aclmanager.RemoveExternalNets("pu1")
						So(err, ShouldBeNil)
						err = i.DeletePortFromPortSet("pu1", "8080")
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

func Test_ExtensionsV4(t *testing.T) {
	Convey("Given an iptables controller with a memory backend with extensions in policy and log disabled", t, func() {
		cfg := &runtime.Configuration{
			TCPTargetNetworks: []string{"0.0.0.0/0"},
			UDPTargetNetworks: []string{"10.0.0.0/8"},
			ExcludedNetworks:  []string{"127.0.0.1"},
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

		Convey("When I start the controller, I should get the right global chains and ipsets and proper extensions should be configured", func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			err := i.Run(ctx)
			i.SetTargetNetworks(cfg) //nolint
			So(err, ShouldBeNil)

			for set, targets := range ipsv4.sets {
				So(expectedGlobalIPSetsV4, ShouldContainKey, set)
				for target := range targets.set {
					So(expectedGlobalIPSetsV4[set], ShouldContain, target)
				}
			}

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
						Extensions: []string{"--match multiport --dports 443 -m bpf --bytecode \"20,0 0 0 0,177 0 0 0,12 0 0 0,7 0 0 0,72 0 0 4,53 0 13 29,135 0 0 0,4 0 0 8,7 0 0 0,72 0 0 2,84 0 0 64655,21 0 7 0,72 0 0 4,21 0 5 1,64 0 0 6,21 0 3 0,72 0 0 10,37 1 0 1,6 0 0 0,6 0 0 65535\" -j DROP"},
					},
					policy.IPRule{
						Addresses: []string{"50.0.0.0/24"},
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
				i.iptv4.aclmanager.RegisterExternalNets("pu1", iprules) //nolint

				err = i.iptv4.ConfigureRules(0, "pu1", puInfo)
				So(err, ShouldBeNil)
				err = i.AddPortToPortSet("pu1", "8080")
				So(err, ShouldBeNil)
				t := i.iptv4.impl.RetrieveTable()

				for chain, rules := range t["mangle"] {
					So(expectedMangleAfterPUInsertWithExtensionsV4, ShouldContainKey, chain)
					So(rules, ShouldResemble, expectedMangleAfterPUInsertWithExtensionsV4[chain])
				}

				for chain, rules := range t["nat"] {
					So(expectedNATAfterPUInsertV4, ShouldContainKey, chain)
					So(rules, ShouldResemble, expectedNATAfterPUInsertV4[chain])
				}

				for set, targets := range ipsv4.sets {
					So(expectedIPSetsAfterPUInsertV4, ShouldContainKey, set)
					for target := range targets.set {
						So(expectedIPSetsAfterPUInsertV4[set], ShouldContain, target)
					}
				}
			})
		})
	})

	Convey("Given an iptables controller with a memory backend with bad extensions in policy and log enabled", t, func() {
		cfg := &runtime.Configuration{
			TCPTargetNetworks: []string{"0.0.0.0/0"},
			UDPTargetNetworks: []string{"10.0.0.0/8"},
			ExcludedNetworks:  []string{"127.0.0.1"},
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

		Convey("When I start the controller, I should get the right global chains and ipsets and proper drop extension should be configured", func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			err := i.Run(ctx)
			i.SetTargetNetworks(cfg) //nolint
			So(err, ShouldBeNil)

			for set, targets := range ipsv4.sets {
				So(expectedGlobalIPSetsV4, ShouldContainKey, set)
				for target := range targets.set {
					So(expectedGlobalIPSetsV4[set], ShouldContain, target)
				}
			}

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
							Action:    policy.Accept | policy.Log,
							ServiceID: "s2",
							PolicyID:  "2",
						},
						Extensions: []string{" -j DROP"},
					},
					policy.IPRule{
						Addresses: []string{"50.0.0.0/24"},
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
				i.iptv4.aclmanager.RegisterExternalNets("pu1", iprules) //nolint

				err = i.iptv4.ConfigureRules(0, "pu1", puInfo)
				So(err, ShouldBeNil)
				err = i.AddPortToPortSet("pu1", "8080")
				So(err, ShouldBeNil)
				t := i.iptv4.impl.RetrieveTable()

				for chain, rules := range t["mangle"] {
					So(expectedMangleAfterPUInsertWithLogV4, ShouldContainKey, chain)
					So(rules, ShouldResemble, expectedMangleAfterPUInsertWithLogV4[chain])
				}

				for chain, rules := range t["nat"] {
					So(expectedNATAfterPUInsertV4, ShouldContainKey, chain)
					So(rules, ShouldResemble, expectedNATAfterPUInsertV4[chain])
				}

				for set, targets := range ipsv4.sets {
					So(expectedIPSetsAfterPUInsertV4, ShouldContainKey, set)
					for target := range targets.set {
						So(expectedIPSetsAfterPUInsertV4[set], ShouldContain, target)
					}
				}
			})
		})
	})

	Convey("Given an iptables controller with a memory backend with extensions in policy and log enabled", t, func() {
		cfg := &runtime.Configuration{
			TCPTargetNetworks: []string{"0.0.0.0/0"},
			UDPTargetNetworks: []string{"10.0.0.0/8"},
			ExcludedNetworks:  []string{"127.0.0.1"},
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

		Convey("When I start the controller, I should get the right global chains and ipsets and proper drop extension should be configured", func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			err := i.Run(ctx)
			i.SetTargetNetworks(cfg) //nolint
			So(err, ShouldBeNil)

			for set, targets := range ipsv4.sets {
				So(expectedGlobalIPSetsV4, ShouldContainKey, set)
				for target := range targets.set {
					So(expectedGlobalIPSetsV4[set], ShouldContain, target)
				}
			}

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
							// Log enabled.
							Action:    policy.Accept | policy.Log,
							ServiceID: "s2",
							PolicyID:  "2",
						},
						Extensions: []string{"--match multiport --dports 443  -m bpf --bytecode \"20,0 0 0 0,177 0 0 0,12 0 0 0,7 0 0 0,72 0 0 4,53 0 13 29,135 0 0 0,4 0 0 8,7 0 0 0,72 0 0 2,84 0 0 64655,21 0 7 0,72 0 0 4,21 0 5 1,64 0 0 6,21 0 3 0,72 0 0 10,37 1 0 1,6 0 0 0,6 0 0 65535\" -j DROP"},
					},
					policy.IPRule{
						Addresses: []string{"50.0.0.0/24"},
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
				i.iptv4.aclmanager.RegisterExternalNets("pu1", iprules) //nolint

				err = i.iptv4.ConfigureRules(0, "pu1", puInfo)
				So(err, ShouldBeNil)
				err = i.AddPortToPortSet("pu1", "8080")
				So(err, ShouldBeNil)
				t := i.iptv4.impl.RetrieveTable()

				for chain, rules := range t["mangle"] {
					So(expectedMangleAfterPUInsertWithExtensionsAndLogV4, ShouldContainKey, chain)
					So(rules, ShouldResemble, expectedMangleAfterPUInsertWithExtensionsAndLogV4[chain])
				}

				for chain, rules := range t["nat"] {
					So(expectedNATAfterPUInsertV4, ShouldContainKey, chain)
					So(rules, ShouldResemble, expectedNATAfterPUInsertV4[chain])
				}

				for set, targets := range ipsv4.sets {
					So(expectedIPSetsAfterPUInsertV4, ShouldContainKey, set)
					for target := range targets.set {
						So(expectedIPSetsAfterPUInsertV4[set], ShouldContain, target)
					}
				}
			})
		})
	})
}

var (
	expectedContainerGlobalMangleChainsV4 = map[string][]string{
		"INPUT": {
			"-m set ! --match-set TRI-v4-Excluded src -j TRI-Net",
		},
		"OUTPUT": {
			"-m set ! --match-set TRI-v4-Excluded dst -j TRI-App",
		},
		"TRI-App": {
			"-j TRI-Prx-App",
			"-m mark --mark 1073741922 -j ACCEPT",
			"-m connmark --mark 61167 -j ACCEPT",
			"-m connmark --mark 61166 -p tcp ! --tcp-flags SYN,ACK SYN,ACK -j ACCEPT",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -j HMARK --hmark-tuple dst,dport,src,sport --hmark-offset 0x1 --hmark-rnd 0xdeafbee1 --hmark-mod 4",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -j HMARK --hmark-tuple dst,dport,src,sport --hmark-offset 0x1 --hmark-rnd 0xdeafbee1 --hmark-mod 4",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -j MARK --set-mark 0/0xfffffc00",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 8 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 9 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 10 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 11 --queue-bypass",
		},
		"TRI-Net": {
			"-j TRI-Prx-Net",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -j HMARK --hmark-tuple src,sport,dst,dport --hmark-offset 0x1 --hmark-rnd 0xdeafbee1 --hmark-mod 4",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -m mark --mark 1/0x3ff -j NFQUEUE --queue-bypass --queue-num 24",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -m mark --mark 2/0x3ff -j NFQUEUE --queue-bypass --queue-num 25",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -m mark --mark 3/0x3ff -j NFQUEUE --queue-bypass --queue-num 26",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -m mark --mark 4/0x3ff -j NFQUEUE --queue-bypass --queue-num 27",
			"-m connmark --mark 61167 -j ACCEPT",
			"-m connmark --mark 61166 -p tcp ! --tcp-flags SYN,ACK SYN,ACK -j ACCEPT",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -j HMARK --hmark-tuple src,sport,dst,dport --hmark-offset 0x1 --hmark-rnd 0xdeafbee1 --hmark-mod 4",
			"-m set --match-set TRI-v4-TargetTCP src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 24 --queue-bypass",
			"-m set --match-set TRI-v4-TargetTCP src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 25 --queue-bypass",
			"-m set --match-set TRI-v4-TargetTCP src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 26 --queue-bypass",
			"-m set --match-set TRI-v4-TargetTCP src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 27 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 16 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 17 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 18 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 19 --queue-bypass",
		},

		"TRI-Prx-App": {
			"-m mark --mark 0x40 -j ACCEPT",
		},
		"TRI-Prx-Net": {
			"-m mark --mark 0x40 -j ACCEPT",
		},
	}

	expectedContainerGlobalNATChainsV4 = map[string][]string{
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

	expectedContainerGlobalIPSetsV4 = map[string][]string{
		"TRI" + "-v4-" + targetTCPNetworkSet: {"0.0.0.0/1", "128.0.0.0/1"},
		"TRI" + "-v4-" + targetUDPNetworkSet: {"10.0.0.0/8"},
		"TRI" + "-v4-" + excludedNetworkSet:  {"127.0.0.1"},
	}

	expectedContainerMangleAfterPUInsertV4 = map[string][]string{
		"INPUT": {
			"-m set ! --match-set TRI-v4-Excluded src -j TRI-Net",
		},
		"OUTPUT": {
			"-m set ! --match-set TRI-v4-Excluded dst -j TRI-App",
		},
		"TRI-App": {
			"-j TRI-Prx-App",
			"-m mark --mark 1073741922 -j ACCEPT",
			"-m connmark --mark 61167 -j ACCEPT",
			"-m connmark --mark 61166 -p tcp ! --tcp-flags SYN,ACK SYN,ACK -j ACCEPT",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -j HMARK --hmark-tuple dst,dport,src,sport --hmark-offset 0x1 --hmark-rnd 0xdeafbee1 --hmark-mod 4",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -j HMARK --hmark-tuple dst,dport,src,sport --hmark-offset 0x1 --hmark-rnd 0xdeafbee1 --hmark-mod 4",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -j MARK --set-mark 0/0xfffffc00",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 8 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 9 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 10 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 11 --queue-bypass",
			"-m comment --comment Container-specific-chain -j TRI-App-pu1N7uS6--0",
		},
		"TRI-Net": {
			"-j TRI-Prx-Net",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -j HMARK --hmark-tuple src,sport,dst,dport --hmark-offset 0x1 --hmark-rnd 0xdeafbee1 --hmark-mod 4",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -m mark --mark 1/0x3ff -j NFQUEUE --queue-bypass --queue-num 24",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -m mark --mark 2/0x3ff -j NFQUEUE --queue-bypass --queue-num 25",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -m mark --mark 3/0x3ff -j NFQUEUE --queue-bypass --queue-num 26",
			"-p udp -m set --match-set TRI-v4-TargetUDP src -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -m mark --mark 4/0x3ff -j NFQUEUE --queue-bypass --queue-num 27",
			"-m connmark --mark 61167 -j ACCEPT",
			"-m connmark --mark 61166 -p tcp ! --tcp-flags SYN,ACK SYN,ACK -j ACCEPT",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -j HMARK --hmark-tuple src,sport,dst,dport --hmark-offset 0x1 --hmark-rnd 0xdeafbee1 --hmark-mod 4",
			"-m set --match-set TRI-v4-TargetTCP src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 24 --queue-bypass",
			"-m set --match-set TRI-v4-TargetTCP src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 25 --queue-bypass",
			"-m set --match-set TRI-v4-TargetTCP src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 26 --queue-bypass",
			"-m set --match-set TRI-v4-TargetTCP src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 27 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 16 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 17 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 18 --queue-bypass",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 19 --queue-bypass",
			"-m comment --comment Container-specific-chain -j TRI-Net-pu1N7uS6--0",
		},
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
		"TRI-Net-pu1N7uS6--0": {
			"-p UDP -m set --match-set TRI-v4-ext-6zlJIvP3B68= src -m state --state ESTABLISHED -j ACCEPT",
			"-p TCP -m set --match-set TRI-v4-ext-w5frVvhsnpU= src -m state --state NEW -m set ! --match-set TRI-v4-TargetTCP src --match multiport --dports 80 -j DROP",
			"-p UDP -m set --match-set TRI-v4-ext-IuSLsD1R-mE= src --match multiport --dports 443 -j ACCEPT",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 16",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 17",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 18",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 19",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 20",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 21",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 22",
			"-p tcp -m set --match-set TRI-v4-TargetTCP src -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 23",
			"-p udp -m set --match-set TRI-v4-TargetUDP src --match limit --limit 1000/s -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 16",
			"-p udp -m set --match-set TRI-v4-TargetUDP src --match limit --limit 1000/s -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 17",
			"-p udp -m set --match-set TRI-v4-TargetUDP src --match limit --limit 1000/s -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 18",
			"-p udp -m set --match-set TRI-v4-TargetUDP src --match limit --limit 1000/s -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 19",
			"-p tcp -m state --state ESTABLISHED -m comment --comment TCP-Established-Connections -j ACCEPT",
			"-s 0.0.0.0/0 -m state --state NEW -j NFLOG --nflog-group 11 --nflog-prefix 913787369:default:default:6",
			"-s 0.0.0.0/0 -m state ! --state NEW -j NFLOG --nflog-group 11 --nflog-prefix 913787369:default:default:10",
			"-s 0.0.0.0/0 -j DROP",
		},

		"TRI-App-pu1N7uS6--0": {
			"-p TCP -m set --match-set TRI-v4-ext-uNdc0vdcFZA= dst -m state --state NEW -m set ! --match-set TRI-v4-TargetTCP dst --match multiport --dports 80 -j DROP",
			"-p UDP -m set --match-set TRI-v4-ext-6zlJIvP3B68= dst --match multiport --dports 443 -j ACCEPT",
			"-p UDP -m set --match-set TRI-v4-ext-IuSLsD1R-mE= dst -m state --state ESTABLISHED -j ACCEPT",
			"-p tcp -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 0",
			"-p tcp -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 1",
			"-p tcp -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 2",
			"-p tcp -m tcp --tcp-flags SYN,ACK SYN -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 3",
			"-p tcp -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 4",
			"-p tcp -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 5",
			"-p tcp -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 6",
			"-p tcp -m tcp --tcp-flags SYN,ACK ACK -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 7",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -m mark --mark 1/0x3ff -j NFQUEUE --queue-num 0",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -m mark --mark 2/0x3ff -j NFQUEUE --queue-num 1",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -m mark --mark 3/0x3ff -j NFQUEUE --queue-num 2",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -m mark --mark 4/0x3ff -j NFQUEUE --queue-num 3",
			"-p udp -m set --match-set TRI-v4-TargetUDP dst -m state --state ESTABLISHED -m comment --comment UDP-Established-Connections -j ACCEPT",
			"-p tcp -m state --state ESTABLISHED -m comment --comment TCP-Established-Connections -j ACCEPT",
			"-d 0.0.0.0/0 -m state --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 913787369:default:default:6",
			"-d 0.0.0.0/0 -m state ! --state NEW -j NFLOG --nflog-group 10 --nflog-prefix 913787369:default:default:10",
			"-d 0.0.0.0/0 -j DROP",
		},
	}

	expectedContainerNATAfterPUInsertV4 = map[string][]string{
		"PREROUTING": {
			"-p tcp -m addrtype --dst-type LOCAL -m set ! --match-set TRI-v4-Excluded src -j TRI-Redir-Net",
		},
		"OUTPUT": {
			"-m set ! --match-set TRI-v4-Excluded dst -j TRI-Redir-App",
		},
		"TRI-Redir-App": {
			"-m mark --mark 0x40 -j ACCEPT",
			"-p tcp -m set --match-set TRI-v4-Proxy-pu19gtV-dst dst,dst -m mark ! --mark 0x40 -m cgroup --cgroup 10 -j REDIRECT --to-ports 0",
			"-d 0.0.0.0/0 -p udp --dport 53 -m mark ! --mark 0x40 -m cgroup --cgroup 10 -j CONNMARK --save-mark",
			"-d 0.0.0.0/0 -p udp --dport 53 -m mark ! --mark 0x40 -m cgroup --cgroup 10 -j REDIRECT --to-ports 0",
		},
		"TRI-Redir-Net": {
			"-m mark --mark 0x40 -j ACCEPT",
			"-p tcp -m set --match-set TRI-v4-Proxy-pu19gtV-srv dst -m mark ! --mark 0x40 -j REDIRECT --to-ports 0",
		},
	}
	expectedContainerIPSetsAfterPUInsertV4 = map[string][]string{
		"TRI-v4-" + targetTCPNetworkSet: {"0.0.0.0/1", "128.0.0.0/1"},
		"TRI-v4-" + targetUDPNetworkSet: {"10.0.0.0/8"},
		"TRI-v4-" + excludedNetworkSet:  {"127.0.0.1"},
		"TRI-v4-ProcPort-pu19gtV":       {"8080"},
		"TRI-v4-ext-6zlJIvP3B68=":       {"30.0.0.0/24"},
		"TRI-v4-ext-uNdc0vdcFZA=":       {"30.0.0.0/24"},
		"TRI-v4-ext-w5frVvhsnpU=":       {"40.0.0.0/24"},
		"TRI-v4-ext-IuSLsD1R-mE=":       {"40.0.0.0/24"},
		"TRI-v4-Proxy-pu19gtV-dst":      {},
		"TRI-v4-Proxy-pu19gtV-srv":      {},
	}
)

func Test_OperationWithContainersV4(t *testing.T) {
	Convey("Given an iptables controller with a memory backend for containers ", t, func() {
		cfg := &runtime.Configuration{
			TCPTargetNetworks: []string{"0.0.0.0/0"},
			UDPTargetNetworks: []string{"10.0.0.0/8"},
			ExcludedNetworks:  []string{"127.0.0.1"},
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
			i.SetTargetNetworks(cfg) //nolint
			So(err, ShouldBeNil)

			for set, targets := range ipsv4.sets {
				So(expectedContainerGlobalIPSetsV4, ShouldContainKey, set)
				for target := range targets.set {
					So(expectedContainerGlobalIPSetsV4[set], ShouldContain, target)
				}
			}

			t := i.iptv4.impl.RetrieveTable()
			So(t, ShouldNotBeNil)
			So(len(t), ShouldEqual, 2)
			So(t["mangle"], ShouldNotBeNil)
			So(t["nat"], ShouldNotBeNil)

			for chain, rules := range t["mangle"] {
				So(expectedContainerGlobalMangleChainsV4, ShouldContainKey, chain)
				So(rules, ShouldResemble, expectedContainerGlobalMangleChainsV4[chain])
			}

			for chain, rules := range t["nat"] {
				So(expectedContainerGlobalNATChainsV4, ShouldContainKey, chain)
				So(rules, ShouldResemble, expectedContainerGlobalNATChainsV4[chain])
			}

			Convey("When I configure a new set of rules, the ACLs must be correct", func() {
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
				i.iptv4.aclmanager.RegisterExternalNets("pu1", iprules) //nolint

				err := i.iptv4.ConfigureRules(0, "pu1", puInfo)
				So(err, ShouldBeNil)
				t := i.iptv4.impl.RetrieveTable()

				for chain, rules := range t["mangle"] {
					So(expectedContainerMangleAfterPUInsertV4, ShouldContainKey, chain)
					So(rules, ShouldResemble, expectedContainerMangleAfterPUInsertV4[chain])
				}

				for chain, rules := range t["nat"] {
					So(expectedContainerNATAfterPUInsertV4, ShouldContainKey, chain)
					So(rules, ShouldResemble, expectedContainerNATAfterPUInsertV4[chain])
				}

				for set, targets := range ipsv4.sets {
					So(expectedContainerIPSetsAfterPUInsertV4, ShouldContainKey, set)
					for target := range targets.set {
						So(expectedContainerIPSetsAfterPUInsertV4[set], ShouldContain, target)
					}
				}

				Convey("When I delete the same rule, the chains must be restored in the global state", func() {
					err := i.iptv4.DeleteRules(0, "pu1", "0", "0", "10", "", puInfo)
					So(err, ShouldBeNil)

					t := i.iptv4.impl.RetrieveTable()
					if err != nil {
						printTable(t)
					}

					So(t["mangle"], ShouldNotBeNil)
					So(t["nat"], ShouldNotBeNil)

					for chain, rules := range t["mangle"] {
						So(expectedContainerGlobalMangleChainsV4, ShouldContainKey, chain)
						So(rules, ShouldResemble, expectedContainerGlobalMangleChainsV4[chain])
					}

					for chain, rules := range t["nat"] {
						So(expectedContainerGlobalNATChainsV4, ShouldContainKey, chain)
						So(rules, ShouldResemble, expectedContainerGlobalNATChainsV4[chain])
					}
				})

			})
		})
	})
}

func TestImpl(t *testing.T) {
	instance, err := NewInstance(nil, constants.LocalServer, nil, true, nil)
	assert.Equal(t, instance != nil, true, "instance should not be nil")
	assert.Equal(t, err == nil, true, "err should be nil")
}

func printTable(t map[string]map[string][]string) {
	fmt.Printf("\n")
	for table, chains := range t {
		fmt.Println(table)
		for chain, rules := range chains {
			fmt.Println(chain)
			for _, rule := range rules {
				fmt.Println(rule)
			}
		}
	}
}
