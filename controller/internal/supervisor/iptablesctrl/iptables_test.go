package iptablesctrl

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/aporeto-inc/go-ipset/ipset"
	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/controller/constants"
	provider "go.aporeto.io/trireme-lib/controller/pkg/aclprovider"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/controller/runtime"
	"go.aporeto.io/trireme-lib/policy"
)

const testIP = "172.17.0.1"

func createTestInstance(mode constants.ModeType) (*Instance, error) {
	ips := provider.NewTestIpsetProvider()
	ipt := provider.NewTestIptablesProvider()

	return newInstanceWithProviders(fqconfig.NewFilterQueueWithDefaults(), mode, &runtime.Configuration{}, ipt, ips)
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
	fmt.Println("I AM HERE .........", entry)
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

func TestNewInstance(t *testing.T) {
	Convey("When I create a new iptables instance", t, func() {
		Convey("If I create a remote implemenetation and iptables exists", func() {
			i, err := createTestInstance(constants.RemoteContainer)
			Convey("It should succeed", func() {
				So(i, ShouldNotBeNil)
				So(err, ShouldBeNil)
				So(i.appPacketIPTableSection, ShouldResemble, "OUTPUT")
				So(i.netPacketIPTableSection, ShouldResemble, "INPUT")
			})
		})

		Convey("If ipsets fails to initialize, I should get an error", func() {
			ips := provider.NewTestIpsetProvider()
			ipt := provider.NewTestIptablesProvider()

			ips.MockNewIpset(t, func(set, hash string, p *ipset.Params) (provider.Ipset, error) {
				return nil, fmt.Errorf("new ipset error")
			})

			i, err := newInstanceWithProviders(
				fqconfig.NewFilterQueueWithDefaults(),
				constants.LocalServer,
				&runtime.Configuration{},
				ipt,
				ips,
			)

			Convey("I should get an error", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "new ipset error")
				So(i, ShouldBeNil)
			})
		})

		Convey("If SetTargetNetworks fails to initialize, I should get an error", func() {
			ips := provider.NewTestIpsetProvider()
			ipt := provider.NewTestIptablesProvider()

			s1 := provider.NewTestIpset()
			s2 := provider.NewTestIpset()
			s3 := provider.NewTestIpset()

			ips.MockNewIpset(t, func(set, hash string, p *ipset.Params) (provider.Ipset, error) {
				switch set {
				case targetTCPNetworkSet:
					return s1, nil
				case targetUDPNetworkSet:
					return s2, nil
				case excludedNetworkSet:
					return s3, nil
				}
				return provider.NewTestIpset(), nil
			})

			cfg := &runtime.Configuration{
				TCPTargetNetworks: []string{"10.1.1.0/24"},
			}

			s1.MockAdd(t, func(entry string, timeout int) error {
				if entry == "10.1.1.0/24" {
					return fmt.Errorf("failed to add set")
				}
				return nil
			})

			i, err := newInstanceWithProviders(
				fqconfig.NewFilterQueueWithDefaults(),
				constants.LocalServer,
				cfg,
				ipt,
				ips,
			)

			Convey("I should get an error", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "failed to add set")
				So(i, ShouldBeNil)
			})
		})

		Convey("If SetTargetNetworks fails the sets must be cleaned up", func() {
			ips := provider.NewTestIpsetProvider()
			ipt := provider.NewTestIptablesProvider()

			s1 := provider.NewTestIpset()
			s2 := provider.NewTestIpset()
			s3 := provider.NewTestIpset()

			ips.MockNewIpset(t, func(set, hash string, p *ipset.Params) (provider.Ipset, error) {
				switch set {
				case targetTCPNetworkSet:
					return s1, nil
				case targetUDPNetworkSet:
					return s2, nil
				case excludedNetworkSet:
					return s3, nil
				}
				return provider.NewTestIpset(), nil
			})

			cfg := &runtime.Configuration{
				TCPTargetNetworks: []string{"10.1.1.0/24"},
			}

			s1.MockAdd(t, func(entry string, timeout int) error {
				if entry == "10.1.1.0/24" {
					return fmt.Errorf("failed to add set")
				}
				return nil
			})

			ips.MockDestroyAll(t, func(string) error {
				panic("test")
			})

			So(func() {
				newInstanceWithProviders(
					fqconfig.NewFilterQueueWithDefaults(),
					constants.LocalServer,
					cfg,
					ipt,
					ips,
				)
			}, ShouldPanic)

		})

	})

	Convey("When I create a new iptables instance", t, func() {
		Convey("If I create a Linux server implemenetation and iptables exists", func() {
			i, err := createTestInstance(constants.LocalServer)
			Convey("It should succeed", func() {
				So(i, ShouldNotBeNil)
				So(err, ShouldBeNil)
				So(i.appPacketIPTableSection, ShouldResemble, "OUTPUT")
				So(i.netPacketIPTableSection, ShouldResemble, "INPUT")
			})
		})
	})
}

func Test_NegativeConfigureRules(t *testing.T) {
	Convey("Given a valid instance", t, func() {
		ips := provider.NewTestIpsetProvider()
		ipt := provider.NewTestIptablesProvider()
		i, err := newInstanceWithProviders(
			fqconfig.NewFilterQueueWithDefaults(),
			constants.LocalServer,
			nil,
			ipt,
			ips,
		)
		So(err, ShouldBeNil)

		ipl := policy.ExtendedMap{}
		policyrules := policy.NewPUPolicy("Context",
			policy.Police,
			nil,
			nil,
			nil,
			nil,
			nil,
			nil,
			nil,
			ipl,
			0,
			nil,
			nil,
			[]string{},
		)
		containerinfo := policy.NewPUInfo("Context", common.ContainerPU)
		containerinfo.Policy = policyrules
		containerinfo.Runtime = policy.NewPURuntimeWithDefaults()
		containerinfo.Runtime.SetOptions(policy.OptionsType{
			CgroupMark: "10",
		})

		Convey("When I configure the rules with no errors, it should succeed", func() {
			i.createPUPortSet = func(string) error { return nil }
			err := i.ConfigureRules(1, "ID", containerinfo)
			So(err, ShouldBeNil)
		})

		Convey("When I configure the rules and the port set fails, it should error ", func() {
			i.createPUPortSet = func(string) error { return fmt.Errorf("error") }
			err := i.ConfigureRules(1, "ID", containerinfo)
			So(err, ShouldNotBeNil)
		})

		Convey("When I configure the rules and the proxy set fails, it should error", func() {
			ips.MockNewIpset(t, func(name, hash string, p *ipset.Params) (provider.Ipset, error) {
				return nil, fmt.Errorf("error")
			})
			err := i.ConfigureRules(1, "ID", containerinfo)
			So(err, ShouldNotBeNil)
		})

		Convey("When I configure the rules and acls fail, it should error", func() {
			ipt.MockAppend(t, func(table, chain string, rulespec ...string) error {
				return fmt.Errorf("error")
			})
			err := i.ConfigureRules(1, "ID", containerinfo)
			So(err, ShouldNotBeNil)
		})

		Convey("When I configure the rules and commit fails, it should error", func() {
			ipt.MockCommit(t, func() error {
				return fmt.Errorf("error")
			})
			err := i.ConfigureRules(1, "ID", containerinfo)
			So(err, ShouldNotBeNil)
		})
	})
}

var (
	expectedGlobalMangleChains = map[string][]string{
		"INPUT": []string{
			"-m set ! --match-set TRI-Excluded src -j TRI-Net",
		},
		"OUTPUT": []string{
			"-m set ! --match-set TRI-Excluded dst -j TRI-App",
		},
		"TRI-App": []string{
			"-j TRI-Prx-App",
			"-m mark --mark 1073741922 -j ACCEPT",
			"-m connmark --mark 61166 -j ACCEPT",
			"-j TRI-UID-App",
			"-p tcp -m set --match-set TRI-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -j MARK --set-mark 99",
			"-p tcp -m set --match-set TRI-TargetTCP dst -m tcp --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-balance 8:11 --queue-bypass",
			"-j TRI-Pid-App",
			"-j TRI-Svc-App",
			"-j TRI-Hst-App",
		},
		"TRI-Net": []string{
			"-j TRI-Prx-Net",
			"-p udp -m set --match-set TRI-TargetUDP src -m string --string n30njxq7bmiwr6dtxq --algo bm --to 65535 -j NFQUEUE --queue-bypass --queue-balance 24:27",
			"-m connmark --mark 61166 -j ACCEPT",
			"-m set --match-set TRI-TargetTCP src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-balance 24:27 --queue-bypass",
			"-p tcp -m set --match-set TRI-TargetTCP src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -j NFQUEUE --queue-balance 16:19 --queue-bypass",
			"-j TRI-UID-Net",
			"-j TRI-Pid-Net",
			"-j TRI-Svc-Net",
			"-j TRI-Hst-Net",
		},
		"TRI-Pid-App": []string{},
		"TRI-Pid-Net": []string{},
		"TRI-Prx-App": []string{
			"-m mark --mark 0x40 -j ACCEPT",
		},
		"TRI-Prx-Net": []string{
			"-m mark --mark 0x40 -j ACCEPT",
		},
		"TRI-Hst-App": []string{},
		"TRI-Hst-Net": []string{},
		"TRI-Svc-App": []string{},
		"TRI-Svc-Net": []string{},
		"TRI-UID-App": []string{},
		"TRI-UID-Net": []string{},
	}

	expectedGlobalNATChains = map[string][]string{
		"PREROUTING": []string{
			"-p tcp -m addrtype --dst-type LOCAL -m set ! --match-set TRI-Excluded src -j TRI-Redir-Net",
		},
		"OUTPUT": []string{
			"-m set ! --match-set TRI-Excluded dst -j TRI-Redir-App",
		},
		"TRI-Redir-App": []string{
			"-m mark --mark 0x40 -j ACCEPT",
		},
		"TRI-Redir-Net": []string{
			"-m mark --mark 0x40 -j ACCEPT",
		},
	}

	expectedGlobalIPSets = map[string][]string{
		targetTCPNetworkSet: []string{"0.0.0.0/1", "128.0.0.0/1"},
		targetUDPNetworkSet: []string{"10.0.0.0/8"},
		excludedNetworkSet:  []string{"127.0.0.1"},
	}
)

func Test_Operation(t *testing.T) {
	Convey("Given an iptables controller with a memory backend ", t, func() {
		commitFunc := func(buf *bytes.Buffer) error {
			return nil
		}

		ipt := provider.NewCustomBatchProvider(&baseIpt{}, commitFunc, []string{"nat", "mangle"})
		So(ipt, ShouldNotBeNil)
		ips := &memoryIPSetProvider{sets: map[string]*memoryIPSet{}}
		i, err := newInstanceWithProviders(
			fqconfig.NewFilterQueueWithDefaults(),
			constants.LocalServer,
			&runtime.Configuration{
				TCPTargetNetworks: []string{"0.0.0.0/0"},
				UDPTargetNetworks: []string{"10.0.0.0/8"},
				ExcludedNetworks:  []string{"127.0.0.1"},
			},
			ipt,
			ips,
		)
		So(err, ShouldBeNil)
		So(i, ShouldNotBeNil)

		for set, targets := range ips.sets {
			So(expectedGlobalIPSets, ShouldContainKey, set)
			for target := range targets.set {
				So(expectedGlobalIPSets[set], ShouldContain, target)
			}
		}

		Convey("When I start the controller, I should get the right global chains", func() {
			ctx, cancel := context.WithCancel(context.TODO())
			defer cancel()
			err := i.Run(ctx)
			So(err, ShouldBeNil)

			t := ipt.RetrieveTable()
			So(t, ShouldNotBeNil)
			So(len(t), ShouldEqual, 2)
			So(t["mangle"], ShouldNotBeNil)
			So(t["nat"], ShouldNotBeNil)

			for chain, rules := range t["mangle"] {
				So(expectedGlobalMangleChains, ShouldContainKey, chain)
				So(rules, ShouldResemble, expectedGlobalMangleChains[chain])
			}

			for chain, rules := range t["nat"] {
				So(expectedGlobalNATChains, ShouldContainKey, chain)
				So(rules, ShouldResemble, expectedGlobalNATChains[chain])
			}

			Convey("When I configure a new set of rules, the ACLs must be correct", func() {
				// Mock the exec commands
				i.createPUPortSet = func(setName string) error {
					ips.NewIpset(setName, "bitmap:port", &ipset.Params{})
					return nil
				}

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
						Protocols: []string{"TCP"},
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
						Protocols: []string{"TCP"},
						Policy: &policy.FlowPolicy{
							Action:    policy.Accept,
							ServiceID: "s4",
							PolicyID:  "2",
						},
					},
				}
				ipl := policy.ExtendedMap{}
				policyrules := policy.NewPUPolicy("Context",
					policy.Police,
					appACLs,
					netACLs,
					nil,
					nil,
					nil,
					nil,
					nil,
					ipl,
					0,
					nil,
					nil,
					[]string{},
				)
				puInfo := policy.NewPUInfo("Context", common.LinuxProcessPU)
				puInfo.Policy = policyrules
				puInfo.Runtime.SetOptions(policy.OptionsType{
					CgroupMark: "10",
				})
				err := i.ConfigureRules(0, "pu1", puInfo)
				out := ipt.RetrieveTable()

				fmt.Printf("\n")
				for table, chains := range out {
					fmt.Println(table)
					for chain, rules := range chains {
						fmt.Println(chain)
						for _, rule := range rules {
							fmt.Println(rule)
						}
					}
				}
				So(err, ShouldNotBeNil)
			})
		})
	})
}
