package iptablesctrl

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aporeto-inc/go-ipset/ipset"
	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/controller/constants"
	provider "go.aporeto.io/trireme-lib/controller/pkg/aclprovider"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/monitor/extractors"
	"go.aporeto.io/trireme-lib/policy"
)

const (
	appChain = "appChain"
	errChain = "errChain"
	netChain = "netChain"
	ruleType = "mark"
)

func matchSpec(term string, rulespec []string) error {

	for _, rule := range rulespec {

		if rule == term {
			return nil
		}
	}

	return fmt.Errorf("rule not found: %s", term)
}

func TestAddContainerChain(t *testing.T) {

	Convey("Given an iptables controller", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.RemoteContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables

		Convey("When I add a container chain with no errors", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				return nil
			})
			err := i.addContainerChain(appChain, netChain)
			Convey("I should get no error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When the appPacketIPTableContext fails", func() {
			iptables.MockNewChain(t, func(table string, chain string) error {
				if table == i.appPacketIPTableContext {
					return errors.New("error")
				}
				return nil
			})
			err := i.addContainerChain(appChain, netChain)
			Convey("I should get an error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When the netPacketIPTableContext chain fails", func() {
			iptables.MockNewChain(t, func(table string, chain string) error {
				if table == i.netPacketIPTableContext {
					return errors.New("error")
				}
				return nil
			})
			err := i.addContainerChain(appChain, netChain)
			Convey("I should get an error", func() {
				So(err, ShouldNotBeNil)
			})
		})

	})
}

func TestAddChainRules(t *testing.T) {

	Convey("Given an iptables controller for LocalContainer", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.RemoteContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables

		Convey("When I add the chain rules and they succeed", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				return nil
			})

			err := i.addChainRules("context", "appchain", "netchain", "0", "100", "100", "", "", "5000", "proxyPortSet", "")
			So(err, ShouldBeNil)
		})

		Convey("When I add the chain rules and the appPacketIPTableContext fails ", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				if table == i.appPacketIPTableContext {
					return errors.New("error")
				}
				return nil
			})
			err := i.addChainRules("context", "appchain", "netchain", "0", "100", "100", "", "", "5000", "proxyPortSet", "")
			So(err, ShouldNotBeNil)

		})

		Convey("When I add the chain rules and the netPacketIPtableContext fails ", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				if table == i.netPacketIPTableContext {
					return errors.New("error")
				}
				return nil
			})
			err := i.addChainRules("context", "appchain", "netchain", "0", "100", "100", "", "", "5000", "proxyPortSet", "")
			So(err, ShouldNotBeNil)

		})

	})

	Convey("Given an iptables controller for LocalServer", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.LocalServer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables

		Convey("When I add the chain rules and they succeed for Linux PU", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				return nil
			})
			err := i.addChainRules("context", "appchain", "netchain", "0", "100", "100", "", "", "5000", "proxyPortSet", extractors.LinuxPU)
			So(err, ShouldBeNil)
		})

		Convey("When I add the chain rules for hostmode network pu and they succeed", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				return nil
			})
			err := i.addChainRules("context", "appchain", "netchain", "0", "100", "100", "", "", "5000", "proxyPortSet", extractors.HostModeNetworkPU)
			So(err, ShouldBeNil)
		})

		Convey("When I add the chain rules for hostmode  pu and they succeed", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				return nil
			})
			err := i.addChainRules("context", "appchain", "netchain", "0", "100", "100", "", "", "5000", "proxyPortSet", extractors.HostPU)
			So(err, ShouldBeNil)
		})

		Convey("When I add the chain rules and the appPacketIPTableContext fails ", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				if table == i.appPacketIPTableContext {
					return errors.New("error")
				}
				return nil
			})
			err := i.addChainRules("context", "appchain", "netchain", "0", "100", "100", "", "", "5000", "proxyPortSet", extractors.LinuxPU)
			So(err, ShouldNotBeNil)
		})

		Convey("When I add the chain rules and the appPacketIPTableContext fails in hostmode network pu ", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				if table == i.appPacketIPTableContext {
					return errors.New("error")
				}
				return nil
			})
			err := i.addChainRules("context", "appchain", "netchain", "0", "100", "100", "", "", "5000", "proxyPortSet", extractors.HostModeNetworkPU)
			So(err, ShouldNotBeNil)
		})

		Convey("When I add the chain rules and the netPacketIPtableContext fails ", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				if table == i.netPacketIPTableContext {
					return errors.New("error")
				}
				return nil
			})
			err := i.addChainRules("context", "appchain", "netchain", "0", "100", "100", "", "", "5000", "proxyPortSet", extractors.HostPU)
			So(err, ShouldNotBeNil)
		})

		Convey("When I add the chain rules and the netPacketIPtableContext fails in hostmode ", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				if table == i.netPacketIPTableContext {
					return errors.New("error")
				}
				return nil
			})
			err := i.addChainRules("context", "appchain", "netchain", "0", "100", "100", "", "", "5000", "proxyPortSet", extractors.LinuxPU)
			So(err, ShouldNotBeNil)
		})

		Convey("When i add chain rules with non-zero uid and port 0", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				return nil
			})
			err := i.addChainRules("context", "appchain", "netchain", "0", "0", "0", "100", "1001", "5000", "proxyPortSet", "")
			So(err, ShouldBeNil)

		})

		Convey("When i add chain rules with non-zero uid and port 0 rules are added to the UID Chain", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				if chain == "UIDCHAIN" || chain == "UIDInput" || chain == "OUTPUT" || chain == natProxyInputChain || chain == natProxyOutputChain || chain == proxyInputChain || chain == proxyOutputChain ||
					chain == TriremeInput || chain == TriremeOutput || chain == ipTableSectionPreRouting {
					return nil
				}

				return fmt.Errorf("added to different chain: %s", chain)
			})
			err := i.addChainRules("context", "appchain", "netchain", "80", "0", "0", "100", "1001", "5000", "proxyPortSet", "")
			So(err, ShouldBeNil)

		})

	})
}

func TestAddPacketTrap(t *testing.T) {

	Convey("Given an iptables controller, when I test addPacketTrap for Local Container", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.RemoteContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables

		Convey("When I add the packet trap rules and they succeed", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				return nil
			})
			err := i.addPacketTrap("abc", "appchain", "netchain", false)
			Convey("I should get no error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I add the packet trap rules and the appPacketIPTableContext fails ", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				if table == i.appPacketIPTableContext {
					return errors.New("error")
				}
				return nil
			})
			err := i.addPacketTrap("abc", "appchain", "netchain", false)
			Convey("I should get  error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I add the packet trap rules and the netPacketIPtableContext fails ", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				if table == i.netPacketIPTableContext {
					return errors.New("error")
				}
				return nil
			})
			err := i.addPacketTrap("abc", "appchain", "netchain", false)
			Convey("I should get  error", func() {
				So(err, ShouldNotBeNil)
			})
		})

	})

	Convey("Given an iptables controller, when I test addPacketTrap for Local Server", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.LocalServer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables

		Convey("When I add the packet trap rules and they succeed", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				return nil
			})
			err := i.addPacketTrap("abc", "appchain", "netchain", false)
			Convey("I should get no error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I add the packet trap rules and the appPacketIPTableContext fails ", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				if table == i.appPacketIPTableContext {
					return errors.New("error")
				}
				return nil
			})
			err := i.addPacketTrap("abc", "appchain", "netchain", false)
			Convey("I should get  error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I add the packet trap rules and the netPacketIPtableContext fails ", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				if table == i.netPacketIPTableContext {
					return errors.New("error")
				}
				return nil
			})
			err := i.addPacketTrap("abc", "appchain", "netchain", false)
			Convey("I should get  error", func() {
				So(err, ShouldNotBeNil)
			})
		})

	})

	Convey("Given an iptables controller, when I test addPacketTrap for sidecar container", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.Sidecar)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables

		Convey("When I add the packet trap rules and they succeed", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				return nil
			})
			err := i.addPacketTrap("abc", "appchain", "netchain", false)
			Convey("I should get no error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I add the packet trap rules and the appPacketIPTableContext fails ", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				if table == i.appPacketIPTableContext {
					return errors.New("error")
				}
				return nil
			})
			err := i.addPacketTrap("abc", "appchain", "netchain", false)
			Convey("I should get  error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I add the packet trap rules and the netPacketIPtableContext fails ", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				if table == i.netPacketIPTableContext {
					return errors.New("error")
				}
				return nil
			})
			err := i.addPacketTrap("abc", "appchain", "netchain", false)
			Convey("I should get  error", func() {
				So(err, ShouldNotBeNil)
			})
		})

	})
}

func TestDeleteChainRules(t *testing.T) {

	Convey("Given an iptables controller", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.RemoteContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables

		Convey("When I delete the chain rules and it succeeds", func() {
			iptables.MockDelete(t, func(table string, chain string, rulespec ...string) error {
				return nil
			})
			err := i.deleteChainRules("context", "appchain", "netchain", "0", "100", "100", "", "", "5000", "proxyPortSetName", "")
			So(err, ShouldBeNil)
		})

		Convey("When I delete the chain rules and it fails", func() {
			iptables.MockDelete(t, func(table string, chain string, rulespec ...string) error {
				return nil
			})
			err := i.deleteChainRules("context", "appchain", "netchain", "0", "100", "100", "", "", "5000", "proxyPortSetName", "")
			So(err, ShouldBeNil)

		})

		Convey("When I delete the chain rules and it fails in hostmode in hostmode", func() {
			iptables.MockDelete(t, func(table string, chain string, rulespec ...string) error {
				return nil
			})
			err := i.deleteChainRules("context", "appchain", "netchain", "0", "100", "100", "", "", "5000", "proxyPortSetName", extractors.HostPU)
			So(err, ShouldBeNil)

		})

		Convey("When I delete the chain rules and it succeeds in hostmode", func() {
			iptables.MockDelete(t, func(table string, chain string, rulespec ...string) error {
				return nil
			})
			err := i.deleteChainRules("context", "appchain", "netchain", "0", "100", "100", "", "", "5000", "proxyPortSetName", extractors.HostPU)
			So(err, ShouldBeNil)
		})

	})

}

func TestDeleteAllContainerChains(t *testing.T) {

	Convey("Given an iptables controller", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.RemoteContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables

		Convey("When I delete all container chains and it succeeds ", func() {
			iptables.MockDeleteChain(t, func(table string, chain string) error {
				return nil
			})
			iptables.MockClearChain(t, func(table string, chain string) error {
				return nil
			})
			err := i.deleteAllContainerChains("appchain", "netchain")
			Convey("I should get no error ", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I delete all container chains and it fails in clear chain ", func() {
			iptables.MockDeleteChain(t, func(table string, chain string) error {
				return nil
			})
			iptables.MockClearChain(t, func(table string, chain string) error {
				return errors.New("error")
			})
			err := i.deleteAllContainerChains("appchain", "netchain")
			Convey("I should stil get no error ", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I delete all container chains and it fails in delete chain ", func() {
			iptables.MockDeleteChain(t, func(table string, chain string) error {
				return errors.New("error")
			})
			iptables.MockClearChain(t, func(table string, chain string) error {
				return nil
			})
			err := i.deleteAllContainerChains("appchain", "netchain")
			Convey("I should stil get no error ", func() {
				So(err, ShouldBeNil)
			})
		})

	})

}

func TestAcceptMarkedPackets(t *testing.T) {

	Convey("Given an iptables controller", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.RemoteContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables

	})
}

func TestAddExclusionACLs(t *testing.T) {
	Convey("Given an iptables controller", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.RemoteContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables

		Convey("When I add the exclusion rules and they succeed", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				return nil
			})

			err := i.addExclusionACLs("appchain", "netchain", []string{"10.1.1.1/32"})
			Convey("I should get no error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I add the exclusion chain rules and the appPacketIPTableContext fails ", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				if table == i.appPacketIPTableContext {
					return errors.New("error")
				}
				return nil
			})
			err := i.addExclusionACLs("appchain", "netchain", []string{"10.1.1.1/32"})
			Convey("I should get  error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I add the exclusion chain rules and the netPacketIPTableContext fails ", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				if table == i.netPacketIPTableContext {
					return errors.New("error")
				}
				return nil
			})
			err := i.addExclusionACLs("appchain", "netchain", []string{"10.1.1.1/32"})
			Convey("I should get  error", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})
}

func TestAddNATExclusionACLs(t *testing.T) {
	Convey("Given an iptables controller", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.RemoteContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables

		Convey("When I add the NAT exclusion rules and they succeed", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				return nil
			})
			err := i.addNATExclusionACLs("", "myset", []string{"10.1.1.3/32"})
			Convey("I should get no error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I add the NAT exclusion chain rules and the appPacketIPTableContext fails ", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				if table == i.appProxyIPTableContext {
					return errors.New("error")
				}
				return nil
			})
			err := i.addNATExclusionACLs("", "myset", []string{"10.1.1.3/32"})
			Convey("I should get  error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I add the exclusion chain rules and the install in the output chain fails ", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				if table == i.appProxyIPTableContext && strings.Contains(chain, natProxyOutputChain) {
					return errors.New("error")
				}
				return nil
			})
			err := i.addNATExclusionACLs("", "myset", []string{"10.1.1.3/32"})
			Convey("I should get  error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I add the NAT exclusion rules for a PU with a cgroup mark", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				for _, rule := range rulespec {
					if rule == ruleType {
						return nil
					}
				}
				return errors.New("Bad cgroup mark")
			})
			err := i.addNATExclusionACLs(ruleType, "myset", []string{"10.1.1.3/32"})
			Convey("I should get no error", func() {
				So(err, ShouldBeNil)
			})
		})

	})
}

func TestDeleteNATExclusionACLs(t *testing.T) {
	Convey("Given an iptables controller", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.RemoteContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables

		Convey("When I delete the NAT exclusion rules and they succeed", func() {
			iptables.MockDelete(t, func(table string, chain string, rulespec ...string) error {
				return nil
			})
			err := i.deleteNATExclusionACLs("", "myset", []string{"10.1.1.3/32"})
			Convey("I should get no error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I delete the NAT exclusion chain rules and the appPacketIPTableContext fails ", func() {
			iptables.MockDelete(t, func(table string, chain string, rulespec ...string) error {

				return nil
			})
			err := i.deleteNATExclusionACLs("", "myset", []string{"10.1.1.3/32"})
			Convey("I should get  error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I delete the exclusion chain rules and the install in the output chain fails ", func() {
			iptables.MockDelete(t, func(table string, chain string, rulespec ...string) error {

				return nil
			})
			err := i.deleteNATExclusionACLs("", "myset", []string{"10.1.1.3/32"})
			Convey("I should get  error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I delete the NAT exclusion rules for a PU with a cgroup mark", func() {
			iptables.MockDelete(t, func(table string, chain string, rulespec ...string) error {
				return nil
			})
			err := i.deleteNATExclusionACLs(ruleType, "myset", []string{"10.1.1.3/32"})
			Convey("I should get no error", func() {
				So(err, ShouldBeNil)
			})
		})

	})
}

func TestAddLegacyNATExclusionACLs(t *testing.T) {
	Convey("Given an iptables controller", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.RemoteContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables

		Convey("When I add the NAT exclusion rules and they succeed", func() {
			iptables.MockInsert(t, func(table string, chain string, pos int, rulespec ...string) error {
				return nil
			})
			err := i.addLegacyNATExclusionACLs("", "myset", []string{"10.1.1.3/32"}, "1:56")
			Convey("I should get no error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I add the NAT exclusion chain rules and the appPacketIPTableContext fails ", func() {
			iptables.MockInsert(t, func(table string, chain string, pos int, rulespec ...string) error {
				if table == i.appProxyIPTableContext {
					return errors.New("error")
				}
				return nil
			})
			err := i.addLegacyNATExclusionACLs("", "myset", []string{"10.1.1.3/32"}, "8085")
			Convey("I should get  error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I add the exclusion chain rules and the install in the output chain fails ", func() {
			iptables.MockInsert(t, func(table string, chain string, pos int, rulespec ...string) error {
				if table == i.appProxyIPTableContext && strings.Contains(chain, natProxyOutputChain) {
					return errors.New("error")
				}
				return nil
			})
			err := i.addLegacyNATExclusionACLs("", "myset", []string{"10.1.1.3/32"}, "8086")
			Convey("I should get  error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I add the NAT exclusion rules for a PU with source ports", func() {
			iptables.MockInsert(t, func(table string, chain string, pos int, rulespec ...string) error {
				for _, rule := range rulespec {
					if rule == "8086" || rule == ruleType {
						return nil
					}
				}
				return errors.New("Bad source ports")
			})
			err := i.addLegacyNATExclusionACLs(ruleType, "myset", []string{"10.1.1.3/32"}, "8086")
			Convey("I should get no error", func() {
				So(err, ShouldBeNil)
			})
		})

	})
}

func TestDeleteLegacyNATExclusionACLs(t *testing.T) {
	Convey("Given an iptables controller", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.RemoteContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables

		Convey("When I delete the NAT exclusion rules and they succeed", func() {
			iptables.MockDelete(t, func(table string, chain string, rulespec ...string) error {
				return nil
			})
			err := i.deleteLegacyNATExclusionACLs("", "myset", []string{"10.1.1.3/32"}, "3:56")
			Convey("I should get no error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I delete the NAT exclusion chain rules and the appPacketIPTableContext fails ", func() {
			iptables.MockDelete(t, func(table string, chain string, rulespec ...string) error {
				if table == i.appProxyIPTableContext {
					return errors.New("error")
				}
				return nil
			})
			err := i.deleteLegacyNATExclusionACLs("", "myset", []string{"10.1.1.3/32"}, "8085")
			Convey("I should get  error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I delete the exclusion chain rules and the install in the output chain fails ", func() {
			iptables.MockDelete(t, func(table string, chain string, rulespec ...string) error {
				if table == i.appProxyIPTableContext && strings.Contains(chain, natProxyOutputChain) {
					return errors.New("error")
				}
				return nil
			})
			err := i.deleteLegacyNATExclusionACLs("", "myset", []string{"10.1.1.3/32"}, "8085")
			Convey("I should get  error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I delete the NAT exclusion rules for a PU with a source port", func() {
			iptables.MockDelete(t, func(table string, chain string, rulespec ...string) error {
				for _, rule := range rulespec {
					if rule == "8085" || rule == ruleType {
						return nil
					}
				}
				return errors.New("Bad source ports")
			})
			err := i.deleteLegacyNATExclusionACLs("", "myset", []string{"10.1.1.3/32"}, "8085")
			Convey("I should get no error", func() {
				So(err, ShouldBeNil)
			})
		})

	})
}

//
// func TestSetGlobalRules(t *testing.T) {
// 	Convey("Given an iptables controller", t, func() {
// 		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.RemoteContainer, portset.New(nil))
// 		iptables := provider.NewTestIptablesProvider()
// 		i.ipt = iptables
// 		ipsets := provider.NewTestIpsetProvider()
// 		i.ipset = ipsets
//
// 		Convey("When I add the capture for the SynAck packets", func() {
// 			iptables.MockInsert(t, func(table string, chain string, pos int, rulespec ...string) error {
// 				rulestring := strings.Join(rulespec, ",")
// 				fmt.Println("RULES", rulestring)
// 				if chain == "INPUT" || chain == "OUTPUT" {
// 					if matchSpec("--match-set", rulespec) == nil && matchSpec(targetNetworkSet, rulespec) == nil {
// 						return nil
// 					}
// 					if matchSpec("connmark", rulespec) == nil && matchSpec(strconv.Itoa(int(constants.DefaultConnMark)), rulespec) == nil {
// 						return nil
// 					}
//
// 				}
//
// 				if chain == "PREROUTING" || strings.Contains(rulestring, "UIDCHAIN") {
// 					return nil
// 				}
// 				return errors.New("failed")
// 			})
//
// 			ipsets.MockNewIpset(t, func(name string, hasht string, p *ipset.Params) (provider.Ipset, error) {
// 				if name == targetNetworkSet {
// 					testset := provider.NewTestIpset()
// 					testset.MockAdd(t, func(entry string, timeout int) error {
// 						return nil
// 					})
// 					return testset, nil
// 				}
// 				return nil, errors.New("wrong set")
// 			})
//
// 			err := i.setGlobalRules("OUTPUT", "INPUT")
// 			Convey("I should get no error if iptables succeeds", func() {
// 				So(err, ShouldBeNil)
// 			})
// 		})
//
// 		Convey("When I add the capture, but iptables fails in the app chain", func() {
// 			iptables.MockInsert(t, func(table string, chain string, pos int, rulespec ...string) error {
// 				if table == i.appPacketIPTableContext {
// 					return errors.New("error")
// 				}
// 				return nil
// 			})
//
// 			ipsets.MockNewIpset(t, func(name string, hasht string, p *ipset.Params) (provider.Ipset, error) {
// 				if name == targetNetworkSet {
// 					testset := provider.NewTestIpset()
// 					testset.MockAdd(t, func(entry string, timeout int) error {
// 						return nil
// 					})
// 					return testset, nil
// 				}
// 				return nil, errors.New("wrong set")
// 			})
//
// 			err := i.setGlobalRules("OUTPUT", "INPUT")
// 			Convey("I should get an error", func() {
// 				So(err, ShouldNotBeNil)
// 			})
// 		})
//
// 		Convey("When I add the capture, but iptables fails in the net chain", func() {
// 			iptables.MockInsert(t, func(table string, chain string, pos int, rulespec ...string) error {
// 				if table == i.netPacketIPTableContext {
// 					return errors.New("error")
// 				}
// 				return nil
// 			})
//
// 			ipsets.MockNewIpset(t, func(name string, hasht string, p *ipset.Params) (provider.Ipset, error) {
// 				if name == targetNetworkSet {
// 					testset := provider.NewTestIpset()
// 					testset.MockAdd(t, func(entry string, timeout int) error {
// 						return nil
// 					})
// 					return testset, nil
// 				}
// 				return nil, errors.New("wrong set")
// 			})
//
// 			err := i.setGlobalRules("OUTPUT", "INPUT")
// 			Convey("I should get an error", func() {
// 				So(err, ShouldNotBeNil)
// 			})
// 		})
//
// 	})
// }

func TestClearCaptureSynAckPackets(t *testing.T) {
	Convey("Given an iptables controller", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.RemoteContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables

		Convey("When I delete the capture for the SynAck packets", func() {
			iptables.MockDelete(t, func(table string, chain string, rulespec ...string) error {
				if table == i.appPacketIPTableContext && chain == i.appPacketIPTableSection {
					return nil
				}

				if table == i.netPacketIPTableContext && chain == i.netPacketIPTableSection {
					return nil
				}
				return errors.New("error")
			})
		})
	})
}

func TestAddAppACLs(t *testing.T) {
	Convey("Given an iptables controller ", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.RemoteContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables
		ipsets := provider.NewTestIpsetProvider()
		i.ipset = ipsets

		Convey("When I add app ACLs with no rules", func() {
			err := i.addAppACLs("", appChain, netChain, []aclIPset{})
			Convey("I should get no error", func() {
				So(err, ShouldBeNil)
			})
		})
		Convey("When I add app ACLs with one reject and one accept rule and iptables succeeds", func() {

			rules := policy.IPRuleList{
				policy.IPRule{
					Addresses: []string{"192.30.253.0/24"},
					Ports:     []string{"80"},
					Protocols: []string{constants.TCPProtoNum},
					Policy:    &policy.FlowPolicy{Action: (policy.Reject | policy.Log)},
				},

				policy.IPRule{
					Addresses: []string{"192.30.253.0/24"},
					Ports:     []string{"443"},
					Protocols: []string{constants.UDPProtoNum},
					Policy:    &policy.FlowPolicy{Action: policy.Accept},
				},

				policy.IPRule{
					Addresses: []string{"192.30.253.0/24"},
					Protocols: []string{"all"},
					Policy:    &policy.FlowPolicy{Action: policy.Accept},
				},
			}

			ipsets.MockNewIpset(t, func(_ string, _ string, _ *ipset.Params) (provider.Ipset, error) { // nolint
				testset := provider.NewTestIpset()
				testset.MockAdd(t, func(entry string, timeout int) error {
					return nil
				})
				return testset, nil
			})

			ipsets.MockGetIpset(t, func(_ string) provider.Ipset {
				testset := provider.NewTestIpset()
				testset.MockAdd(t, func(entry string, timeout int) error {
					return nil
				})
				return testset
			})

			//ipsets.Mock
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				// test DROP rules are before ACCEPT

				if table == i.appPacketIPTableContext && chain == appChain {
					if matchSpec("DROP", rulespec) == nil || matchSpec("ACCEPT", rulespec) == nil || matchSpec("NFLOG", rulespec) == nil {
						return nil
					}
				}

				if chain == netChain {
					if matchSpec("ACCEPT", rulespec) == nil {
						return nil
					}
				}

				if chain == errChain {
					return errors.New("chain is incorrect")
				}

				return errors.New("Chains and table are incorrect")
			})

			appACLIPset, err := i.createACLIPSets("chain", rules)
			So(err, ShouldBeNil)

			err = i.addAppACLs("chain", appChain, netChain, appACLIPset)
			Convey("I should get no error", func() {
				So(err, ShouldBeNil)
			})

			err = i.addAppACLs("chain", errChain, errChain, appACLIPset)
			Convey("I should get an error", func() {
				So(err, ShouldNotBeNil)
			})

		})

	})

}

func TestAddNetACLs(t *testing.T) {
	Convey("Given an iptables controller ", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.RemoteContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables
		ipsets := provider.NewTestIpsetProvider()
		i.ipset = ipsets

		Convey("When I add app ACLs with no rules", func() {
			err := i.addNetACLs("", appChain, netChain, []aclIPset{})
			Convey("I should get no error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I add app ACLs with one reject and one accept rule and iptables succeeds", func() {

			rules := policy.IPRuleList{
				policy.IPRule{
					Addresses: []string{"192.30.253.0/24"},
					Ports:     []string{"80"},
					Protocols: []string{constants.TCPProtoNum},
					Policy:    &policy.FlowPolicy{Action: (policy.Reject | policy.Log)},
				},

				policy.IPRule{
					Addresses: []string{"192.30.253.0/24"},
					Ports:     []string{"443"},
					Protocols: []string{constants.UDPProtoNum},
					Policy:    &policy.FlowPolicy{Action: policy.Accept},
				},

				policy.IPRule{
					Addresses: []string{"192.30.253.0/24"},
					Protocols: []string{"all"},
					Policy:    &policy.FlowPolicy{Action: policy.Accept},
				},
			}

			ipsets.MockNewIpset(t, func(_ string, _ string, _ *ipset.Params) (provider.Ipset, error) { // nolint
				testset := provider.NewTestIpset()
				testset.MockAdd(t, func(entry string, timeout int) error {
					return nil
				})
				return testset, nil
			})

			ipsets.MockGetIpset(t, func(_ string) provider.Ipset {
				testset := provider.NewTestIpset()
				testset.MockAdd(t, func(entry string, timeout int) error {
					return nil
				})
				return testset
			})

			//ipsets.Mock
			iptables.MockInsert(t, func(table string, chain string, pos int, rulespec ...string) error {
				// test DROP rules are before ACCEPT
				if table == i.appPacketIPTableContext && chain == netChain {
					if matchSpec("DROP", rulespec) == nil && matchSpec("ACCEPT", rulespec) == nil && matchSpec("NFLOG", rulespec) == nil {
						return nil
					}
				}

				if chain == appChain {
					if matchSpec("ACCEPT", rulespec) == nil {
						return nil
					}
				}

				return errors.New("Chains and table are incorrect")
			})

			netACLIPset, err := i.createACLIPSets("chain", rules)
			So(err, ShouldBeNil)

			err = i.addNetACLs("chain", appChain, netChain, netACLIPset)
			Convey("I should get no error", func() {
				So(err, ShouldBeNil)
			})
		})
	})
}
