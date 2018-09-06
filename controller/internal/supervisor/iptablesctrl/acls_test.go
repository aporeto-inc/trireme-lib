package iptablesctrl

import (
	"errors"
	"fmt"
	"testing"

	"github.com/bvandewalle/go-ipset/ipset"
	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/portset"
	"go.aporeto.io/trireme-lib/controller/pkg/aclprovider"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/policy"
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
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.RemoteContainer, portset.New(nil))
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables

		Convey("When I add a container chain with no errors", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				return nil
			})
			err := i.addContainerChain("appChain", "netChain")
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
			err := i.addContainerChain("appChain", "netChain")
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
			err := i.addContainerChain("appChain", "netChain")
			Convey("I should get an error", func() {
				So(err, ShouldNotBeNil)
			})
		})

	})
}

func TestAddChainRules(t *testing.T) {

	Convey("Given an iptables controller for LocalContainer", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.RemoteContainer, portset.New(nil))
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables

		Convey("When I add the chain rules and they succeed", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				return nil
			})

			err := i.addChainRules("appchain", "netchain", "0", "100", "100", "", "", "5000", "proxyPortSet")
			So(err, ShouldBeNil)
		})

		Convey("When I add the chain rules and the appPacketIPTableContext fails ", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				if table == i.appPacketIPTableContext {
					return errors.New("error")
				}
				return nil
			})
			err := i.addChainRules("appchain", "netchain", "0", "100", "100", "", "", "5000", "proxyPortSet")
			So(err, ShouldNotBeNil)

		})

		Convey("When I add the chain rules and the netPacketIPtableContext fails ", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				if table == i.netPacketIPTableContext {
					return errors.New("error")
				}
				return nil
			})
			err := i.addChainRules("appchain", "netchain", "0", "100", "100", "", "", "5000", "proxyPortSet")
			So(err, ShouldNotBeNil)

		})

	})

	Convey("Given an iptables controller for LocalServer", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.LocalServer, portset.New(nil))
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables

		Convey("When I add the chain rules and they succeed", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				return nil
			})
			err := i.addChainRules("appchain", "netchain", "0", "100", "100", "", "", "5000", "proxyPortSet")
			So(err, ShouldBeNil)
		})

		Convey("When I add the chain rules and the appPacketIPTableContext fails ", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				if table == i.appPacketIPTableContext {
					return errors.New("error")
				}
				return nil
			})
			err := i.addChainRules("appchain", "netchain", "0", "100", "100", "", "", "5000", "proxyPortSet")
			So(err, ShouldNotBeNil)
		})

		Convey("When I add the chain rules and the netPacketIPtableContext fails ", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				if table == i.netPacketIPTableContext {
					return errors.New("error")
				}
				return nil
			})
			err := i.addChainRules("appchain", "netchain", "0", "100", "100", "", "", "5000", "proxyPortSet")
			So(err, ShouldNotBeNil)
		})
		Convey("When i add chain rules with non-zero uid and port 0", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				return nil
			})
			err := i.addChainRules("appchain", "netchain", "0", "0", "0", "1001", "", "5000", "proxyPortSet")
			So(err, ShouldBeNil)

		})

		Convey("When i add chain rules with non-zero uid and port 0 rules are added to the UID Chain", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				if chain == "UIDCHAIN" || chain == "netchain" || chain == "INPUT" || chain == "OUTPUT" || chain == "RedirProxy-Net" || chain == "RedirProxy-App" || chain == "Proxy-Net" || chain == "Proxy-App" {
					return nil
				}

				return fmt.Errorf("added to different chain: %s", chain)
			})
			err := i.addChainRules("appchain", "netchain", "80", "0", "0", "1001", "", "5000", "proxyPortSet")
			So(err, ShouldBeNil)

		})

	})
}

func TestAddPacketTrap(t *testing.T) {

	Convey("Given an iptables controller, when I test addPacketTrap for Local Container", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.RemoteContainer, portset.New(nil))
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables

		Convey("When I add the packet trap rules and they succeed", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				return nil
			})
			err := i.addPacketTrap("appchain", "netchain", []string{"172.17.0.0/24"})
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
			err := i.addPacketTrap("appchain", "netchain", []string{"172.17.0.0/24"})
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
			err := i.addPacketTrap("appchain", "netchain", []string{"172.17.0.0/24"})
			Convey("I should get  error", func() {
				So(err, ShouldNotBeNil)
			})
		})

	})

	Convey("Given an iptables controller, when I test addPacketTrap for Local Server", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.LocalServer, portset.New(nil))
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables

		Convey("When I add the packet trap rules and they succeed", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				return nil
			})
			err := i.addPacketTrap("appchain", "netchain", []string{"172.17.0.0/24"})
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
			err := i.addPacketTrap("appchain", "netchain", []string{"172.17.0.0/24"})
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
			err := i.addPacketTrap("appchain", "netchain", []string{"172.17.0.0/24"})
			Convey("I should get  error", func() {
				So(err, ShouldNotBeNil)
			})
		})

	})

	Convey("Given an iptables controller, when I test addPacketTrap for sidecar container", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.Sidecar, portset.New(nil))
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables

		Convey("When I add the packet trap rules and they succeed", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				return nil
			})
			err := i.addPacketTrap("appchain", "netchain", []string{"172.17.0.0/24"})
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
			err := i.addPacketTrap("appchain", "netchain", []string{"172.17.0.0/24"})
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
			err := i.addPacketTrap("appchain", "netchain", []string{"172.17.0.0/24"})
			Convey("I should get  error", func() {
				So(err, ShouldNotBeNil)
			})
		})

	})
}

func TestAddAppACLs(t *testing.T) {

	Convey("Given an iptables controller ", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.RemoteContainer, portset.New(nil))
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables

		Convey("When I add app ACLs with no rules", func() {
			iptables.MockInsert(t, func(table string, chain string, pos int, rulespec ...string) error {
				if table == i.appPacketIPTableContext && chain == "appChain" {
					if err := matchSpec("DROP", rulespec); err == nil {
						return nil
					}
					if err := matchSpec("ESTABLISHED", rulespec); err == nil {
						return nil
					}
					if err := matchSpec("NFLOG", rulespec); err == nil {
						return nil
					}
				}
				return errors.New("error")
			})

			err := i.addAppACLs("", "appChain", "netChain", policy.IPRuleList{})
			Convey("I should get no error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I add app ACLs with no rules and it fails", func() {
			iptables.MockInsert(t, func(table string, chain string, pos int, rulespec ...string) error {
				if table == i.appPacketIPTableContext && chain == "appChain" {
					return errors.New("error")
				}
				return nil
			})

			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				if table == i.appPacketIPTableContext && chain == "appChain" {
					return errors.New("error")
				}
				return nil
			})

			err := i.addAppACLs("", "appChain", "netChain", policy.IPRuleList{})
			Convey("I should get  error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I add app ACLs with one reject and one accept rule and iptables succeeds", func() {

			rules := policy.IPRuleList{
				policy.IPRule{
					Address:  "192.30.253.0/24",
					Port:     "80",
					Protocol: "UDP",
					Policy:   &policy.FlowPolicy{Action: policy.Reject},
				},

				policy.IPRule{
					Address:  "192.30.253.0/24",
					Port:     "443",
					Protocol: "UDP",
					Policy:   &policy.FlowPolicy{Action: policy.Accept},
				},
			}

			iptables.MockInsert(t, func(table string, chain string, pos int, rulespec ...string) error {
				if matchSpec("80", rulespec) == nil && matchSpec("DROP", rulespec) == nil {
					return nil
				}
				if matchSpec("443", rulespec) == nil && matchSpec("ACCEPT", rulespec) == nil {
					return nil
				}
				if matchSpec("0.0.0.0/0", rulespec) == nil {
					return nil
				}
				return fmt.Errorf("error %s", rulespec)
			})
			err := i.addAppACLs("chain", "appChain", "netChain", rules)
			Convey("I should get no error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I add app ACLs with one reject and one accept and the accept fails", func() {

			rules := policy.IPRuleList{
				policy.IPRule{
					Address:  "192.30.253.0/24",
					Port:     "80",
					Protocol: "UDP",
					Policy:   &policy.FlowPolicy{Action: policy.Reject},
				},

				policy.IPRule{
					Address:  "192.30.253.0/24",
					Port:     "443",
					Protocol: "UDP",
					Policy:   &policy.FlowPolicy{Action: policy.Accept},
				},
			}

			iptables.MockInsert(t, func(table string, chain string, pos int, rulespec ...string) error {
				if matchSpec("80", rulespec) == nil && matchSpec("DROP", rulespec) == nil {
					return nil
				}
				if matchSpec("0.0.0.0/0", rulespec) == nil {
					return nil
				}
				return fmt.Errorf("error %s", rulespec)
			})
			err := i.addAppACLs("chain", "appChain", "netChain", rules)
			Convey("I should get no error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I add app ACLs with one reject and one accept and the reject rule fails", func() {

			rules := policy.IPRuleList{
				policy.IPRule{
					Address:  "192.30.253.0/24",
					Port:     "443",
					Protocol: "UDP",
					Policy:   &policy.FlowPolicy{Action: policy.Accept},
				},
				policy.IPRule{
					Address:  "192.30.253.0/24",
					Port:     "80",
					Protocol: "UDP",
					Policy:   &policy.FlowPolicy{Action: policy.Reject},
				},
			}

			iptables.MockInsert(t, func(table string, chain string, pos int, rulespec ...string) error {
				if matchSpec("443", rulespec) == nil && matchSpec("ACCEPT", rulespec) == nil {
					return nil
				}
				if matchSpec("0.0.0.0/0", rulespec) == nil {
					return nil
				}
				return fmt.Errorf("error %s", rulespec)
			})
			err := i.addAppACLs("chain", "appChain", "netChain", rules)
			Convey("I should error for reject", func() {
				So(err, ShouldNotBeNil)
			})
		})

	})
}

func TestAddNetAcls(t *testing.T) {

	Convey("Given an iptables controller ", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.RemoteContainer, portset.New(nil))
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables

		Convey("When I add net ACLs with no rules", func() {
			iptables.MockInsert(t, func(table string, chain string, pos int, rulespec ...string) error {
				if table == i.netPacketIPTableContext && chain == "chain" {
					if err := matchSpec("DROP", rulespec); err == nil {
						return nil
					}
					if err := matchSpec("ESTABLISHED", rulespec); err == nil {
						return nil
					}
					if err := matchSpec("NFLOG", rulespec); err == nil {
						return nil
					}
				}
				return errors.New("error")
			})

			err := i.addNetACLs("", "", "chain", policy.IPRuleList{})
			Convey("I should get no error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I add net ACLs with no rules and it fails", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				if table == i.netPacketIPTableContext && chain == "chain" {
					return errors.New("error")
				}
				return nil
			})

			err := i.addNetACLs("", "", "chain", policy.IPRuleList{})
			Convey("I should get  error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I add net ACLs with one reject and one accept rule and iptables succeeds", func() {

			rules := policy.IPRuleList{
				policy.IPRule{
					Address:  "192.30.253.0/24",
					Port:     "80",
					Protocol: "TCP",
					Policy:   &policy.FlowPolicy{Action: policy.Reject},
				},

				policy.IPRule{
					Address:  "192.30.253.0/24",
					Port:     "443",
					Protocol: "TCP",
					Policy:   &policy.FlowPolicy{Action: policy.Accept},
				},
			}

			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				if matchSpec("NFLOG", rulespec) == nil {
					return nil
				}
				if matchSpec("80", rulespec) == nil && matchSpec("REJECT", rulespec) == nil {
					return nil
				}
				if matchSpec("443", rulespec) == nil && matchSpec("ACCEPT", rulespec) == nil {
					return nil
				}
				if matchSpec("0.0.0.0/0", rulespec) == nil {
					return nil
				}
				return fmt.Errorf("error %s", rulespec)
			})
			err := i.addNetACLs("chain", "", "", rules)
			Convey("I should get no error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I add net ACLs with one reject and one accept and the accept fails", func() {

			rules := policy.IPRuleList{
				policy.IPRule{
					Address:  "192.30.253.0/24",
					Port:     "80",
					Protocol: "TCP",
					Policy:   &policy.FlowPolicy{Action: policy.Reject},
				},

				policy.IPRule{
					Address:  "192.30.253.0/24",
					Port:     "443",
					Protocol: "TCP",
					Policy:   &policy.FlowPolicy{Action: policy.Accept},
				},
			}

			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				if matchSpec("NFLOG", rulespec) == nil {
					return nil
				}
				if matchSpec("80", rulespec) == nil && matchSpec("REJECT", rulespec) == nil {
					return nil
				}
				if matchSpec("0.0.0.0/0", rulespec) == nil {
					return nil
				}
				return fmt.Errorf("error %s", rulespec)
			})
			err := i.addNetACLs("chain", "", "", rules)
			Convey("I should get no error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I add net ACLs with one reject and one accept and the reject rule fails", func() {

			rules := policy.IPRuleList{
				policy.IPRule{
					Address:  "192.30.253.0/24",
					Port:     "80",
					Protocol: "TCP",
					Policy:   &policy.FlowPolicy{Action: policy.Reject},
				},

				policy.IPRule{
					Address:  "192.30.253.0/24",
					Port:     "443",
					Protocol: "TCP",
					Policy:   &policy.FlowPolicy{Action: policy.Accept},
				},
			}

			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				if matchSpec("NFLOG", rulespec) == nil {
					return nil
				}
				if matchSpec("443", rulespec) == nil && matchSpec("ACCEPT", rulespec) == nil {
					return nil
				}
				if matchSpec("0.0.0.0/0", rulespec) == nil {
					return nil
				}
				return fmt.Errorf("error %s", rulespec)
			})
			err := i.addNetACLs("chain", "", "", rules)
			Convey("I should get no error", func() {
				So(err, ShouldBeNil)
			})
		})

	})
}

func TestDeleteChainRules(t *testing.T) {

	Convey("Given an iptables controller", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.RemoteContainer, portset.New(nil))
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables

		Convey("When I delete the chain rules and it succeeds", func() {
			iptables.MockDelete(t, func(table string, chain string, rulespec ...string) error {
				return nil
			})
			err := i.deleteChainRules("appchain", "netchain", "0", "100", "100", "", "", "5000", "proxyPortSetName")
			So(err, ShouldBeNil)
		})

		Convey("When I delete the chain rules and it fails", func() {
			iptables.MockDelete(t, func(table string, chain string, rulespec ...string) error {
				return nil
			})
			err := i.deleteChainRules("appchain", "netchain", "0", "100", "100", "", "", "5000", "proxyPortSetName")
			So(err, ShouldBeNil)

		})

	})

}

func TestDeleteAllContainerChains(t *testing.T) {

	Convey("Given an iptables controller", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.RemoteContainer, portset.New(nil))
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
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.RemoteContainer, portset.New(nil))
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables

	})
}

func TestRemoveMarkRule(t *testing.T) {

	Convey("Given an iptables controller", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.RemoteContainer, portset.New(nil))
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables

		Convey("When I delete the rule for marked packets and it succeeds ", func() {
			iptables.MockDelete(t, func(table string, chain string, rulespec ...string) error {
				return nil
			})
			err := i.removeMarkRule()
			Convey("I should get no error ", func() {
				So(err, ShouldBeNil)
			})
		})
		Convey("When I delete the rule for marked packets and it fails  ", func() {
			iptables.MockDelete(t, func(table string, chain string, rulespec ...string) error {
				return errors.New("error")
			})
			err := i.removeMarkRule()
			Convey("I should STILL get no error ", func() {
				So(err, ShouldBeNil)
			})
		})
	})
}

func TestAddExclusionACLs(t *testing.T) {
	Convey("Given an iptables controller", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.RemoteContainer, portset.New(nil))
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables

		Convey("When I add the exclusion rules and they succeed", func() {
			iptables.MockInsert(t, func(table string, chain string, pos int, rulespec ...string) error {
				return nil
			})

			err := i.addExclusionACLs("appchain", "netchain", []string{"10.1.1.1/32"})
			Convey("I should get no error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I add the exclusion chain rules and the appPacketIPTableContext fails ", func() {
			iptables.MockInsert(t, func(table string, chain string, pos int, rulespec ...string) error {
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
			iptables.MockInsert(t, func(table string, chain string, pos int, rulespec ...string) error {
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
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.RemoteContainer, portset.New(nil))
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

			err := i.CleanGlobalRules()
			Convey("I should get no error if iptables succeeds", func() {
				So(err, ShouldBeNil)
			})
		})
	})
}

func TestUpdateTargetNetworks(t *testing.T) {
	Convey("Given an iptables controller,", t, func() {
		i, _ := NewInstance(&fqconfig.FilterQueue{}, constants.RemoteContainer, portset.New(nil))
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables
		ipsets := provider.NewTestIpsetProvider()
		i.ipset = ipsets

		Convey("When I create the target networks for the first time and ipset succeeds, it should succeed", func() {

			ipsets.MockNewIpset(t, func(name string, hasht string, p *ipset.Params) (provider.Ipset, error) {
				if name == targetNetworkSet {
					testset := provider.NewTestIpset()
					testset.MockAdd(t, func(entry string, timeout int) error {
						if entry == "10.1.1.0/24" || entry == "20.1.1.0/24" || entry == "30.1.1.0/24" {
							return nil
						}
						return errors.New("error")
					})

					testset.MockDel(t, func(entry string) error {
						if entry == "10.1.1.0/24" {
							return nil
						}
						return errors.New("error")
					})

					return testset, nil
				}
				return nil, errors.New("wrong set")
			})

			err := i.createTargetSet([]string{"10.1.1.0/24", "20.1.1.0/24"})
			So(err, ShouldBeNil)

			Convey("When I update the target network and I delete an entry", func() {
				err := i.updateTargetNetworks([]string{"10.1.1.0/24", "20.1.1.0/24"}, []string{"20.1.1.0/24"})
				So(err, ShouldBeNil)
			})

			Convey("When I update the target network and I add an entry", func() {
				err := i.updateTargetNetworks([]string{"10.1.1.0/24", "20.1.1.0/24"}, []string{"30.1.1.0/24"})
				So(err, ShouldBeNil)
			})
		})
	})
}
