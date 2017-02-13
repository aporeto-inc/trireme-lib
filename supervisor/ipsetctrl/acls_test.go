package ipsetctrl

import (
	"fmt"
	"testing"

	"github.com/bvandewalle/go-ipset/ipset"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/supervisor/provider"
)

func matchSpec(term string, rulespec []string) bool {
	for _, rule := range rulespec {
		if rule == term {
			return true
		}
	}
	return false
}

func TestCreateACLSets(t *testing.T) {
	Convey("Given an ipsets  controllers", t, func() {
		i, _ := NewInstance("0:1", "2:3", 0x1000, true, constants.LocalContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables
		ipsets := provider.NewTestIpsetProvider()
		i.ips = ipsets

		Convey("When I create the ACL sets for APP1 with version 0 and accept/reject rules", func() {
			ipsets.MockNewIpset(t, func(name string, hasht string, p *ipset.Params) (provider.Ipset, error) {
				if (name == "APP1-A-0" || name == "APP1-R-0") && hasht == "hash:net,port" {
					testset := provider.NewTestIpset()
					testset.MockAdd(t, func(entry string, timeout int) error {
						return nil
					})
					return testset, nil
				}
				return nil, fmt.Errorf("Error")
			})

			rules := policy.NewIPRuleList([]policy.IPRule{
				policy.IPRule{
					Address:  "192.30.253.0/24",
					Port:     "80",
					Protocol: "TCP",
					Action:   policy.Reject,
				},

				policy.IPRule{
					Address:  "192.30.253.0/24",
					Port:     "443",
					Protocol: "TCP",
					Action:   policy.Accept,
				},
			})

			err := i.createACLSets("0", "APP1-", rules)

			Convey("I should get no error", func() {
				So(err, ShouldBeNil)
			})

		})

		Convey("When I create the ACL sets for APP1 with version 1 and set create fails", func() {
			ipsets.MockNewIpset(t, func(name string, hasht string, p *ipset.Params) (provider.Ipset, error) {
				return nil, fmt.Errorf("Error")
			})

			err := i.createACLSets("0", "APP1-", policy.NewIPRuleList(nil))
			Convey("I should get an error", func() {
				So(err, ShouldNotBeNil)
			})

		})

		Convey("When I create the ACL sets for APP1 with version 0 and accept/reject rules and adding a rules fails", func() {
			ipsets.MockNewIpset(t, func(name string, hasht string, p *ipset.Params) (provider.Ipset, error) {
				if (name == "APP1-A-0" || name == "APP1-R-0") && hasht == "hash:net,port" {
					testset := provider.NewTestIpset()
					testset.MockAdd(t, func(entry string, timeout int) error {
						return fmt.Errorf("Error adding a rule")
					})
					return testset, nil
				}
				return nil, fmt.Errorf("Error")
			})

			rules := policy.NewIPRuleList([]policy.IPRule{
				policy.IPRule{
					Address:  "192.30.253.0/24",
					Port:     "80",
					Protocol: "TCP",
					Action:   policy.Reject,
				},

				policy.IPRule{
					Address:  "192.30.253.0/24",
					Port:     "443",
					Protocol: "TCP",
					Action:   policy.Accept,
				},
			})

			err := i.createACLSets("0", "APP1-", rules)
			Convey("I should get an error", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})
}

func TestAddAppSetRuleS(t *testing.T) {
	Convey("Given an ipset controller", t, func() {
		i, _ := NewInstance("0:1", "2:3", 0x1000, true, constants.LocalContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables
		ipsets := provider.NewTestIpsetProvider()
		i.ips = ipsets

		Convey("When I add the app set rules with the right parameters", func() {
			iptables.MockInsert(t, func(table string, chain string, pos int, rulespec ...string) error {
				if !matchSpec("172.17.0.2", rulespec) {
					return fmt.Errorf("Error in IP")
				}
				if matchSpec("--match-set", rulespec) && matchSpec("SET-R-0", rulespec) {
					return nil
				}
				if matchSpec("--match-set", rulespec) && matchSpec("SET-A-0", rulespec) {
					return nil
				}
				return fmt.Errorf("Error")
			})

			err := i.addAppSetRules("0", "SET-", "172.17.0.2")
			Convey("I should not get an error ", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I add the app set rules and the command fails ", func() {
			iptables.MockInsert(t, func(table string, chain string, pos int, rulespec ...string) error {
				return fmt.Errorf("Error")
			})

			err := i.addAppSetRules("0", "SET-", "172.17.0.2")
			Convey("I should get an error ", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})
}

func TestAddNetSetRules(t *testing.T) {
	Convey("Given an ipset controller", t, func() {
		i, _ := NewInstance("0:1", "2:3", 0x1000, true, constants.LocalContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables
		ipsets := provider.NewTestIpsetProvider()
		i.ips = ipsets

		Convey("When I add the app set rules with the right parameters", func() {
			iptables.MockInsert(t, func(table string, chain string, pos int, rulespec ...string) error {
				if !matchSpec("172.17.0.2", rulespec) {
					return fmt.Errorf("Error in IP")
				}
				if matchSpec("--match-set", rulespec) && matchSpec("SET-R-0", rulespec) {
					return nil
				}
				if matchSpec("--match-set", rulespec) && matchSpec("SET-A-0", rulespec) {
					return nil
				}
				return fmt.Errorf("Error")
			})

			err := i.addNetSetRules("0", "SET-", "172.17.0.2")
			Convey("I should not get an error ", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I add the app set rules and the command fails ", func() {
			iptables.MockInsert(t, func(table string, chain string, pos int, rulespec ...string) error {
				return fmt.Errorf("Error")
			})

			err := i.addNetSetRules("0", "SET-", "172.17.0.2")
			Convey("I should get an error ", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})
}

func TestDeleteAppSetRules(t *testing.T) {
	Convey("Given an ipset controller", t, func() {
		i, _ := NewInstance("0:1", "2:3", 0x1000, true, constants.LocalContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables
		ipsets := provider.NewTestIpsetProvider()
		i.ips = ipsets

		Convey("When I add the app set rules with the right parameters", func() {
			iptables.MockDelete(t, func(table string, chain string, rulespec ...string) error {
				if !matchSpec("172.17.0.2", rulespec) {
					return fmt.Errorf("Error in IP")
				}
				if matchSpec("--match-set", rulespec) && matchSpec("SET-R-0", rulespec) {
					return nil
				}
				if matchSpec("--match-set", rulespec) && matchSpec("SET-A-0", rulespec) {
					return nil
				}
				return fmt.Errorf("Error")
			})

			err := i.deleteAppSetRules("0", "SET-", "172.17.0.2")
			Convey("I should not get an error ", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I add the app set rules and the command fails ", func() {
			iptables.MockDelete(t, func(table string, chain string, rulespec ...string) error {
				return fmt.Errorf("Error")
			})

			err := i.deleteAppSetRules("0", "SET-", "172.17.0.2")
			Convey("I should still no  error ", func() {
				So(err, ShouldBeNil)
			})
		})
	})
}

func TestDeleteNetSetRules(t *testing.T) {
	Convey("Given an ipset controller", t, func() {
		i, _ := NewInstance("0:1", "2:3", 0x1000, true, constants.LocalContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables
		ipsets := provider.NewTestIpsetProvider()
		i.ips = ipsets

		Convey("When I add the app set rules with the right parameters", func() {
			iptables.MockDelete(t, func(table string, chain string, rulespec ...string) error {
				if !matchSpec("172.17.0.2", rulespec) {
					return fmt.Errorf("Error in IP")
				}
				if matchSpec("--match-set", rulespec) && matchSpec("SET-R-0", rulespec) {
					return nil
				}
				if matchSpec("--match-set", rulespec) && matchSpec("SET-A-0", rulespec) {
					return nil
				}
				return fmt.Errorf("Error")
			})

			err := i.deleteNetSetRules("0", "SET-", "172.17.0.2")
			Convey("I should not get an error ", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I add the app set rules and the command fails ", func() {
			iptables.MockDelete(t, func(table string, chain string, rulespec ...string) error {
				return fmt.Errorf("Error")
			})

			err := i.deleteNetSetRules("0", "SET-", "172.17.0.2")
			Convey("I should stil get no  error ", func() {
				So(err, ShouldBeNil)
			})
		})
	})
}

func TestSetupIpset(t *testing.T) {
	Convey("Given an ipset controller", t, func() {
		i, _ := NewInstance("0:1", "2:3", 0x1000, true, constants.LocalContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables
		ipsets := provider.NewTestIpsetProvider()
		i.ips = ipsets

		Convey("When I setup the basic ipsets for target networks and containers ", func() {
			ipsets.MockNewIpset(t, func(name string, hasht string, p *ipset.Params) (provider.Ipset, error) {
				if (name == "target" && hasht == "hash:net") || (name == "container" && hasht == "hash:ip") {
					testset := provider.NewTestIpset()
					testset.MockAdd(t, func(entry string, timeout int) error {
						return nil
					})
					return testset, nil
				}
				return nil, fmt.Errorf("Error")
			})

			err := i.setupIpset("target", "container")
			Convey("I should get no errors", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I setup the basic ipsets for target networks and containers and target networks fails ", func() {
			ipsets.MockNewIpset(t, func(name string, hasht string, p *ipset.Params) (provider.Ipset, error) {
				if name == "container" && hasht == "hash:ip" {
					testset := provider.NewTestIpset()
					testset.MockAdd(t, func(entry string, timeout int) error {
						return nil
					})
					return testset, nil
				}
				return nil, fmt.Errorf("Error")
			})

			err := i.setupIpset("target", "container")
			Convey("I should get an error ", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I setup the basic ipsets for target networks and containers and the containers set fails ", func() {
			ipsets.MockNewIpset(t, func(name string, hasht string, p *ipset.Params) (provider.Ipset, error) {
				if name == "target" && hasht == "hash:net" {
					testset := provider.NewTestIpset()
					testset.MockAdd(t, func(entry string, timeout int) error {
						return nil
					})
					return testset, nil
				}
				return nil, fmt.Errorf("Error")
			})

			err := i.setupIpset("target", "container")
			Convey("I should get an error ", func() {
				So(err, ShouldNotBeNil)
			})
		})

	})
}

func TestAddContainerToSet(t *testing.T) {
	Convey("Given an ipset controller with a nil container set", t, func() {
		i, _ := NewInstance("0:1", "2:3", 0x1000, true, constants.LocalContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables
		ipsets := provider.NewTestIpsetProvider()
		i.ips = ipsets

		Convey("When I add a container to the set", func() {
			err := i.addContainerToSet("172.17.0.2")
			Convey("It should fail without a crash", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})

	Convey("Given an ipset controller with a valid container set", t, func() {
		i, _ := NewInstance("0:1", "2:3", 0x1000, true, constants.LocalContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables
		ipsets := provider.NewTestIpsetProvider()
		i.ips = ipsets

		ipsets.MockNewIpset(t, func(name string, hasht string, p *ipset.Params) (provider.Ipset, error) {
			testset := provider.NewTestIpset()
			testset.MockAdd(t, func(entry string, timeout int) error {
				return nil
			})
			return testset, nil
		})

		i.containerSet, _ = ipsets.NewIpset("container", "hash:ip", &ipset.Params{})

		Convey("When I add a container to the set", func() {
			err := i.addContainerToSet("172.17.0.2")
			Convey("It should succeed", func() {
				So(err, ShouldBeNil)
			})
		})
	})

	Convey("Given an ipset controller with a valid container set where the add fails", t, func() {
		i, _ := NewInstance("0:1", "2:3", 0x1000, true, constants.LocalContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables
		ipsets := provider.NewTestIpsetProvider()
		i.ips = ipsets

		ipsets.MockNewIpset(t, func(name string, hasht string, p *ipset.Params) (provider.Ipset, error) {
			testset := provider.NewTestIpset()
			testset.MockAdd(t, func(entry string, timeout int) error {
				return fmt.Errorf("Error")
			})
			return testset, nil
		})

		i.containerSet, _ = ipsets.NewIpset("container", "hash:ip", &ipset.Params{})

		Convey("When I add a container to the set", func() {
			err := i.addContainerToSet("172.17.0.2")
			Convey("It should fail ", func() {
				So(err, ShouldNotBeNil)
			})
		})

	})

}

func TestDelContainerFromSet(t *testing.T) {
	Convey("Given an ipset controller with a nil container set", t, func() {
		i, _ := NewInstance("0:1", "2:3", 0x1000, true, constants.LocalContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables
		ipsets := provider.NewTestIpsetProvider()
		i.ips = ipsets

		Convey("When I delete a container to the set", func() {
			err := i.delContainerFromSet("172.17.0.2")
			Convey("It should fail without a crash", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})

	Convey("Given an ipset controller with a valid container set", t, func() {
		i, _ := NewInstance("0:1", "2:3", 0x1000, true, constants.LocalContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables
		ipsets := provider.NewTestIpsetProvider()
		i.ips = ipsets

		ipsets.MockNewIpset(t, func(name string, hasht string, p *ipset.Params) (provider.Ipset, error) {
			testset := provider.NewTestIpset()
			testset.MockDel(t, func(entry string) error {
				return nil
			})
			return testset, nil
		})

		i.containerSet, _ = ipsets.NewIpset("container", "hash:ip", &ipset.Params{})

		Convey("When I delete a container to the set", func() {
			err := i.delContainerFromSet("172.17.0.2")
			Convey("It should succeed", func() {
				So(err, ShouldBeNil)
			})
		})
	})

	Convey("Given an ipset controller with a valid container set where the delete fails", t, func() {
		i, _ := NewInstance("0:1", "2:3", 0x1000, true, constants.LocalContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables
		ipsets := provider.NewTestIpsetProvider()
		i.ips = ipsets

		ipsets.MockNewIpset(t, func(name string, hasht string, p *ipset.Params) (provider.Ipset, error) {
			testset := provider.NewTestIpset()
			testset.MockDel(t, func(entry string) error {
				return fmt.Errorf("Error")
			})
			return testset, nil
		})

		i.containerSet, _ = ipsets.NewIpset("container", "hash:ip", &ipset.Params{})

		Convey("When I delete a container to the set", func() {
			err := i.delContainerFromSet("172.17.0.2")
			Convey("It should fail ", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})
}

func TestAddIpsetOption(t *testing.T) {
	Convey("Given an ipset controller with a nil target set", t, func() {
		i, _ := NewInstance("0:1", "2:3", 0x1000, true, constants.LocalContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables
		ipsets := provider.NewTestIpsetProvider()
		i.ips = ipsets

		Convey("When I add an option to the set", func() {
			err := i.addIpsetOption("172.17.0.2")
			Convey("It should fail without a crash", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})

	Convey("Given an ipset controller with a valid target set", t, func() {
		i, _ := NewInstance("0:1", "2:3", 0x1000, true, constants.LocalContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables
		ipsets := provider.NewTestIpsetProvider()
		i.ips = ipsets

		ipsets.MockNewIpset(t, func(name string, hasht string, p *ipset.Params) (provider.Ipset, error) {
			testset := provider.NewTestIpset()
			testset.MockAddOption(t, func(entry string, option string, timeout int) error {
				return nil
			})
			return testset, nil
		})

		i.targetSet, _ = ipsets.NewIpset("target", "hash:net", &ipset.Params{})

		Convey("When I add an option IP  to the set", func() {
			err := i.addIpsetOption("172.17.0.2")
			Convey("It should succeed", func() {
				So(err, ShouldBeNil)
			})
		})
	})

	Convey("Given an ipset controller with a valid target set", t, func() {
		i, _ := NewInstance("0:1", "2:3", 0x1000, true, constants.LocalContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables
		ipsets := provider.NewTestIpsetProvider()
		i.ips = ipsets

		ipsets.MockNewIpset(t, func(name string, hasht string, p *ipset.Params) (provider.Ipset, error) {
			testset := provider.NewTestIpset()
			testset.MockAddOption(t, func(entry string, option string, timeout int) error {
				return fmt.Errorf("Error")
			})
			return testset, nil
		})

		i.targetSet, _ = ipsets.NewIpset("target", "hash:net", &ipset.Params{})

		Convey("When I add an option IP  to the set that fails ", func() {
			err := i.addIpsetOption("172.17.0.2")
			Convey("It should fail", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})

}

func TestDelIPsetOption(t *testing.T) {
	Convey("Given an ipset controller with a nil target set", t, func() {
		i, _ := NewInstance("0:1", "2:3", 0x1000, true, constants.LocalContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables
		ipsets := provider.NewTestIpsetProvider()
		i.ips = ipsets

		Convey("When I delete an option to the set", func() {
			err := i.deleteIpsetOption("172.17.0.2")
			Convey("It should fail without a crash", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})

	Convey("Given an ipset controller with a valid target set", t, func() {
		i, _ := NewInstance("0:1", "2:3", 0x1000, true, constants.LocalContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables
		ipsets := provider.NewTestIpsetProvider()
		i.ips = ipsets

		ipsets.MockNewIpset(t, func(name string, hasht string, p *ipset.Params) (provider.Ipset, error) {
			testset := provider.NewTestIpset()
			testset.MockDel(t, func(entry string) error {
				return nil
			})
			return testset, nil
		})

		i.targetSet, _ = ipsets.NewIpset("target", "hash:net", &ipset.Params{})

		Convey("When I delete an option IP  to the set", func() {
			err := i.deleteIpsetOption("172.17.0.2")
			Convey("It should succeed", func() {
				So(err, ShouldBeNil)
			})
		})
	})

	Convey("Given an ipset controller with a valid target set", t, func() {
		i, _ := NewInstance("0:1", "2:3", 0x1000, true, constants.LocalContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables
		ipsets := provider.NewTestIpsetProvider()
		i.ips = ipsets

		ipsets.MockNewIpset(t, func(name string, hasht string, p *ipset.Params) (provider.Ipset, error) {
			testset := provider.NewTestIpset()
			testset.MockDel(t, func(entry string) error {
				return fmt.Errorf("Error")
			})
			return testset, nil
		})

		i.targetSet, _ = ipsets.NewIpset("target", "hash:net", &ipset.Params{})

		Convey("When I delete an option IP  to the set that fails ", func() {
			err := i.deleteIpsetOption("172.17.0.2")
			Convey("It should fail", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})
}

func TestSetupTrapRules(t *testing.T) {
	Convey("Given an ipset controller", t, func() {
		i, _ := NewInstance("0:1", "2:3", 0x1000, true, constants.LocalContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables
		ipsets := provider.NewTestIpsetProvider()
		i.ips = ipsets

		Convey("When I add the trap rules and iptables works", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				if matchSpec("ContainerSet", rulespec) {
					return nil
				}
				return fmt.Errorf("Error")
			})

			err := i.setupTrapRules("set")
			Convey("I should get no error ", func() {
				So(err, ShouldBeNil)
			})

		})
		Convey("When I add the trap rules and iptables fails ", func() {
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				if matchSpec("ContainerSet", rulespec) {
					return fmt.Errorf("Error")
				}
				return fmt.Errorf("Error")
			})

			err := i.setupTrapRules("set")
			Convey("I should get an error ", func() {
				So(err, ShouldNotBeNil)
			})

		})

	})
}
