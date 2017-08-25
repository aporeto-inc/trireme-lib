package iptablesctrl

import (
	"fmt"
	"testing"

	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/enforcer/utils/fqconfig"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/supervisor/provider"
	. "github.com/smartystreets/goconvey/convey"
)

func TestNewInstance(t *testing.T) {

	Convey("When I create a new iptables instance", t, func() {

		Convey("If I create a local implemenetation and iptables exists", func() {
			i, err := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.LocalContainer)
			Convey("It should succeed", func() {
				So(i, ShouldNotBeNil)
				So(err, ShouldBeNil)
				So(i.appPacketIPTableSection, ShouldResemble, "PREROUTING")
				So(i.netPacketIPTableSection, ShouldResemble, "POSTROUTING")
			})
		})

		Convey("If I create a remote implemenetation and iptables exists", func() {
			i, err := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.RemoteContainer)
			Convey("It should succeed", func() {
				So(i, ShouldNotBeNil)
				So(err, ShouldBeNil)
				So(i.appPacketIPTableSection, ShouldResemble, "OUTPUT")
				So(i.netPacketIPTableSection, ShouldResemble, "INPUT")
			})
		})
	})
}

func TestChainName(t *testing.T) {
	Convey("When I test the creation of the name of the chain", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.LocalContainer)
		Convey("With a contextID of Context and version of 1", func() {
			app, net := i.chainName("Context", 1)
			Convey("I should get the right names", func() {
				So(app, ShouldResemble, "TRIREME-App-Context-1")
				So(net, ShouldResemble, "TRIREME-Net-Context-1")
			})
		})
	})
}

func TestDefaultIP(t *testing.T) {
	Convey("Given an iptables controller with remote off ", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.LocalContainer)
		Convey("When I get the default IP address of a list that has the default namespace", func() {
			addresslist := map[string]string{
				policy.DefaultNamespace: "10.1.1.1",
			}
			address, status := i.defaultIP(addresslist)

			Convey("I should get the right IP", func() {
				So(address, ShouldResemble, "10.1.1.1")
				So(status, ShouldBeTrue)
			})
		})

		Convey("When I provide list with no matching default", func() {
			addresslist := map[string]string{}
			address, status := i.defaultIP(addresslist)

			Convey("I should get back the default IP and false status", func() {
				So(address, ShouldResemble, "0.0.0.0/0")
				So(status, ShouldBeFalse)
			})
		})
	})

	Convey("Given an iptables controller with remote on ", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.LocalContainer)
		Convey("When I get the default IP address of a list that has the default namespace", func() {
			addresslist := map[string]string{
				policy.DefaultNamespace: "10.1.1.1",
			}
			address, status := i.defaultIP(addresslist)

			Convey("I should get the right IP", func() {
				So(address, ShouldResemble, "10.1.1.1")
				So(status, ShouldBeTrue)
			})
		})

		Convey("When I provide list with no matching default", func() {
			addresslist := map[string]string{}
			address, status := i.defaultIP(addresslist)

			Convey("I should get back the default IP and true status", func() {
				So(address, ShouldResemble, "0.0.0.0/0")
				So(status, ShouldBeFalse)
			})
		})
	})

}

func TestConfigureRules(t *testing.T) {
	Convey("Given an iptables controllers", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.LocalContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables

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

		Convey("With a set of policy rules and valid IP", func() {

			ipl := policy.ExtendedMap{}
			ipl[policy.DefaultNamespace] = "172.17.0.1"
			policyrules := policy.NewPUPolicy("Context",
				policy.Police,
				rules,
				rules,
				nil,
				nil,
				nil,
				nil, ipl, []string{"172.17.0.0/24"}, []string{})

			containerinfo := policy.NewPUInfo("Context", constants.ContainerPU)
			containerinfo.Policy = policyrules
			containerinfo.Runtime = policy.NewPURuntimeWithDefaults()

			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				return nil
			})
			iptables.MockNewChain(t, func(table string, chain string) error {
				return nil
			})
			err := i.ConfigureRules(1, "Context", containerinfo)
			Convey("It should succeed", func() {
				So(err, ShouldBeNil)
			})

		})

		Convey("With a set of policy rules and invalid IP", func() {
			ipl := policy.ExtendedMap{}
			policyrules := policy.NewPUPolicy("Context",
				policy.Police,
				rules,
				rules,
				nil,
				nil,
				nil,
				nil, ipl, []string{"172.17.0.0/24"}, []string{})

			containerinfo := policy.NewPUInfo("Context", constants.ContainerPU)
			containerinfo.Policy = policyrules
			containerinfo.Runtime = policy.NewPURuntimeWithDefaults()

			err := i.ConfigureRules(1, "Context", containerinfo)
			Convey("I should receive an error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("With a set of policy rules and valid IP, where add container chain fails", func() {

			ipl := policy.ExtendedMap{}
			ipl[policy.DefaultNamespace] = "172.17.0.1"
			policyrules := policy.NewPUPolicy("Context",
				policy.Police,
				rules,
				rules,
				nil,
				nil,
				nil,
				nil, ipl, []string{"172.17.0.0/24"}, []string{})

			containerinfo := policy.NewPUInfo("Context", constants.ContainerPU)
			containerinfo.Policy = policyrules
			containerinfo.Runtime = policy.NewPURuntimeWithDefaults()

			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				return nil
			})
			iptables.MockNewChain(t, func(table string, chain string) error {
				return fmt.Errorf("Failed to add container chain")
			})

			err := i.ConfigureRules(1, "Context", containerinfo)
			Convey("I should get an error ", func() {
				So(err, ShouldNotBeNil)
			})

		})

		Convey("With a set of policy rules and valid IP, where add ACLs fails", func() {

			ipl := policy.ExtendedMap{}
			ipl[policy.DefaultNamespace] = "172.17.0.1"
			policyrules := policy.NewPUPolicy("Context",
				policy.Police,
				rules,
				rules,
				nil,
				nil,
				nil,
				nil, ipl, []string{"172.17.0.0/24"}, []string{})

			containerinfo := policy.NewPUInfo("Context", constants.ContainerPU)
			containerinfo.Policy = policyrules
			containerinfo.Runtime = policy.NewPURuntimeWithDefaults()

			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				return fmt.Errorf("Failed to add container chain")
			})
			iptables.MockNewChain(t, func(table string, chain string) error {
				return nil
			})
			err := i.ConfigureRules(1, "Context", containerinfo)
			Convey("I should get an error ", func() {
				So(err, ShouldNotBeNil)
			})
		})

	})
}

func TestDeleteRules(t *testing.T) {
	Convey("Given an iptables controllers", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.LocalContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables

		Convey("If I try to delete with nil IP addreses", func() {
			err := i.DeleteRules(1, "context", nil, "0", "0", "")
			Convey("I should get an error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("I try to delete with no default IP address ", func() {
			err := i.DeleteRules(1, "context", policy.ExtendedMap{}, "0", "0", "")
			Convey("I should get an error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("I try to delete with a valid default IP address ", func() {
			iptables.MockDelete(t, func(table string, chain string, rulespec ...string) error {
				return nil
			})
			iptables.MockClearChain(t, func(table string, chain string) error {
				return nil
			})
			iptables.MockDeleteChain(t, func(table string, chain string) error {
				return nil
			})
			err := i.DeleteRules(1, "context", policy.ExtendedMap{policy.DefaultNamespace: "172.17.0.2"}, "0", "0", "")
			Convey("I should get no error", func() {
				So(err, ShouldBeNil)
			})
		})

	})
}

func TestUpdateRules(t *testing.T) {
	Convey("Given an iptables controllers", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.LocalContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables

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

		Convey("If I try to update with nil IP addreses", func() {
			err := i.UpdateRules(1, "context", nil)
			Convey("I should get an error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("If I try to update with no default IP address ", func() {
			ipl := policy.ExtendedMap{}
			policyrules := policy.NewPUPolicy("Context",
				policy.Police,
				rules,
				rules,
				nil,
				nil,
				nil,
				nil, ipl, []string{"172.17.0.0/24"}, []string{})

			containerinfo := policy.NewPUInfo("Context", constants.ContainerPU)
			containerinfo.Policy = policyrules
			containerinfo.Runtime = policy.NewPURuntimeWithDefaults()

			err := i.UpdateRules(1, "context", containerinfo)

			Convey("I should get an error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("I try to update with a valid default IP address ", func() {
			iptables.MockDelete(t, func(table string, chain string, rulespec ...string) error {
				if matchSpec("TRIREME-App-Context-0", rulespec) == nil || matchSpec("TRIREME-Net-Context-0", rulespec) == nil {
					return nil
				}
				return fmt.Errorf("Error")
			})
			iptables.MockClearChain(t, func(table string, chain string) error {
				if chain == "TRIREME-App-Context-0" || chain == "TRIREME-Net-Context-0" {
					return nil
				}
				return fmt.Errorf("Error")
			})
			iptables.MockDeleteChain(t, func(table string, chain string) error {
				if chain == "TRIREME-App-Context-0" || chain == "TRIREME-Net-Context-0" {
					return nil
				}
				return fmt.Errorf("Error")
			})
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				if chain == "TRIREME-App-Context-1" || chain == "TRIREME-Net-Context-1" {
					return nil
				}
				if matchSpec("TRIREME-App-Context-1", rulespec) == nil || matchSpec("TRIREME-Net-Context-1", rulespec) == nil {
					return nil
				}
				return fmt.Errorf("Error")
			})
			iptables.MockInsert(t, func(table string, chain string, pos int, rulespec ...string) error {
				if chain == "TRIREME-App-Context-1" || chain == "TRIREME-Net-Context-1" {
					return nil
				}
				return fmt.Errorf("Error")
			})
			iptables.MockNewChain(t, func(table string, chain string) error {
				if chain == "TRIREME-App-Context-1" || chain == "TRIREME-Net-Context-1" {
					return nil
				}
				return fmt.Errorf("Error")
			})

			ipl := policy.ExtendedMap{}
			ipl[policy.DefaultNamespace] = "172.17.0.1"
			policyrules := policy.NewPUPolicy("Context",
				policy.Police,
				rules,
				rules,
				nil,
				nil,
				nil,
				nil, ipl, []string{"172.17.0.0/24"}, []string{})

			containerinfo := policy.NewPUInfo("Context", constants.ContainerPU)
			containerinfo.Policy = policyrules
			containerinfo.Runtime = policy.NewPURuntimeWithDefaults()

			err := i.UpdateRules(1, "Context", containerinfo)
			Convey("I should get no error", func() {
				So(err, ShouldBeNil)
			})
		})

	})
}

func TestStart(t *testing.T) {
	Convey("Given an iptables controllers,", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.LocalContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables

		Convey("When I start the controller and I can insert the right rules", func() {
			iptables.MockInsert(t, func(table string, chain string, pos int, rulespec ...string) error {
				return nil
			})
			iptables.MockDelete(t, func(table string, chain string, rulespec ...string) error {
				return nil
			})
			iptables.MockClearChain(t, func(table string, chain string) error {
				return nil
			})
			iptables.MockListChains(t, func(table string) ([]string, error) {
				return []string{}, nil
			})
			err := i.Start()
			Convey("I should get no error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I start the controller and I fail to insert the mark rule", func() {
			iptables.MockInsert(t, func(table string, chain string, pos int, rulespec ...string) error {
				return fmt.Errorf("Error")
			})
			iptables.MockDelete(t, func(table string, chain string, rulespec ...string) error {
				return nil
			})
			iptables.MockClearChain(t, func(table string, chain string) error {
				return nil
			})
			iptables.MockListChains(t, func(table string) ([]string, error) {
				return []string{}, nil
			})
			err := i.Start()
			Convey("I should get an error", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})
}

func TestStop(t *testing.T) {
	Convey("Given an iptables controller", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.RemoteContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables

		Convey("When I stop the controller, I should get no error ", func() {
			err := i.Stop()
			So(err, ShouldBeNil)
		})
	})
}
