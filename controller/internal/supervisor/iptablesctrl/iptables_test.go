package iptablesctrl

import (
	"context"
	"errors"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/portset"
	"go.aporeto.io/trireme-lib/controller/pkg/aclprovider"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/policy"
)

func TestNewInstance(t *testing.T) {
	Convey("When I create a new iptables instance", t, func() {
		Convey("If I create a remote implemenetation and iptables exists", func() {
			i, err := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.RemoteContainer, portset.New(nil))
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
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.RemoteContainer, portset.New(nil))
		Convey("With a contextID of Context and version of 1", func() {
			app, net, err := i.chainName("Context", 1)
			So(err, ShouldBeNil)

			Convey("I should get the right names", func() {
				//app, net := i.chainName("Context", 1)

				So(app, ShouldContainSubstring, "TRIREME-App")
				So(net, ShouldContainSubstring, "TRIREME-Net")
			})
		})
	})
}

func TestConfigureRules(t *testing.T) {
	Convey("Given an iptables controllers", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.RemoteContainer, portset.New(nil))
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
				nil,
				nil,
				ipl,
				[]string{"172.17.0.0/24"},
				[]string{},
				[]string{},
				nil,
				nil,
				[]string{})

			containerinfo := policy.NewPUInfo("Context", common.ContainerPU)
			containerinfo.Policy = policyrules
			containerinfo.Runtime = policy.NewPURuntimeWithDefaults()

			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				return nil
			})
			iptables.MockNewChain(t, func(table string, chain string) error {
				return nil
			})
			err := i.ConfigureRules(1, "Context", containerinfo)
			//This will fail for ipset since we need to run this as root for ipsets
			Convey("It should succeed", func() {
				//This is erroring since ipset creation is not available to a unpriveleged user
				So(err.Error(), ShouldContainSubstring, "Proxy")
				//So(err, ShouldBeNil)
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
				nil,
				nil,
				ipl,
				[]string{"172.17.0.0/24"},
				[]string{},
				[]string{},
				nil,
				nil,
				[]string{},
			)

			containerinfo := policy.NewPUInfo("Context", common.ContainerPU)
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
				nil,
				nil,
				ipl,
				[]string{"172.17.0.0/24"},
				[]string{},
				[]string{},
				nil,
				nil,
				[]string{},
			)

			containerinfo := policy.NewPUInfo("Context", common.ContainerPU)
			containerinfo.Policy = policyrules
			containerinfo.Runtime = policy.NewPURuntimeWithDefaults()

			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				return nil
			})
			iptables.MockNewChain(t, func(table string, chain string) error {
				return errors.New("unable to add container chain")
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
				nil,
				nil,
				ipl,
				[]string{"172.17.0.0/24"},
				[]string{},
				[]string{},
				nil,
				nil,
				[]string{},
			)

			containerinfo := policy.NewPUInfo("Context", common.ContainerPU)
			containerinfo.Policy = policyrules
			containerinfo.Runtime = policy.NewPURuntimeWithDefaults()

			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
				return errors.New("unabke to add container chain")
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
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.RemoteContainer, portset.New(nil))
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables

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
			err := i.DeleteRules(1, "context", "0", "0", "", "", "5000")
			So(err, ShouldBeNil)
		})

	})
}

func TestUpdateRules(t *testing.T) {
	Convey("Given an iptables controllers", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.RemoteContainer, portset.New(nil))
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

		Convey("I try to update with a valid default IP address ", func() {
			app0, net0, err0 := i.chainName("Context", 0)
			app1, net1, err1 := i.chainName("Context", 1)

			So(err0, ShouldBeNil)
			So(err1, ShouldBeNil)

			iptables.MockDelete(t, func(table string, chain string, rulespec ...string) error {

				if matchSpec(app0, rulespec) == nil || matchSpec(net0, rulespec) == nil {
					return nil
				}
				return errors.New("error")
			})
			iptables.MockClearChain(t, func(table string, chain string) error {
				if chain == app0 || chain == net0 {
					return nil
				}
				return errors.New("error")
			})
			iptables.MockDeleteChain(t, func(table string, chain string) error {
				if chain == app0 || chain == net0 {
					return nil
				}
				return errors.New("error")
			})
			iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {

				if chain == app1 || chain == net1 || chain == "RedirProxy-Net" || chain == "RedirProxy-App" ||
					chain == "Proxy-Net" || chain == "Proxy-App" {
					return nil
				}
				if matchSpec(app1, rulespec) == nil || matchSpec(net1, rulespec) == nil {
					return nil
				}
				return errors.New("error")
			})
			iptables.MockInsert(t, func(table string, chain string, pos int, rulespec ...string) error {
				if chain == app1 || chain == net1 {
					return nil
				}
				return errors.New("error")
			})
			iptables.MockNewChain(t, func(table string, chain string) error {

				if chain == app1 || chain == net1 {
					return nil
				}
				return errors.New("error")
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
				nil,
				nil,
				ipl,
				[]string{"172.17.0.0/24"},
				[]string{},
				[]string{},
				nil,
				nil,
				[]string{},
			)

			containerinfo := policy.NewPUInfo("Context", common.ContainerPU)
			containerinfo.Policy = policyrules
			containerinfo.Runtime = policy.NewPURuntimeWithDefaults()

			err := i.UpdateRules(1, "Context", containerinfo, nil)
			Convey("I should get no error", func() {
				So(err, ShouldBeNil)
			})
		})

	})
}

func TestStart(t *testing.T) {
	Convey("Given an iptables controllers,", t, func() {
		i, _ := NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.RemoteContainer, portset.New(nil))
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
			err := i.Run(context.Background())
			Convey("I should get no error", func() {
				So(err, ShouldBeNil)
			})
		})
	})
}
