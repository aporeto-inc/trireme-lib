package ipsetctrl

import (
	"fmt"
	"testing"

	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/enforcer/utils/fqconfig"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/supervisor/provider"
	"github.com/bvandewalle/go-ipset/ipset"
	. "github.com/smartystreets/goconvey/convey"
)

func TestNewInstance(t *testing.T) {
	Convey("When I create a new ipsets instance", t, func() {

		Convey("If I create a local implemenetation and iptables and ipsets exists", func() {
			fqc := fqconfig.NewFilterQueueWithDefaults()
			i, err := NewInstance(fqc, false, constants.LocalContainer)
			Convey("It should succeed", func() {
				So(i, ShouldNotBeNil)
				So(err, ShouldBeNil)
				So(i.appPacketIPTableSection, ShouldResemble, "PREROUTING")
				So(i.netPacketIPTableSection, ShouldResemble, "POSTROUTING")
				So(i.fqc, ShouldEqual, fqc)
				So(i.ipt, ShouldNotBeNil)
				So(i.ips, ShouldNotBeNil)
			})
		})

		Convey("If I create a remote implemenetation and iptables and ipsets exists", func() {
			fqc := fqconfig.NewFilterQueueWithDefaults()
			i, err := NewInstance(fqc, true, constants.LocalContainer)
			Convey("It should succeed", func() {
				So(i, ShouldNotBeNil)
				So(err, ShouldBeNil)
				So(i.appPacketIPTableSection, ShouldResemble, "OUTPUT")
				So(i.netPacketIPTableSection, ShouldResemble, "INPUT")
				So(i.fqc, ShouldEqual, fqc)
				So(i.ipt, ShouldNotBeNil)
				So(i.ips, ShouldNotBeNil)
			})
		})
	})
}

func TestDefaultIP(t *testing.T) {
	Convey("Given an iptables controller", t, func() {
		fqc := fqconfig.NewFilterQueueWithDefaults()
		i, _ := NewInstance(fqc, true, constants.LocalContainer)
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
}

func TestSetPrefix(t *testing.T) {
	Convey("When I test the creation of the name of the chain", t, func() {
		fqc := fqconfig.NewFilterQueueWithDefaults()
		i, _ := NewInstance(fqc, true, constants.LocalContainer)
		Convey("With a contextID of Context and version of 1", func() {
			app, net := i.setPrefix("Context")
			Convey("I should get the right names", func() {
				So(app, ShouldResemble, "TRIREME-App-Context-")
				So(net, ShouldResemble, "TRIREME-Net-Context-")
			})
		})
	})
}

func TestConfigureRules(t *testing.T) {
	Convey("Given an ipset controller properly configured", t, func() {

		fqc := fqconfig.NewFilterQueueWithDefaults()
		i, _ := NewInstance(fqc, true, constants.LocalContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables
		ipsets := provider.NewTestIpsetProvider()
		i.ips = ipsets

		Convey("When I try to configure rules with nil policy", func() {
			err := i.ConfigureRules(0, "context", nil)
			Convey("It should fail with no crash", func() {
				So(err, ShouldNotBeNil)
			})
		})

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

		Convey("When I try to configure rules with no default IP ", func() {
			ipl := policy.ExtendedMap{}
			policyrules := policy.NewPUPolicy("Context",
				policy.Police,
				rules,
				rules,
				nil,
				nil,
				nil,
				nil,
				ipl,
				[]string{},
				[]string{})
			containerinfo := policy.NewPUInfo("Context", constants.ContainerPU)
			containerinfo.Policy = policyrules
			containerinfo.Runtime = policy.NewPURuntimeWithDefaults()

			err := i.ConfigureRules(0, "context", containerinfo)
			Convey("It should fail with no crash and return error", func() {
				So(err, ShouldNotBeNil)
			})
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
			ipl,
			[]string{},
			[]string{},
		)

		containerinfo := policy.NewPUInfo("Context", constants.ContainerPU)
		containerinfo.Policy = policyrules
		containerinfo.Runtime = policy.NewPURuntimeWithDefaults()

		Convey("When I try to configure rules with no container set  ", func() {
			err := i.ConfigureRules(0, "context", containerinfo)
			Convey("I should get an  error ", func() {
				So(err, ShouldNotBeNil)
			})
		})

		ipsets.MockNewIpset(t, func(name string, hasht string, p *ipset.Params) (provider.Ipset, error) {
			testset := provider.NewTestIpset()
			testset.MockAdd(t, func(entry string, timeout int) error {
				return nil
			})
			return testset, nil
		})

		iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
			return nil
		})

		iptables.MockInsert(t, func(table string, chain string, pos int, rulespec ...string) error {
			return nil
		})

		err := i.Start()
		So(err, ShouldBeNil)

		i.containerSet, _ = ipsets.NewIpset("container", "hash:ip", &ipset.Params{})

		Convey("When I try to configure rules after I add a container set and iptables/ipsets works ", func() {
			err := i.ConfigureRules(0, "context", containerinfo)
			Convey("I should get no errors ", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I try to configure rules and iptables fails", func() {
			iptables.MockInsert(t, func(table string, chain string, pos int, rulespec ...string) error {
				return fmt.Errorf("Error")
			})
			err := i.ConfigureRules(0, "context", containerinfo)
			Convey("I should get an error", func() {
				So(err, ShouldNotBeNil)
			})
		})

	})
}

func TestDeleteRules(t *testing.T) {
	Convey("Given a properly configured ipset controller", t, func() {
		fqc := fqconfig.NewFilterQueueWithDefaults()
		i, _ := NewInstance(fqc, true, constants.LocalContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables
		ipsets := provider.NewTestIpsetProvider()
		i.ips = ipsets

		ipsets.MockNewIpset(t, func(name string, hasht string, p *ipset.Params) (provider.Ipset, error) {
			testset := provider.NewTestIpset()
			testset.MockAdd(t, func(entry string, timeout int) error {
				return nil
			})
			testset.MockDel(t, func(entry string) error {
				return nil
			})
			return testset, nil
		})

		iptables.MockDelete(t, func(table string, chain string, rulespec ...string) error {
			return nil
		})
		i.containerSet, _ = ipsets.NewIpset("container", "hash:ip", &ipset.Params{})

		Convey("When I delete the rules of a container", func() {
			ipl := policy.ExtendedMap{}
			ipl[policy.DefaultNamespace] = "172.17.0.1"
			err := i.DeleteRules(0, "context", ipl, "0", "0", "")
			Convey("It should return no errors", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I delete the rules with invalid map list", func() {
			err := i.DeleteRules(0, "context", policy.ExtendedMap{}, "0", "0", "")
			Convey("It should return an error ", func() {
				So(err, ShouldNotBeNil)
			})
		})

	})
}

func TestUpdateRules(t *testing.T) {
	Convey("Given a properly configured ipset controller", t, func() {
		fqc := fqconfig.NewFilterQueueWithDefaults()
		i, _ := NewInstance(fqc, true, constants.LocalContainer)
		iptables := provider.NewTestIptablesProvider()
		i.ipt = iptables
		ipsets := provider.NewTestIpsetProvider()
		i.ips = ipsets

		ipsets.MockNewIpset(t, func(name string, hasht string, p *ipset.Params) (provider.Ipset, error) {
			testset := provider.NewTestIpset()
			testset.MockAdd(t, func(entry string, timeout int) error {
				return nil
			})
			testset.MockDel(t, func(entry string) error {
				return nil
			})
			testset.MockDestroy(t, func() error {
				return nil
			})
			return testset, nil
		})

		iptables.MockDelete(t, func(table string, chain string, rulespec ...string) error {
			if chain == "context-R-0" || chain == "context-A-0" {
				return nil
			}
			return fmt.Errorf("Error")
		})

		iptables.MockAppend(t, func(table string, chain string, rulespec ...string) error {
			if chain == "context-R-1" || chain == "context-A-1" {
				return nil
			}
			return fmt.Errorf("Error")
		})
		i.containerSet, _ = ipsets.NewIpset("container", "hash:ip", &ipset.Params{})

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

		ipl := policy.ExtendedMap{policy.DefaultNamespace: "172.17.0.1"}
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

		Convey("When I update the rules of a container", func() {

			err := i.DeleteRules(0, "context", ipl, "0", "0", "")
			Convey("It should return no errors", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I delete the rules with invalid map list", func() {
			err := i.UpdateRules(0, "context", containerinfo)
			Convey("It should succeed with no errors  ", func() {
				So(err, ShouldBeNil)
			})
		})

	})
}

func TestAddExcludedIP(t *testing.T) {
	Convey("Testing AddExcludedIP", t, func() {
		fqc := fqconfig.NewFilterQueueWithDefaults()
		Convey("When i call with empty list it returns nil error", func() {
			i, _ := NewInstance(fqc, true, constants.LocalContainer)
			err := i.AddExcludedIP([]string{})
			So(err, ShouldBeNil)
		})
		Convey("When i call with a populate list error should be nil", func() {
			i, _ := NewInstance(fqc, true, constants.LocalContainer)
			err := i.AddExcludedIP([]string{"172.22.197.32"})
			//Since nothing is initialized
			So(err, ShouldNotBeNil)
		})
	})
}

func TestRemoveExcludedIP(t *testing.T) {
}
