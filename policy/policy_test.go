package policy

import (
	"testing"

	"github.com/aporeto-inc/trireme/constants"
	. "github.com/smartystreets/goconvey/convey"
)

func TestNewPolicy(t *testing.T) {
	Convey("Given that I instantiate a new policy", t, func() {

		Convey("When I provide only the mandatory fields", func() {
			p := NewPUPolicy("id1", AllowAll, nil, nil, nil, nil, nil, nil, nil, []string{"172.17.0.0/16"}, []string{})
			Convey("I shpuld get an empty policy", func() {
				So(p, ShouldNotBeNil)
				So(p.triremeNetworks, ShouldResemble, []string{"172.17.0.0/16"})
				So(p.applicationACLs, ShouldNotBeNil)
				So(p.networkACLs, ShouldNotBeNil)
				So(p.triremeAction, ShouldEqual, AllowAll)
				So(p.transmitterRules, ShouldNotBeNil)
				So(p.receiverRules, ShouldNotBeNil)
				So(p.identity, ShouldNotBeNil)
				So(p.ips, ShouldNotBeNil)
				So(p.excludedNetworks, ShouldNotBeNil)
			})
		})

		Convey("When I provide all the feilds", func() {
			appACL := IPRule{
				Policy: &FlowPolicy{
					Action:   Accept,
					PolicyID: "1",
				},
				Address:  "10.0.0.0/8",
				Protocol: "tcp",
				Port:     "80",
			}

			netACL := IPRule{
				Policy: &FlowPolicy{
					Action:   Accept,
					PolicyID: "2",
				},
				Address:  "20.0.0.0/8",
				Protocol: "tcp",
				Port:     "80",
			}

			clause := KeyValueOperator{
				Key:      "app",
				Value:    []string{"web"},
				Operator: Equal,
			}

			txtags := TagSelectorList{
				TagSelector{
					Clause: []KeyValueOperator{clause},
					Policy: &FlowPolicy{Action: Accept, PolicyID: "3"},
				},
			}
			rxtags := TagSelectorList{
				TagSelector{
					Clause: []KeyValueOperator{clause},
					Policy: &FlowPolicy{Action: Reject, PolicyID: "4"},
				},
			}

			identity := NewTagStore()
			identity.AppendKeyValue("image", "nginx")

			annotations := NewTagStore()
			annotations.AppendKeyValue("image", "nginx")
			annotations.AppendKeyValue("server", "local")

			ips := ExtendedMap{DefaultNamespace: "172.0.0.1"}
			triremeNetworks := []string{"10.1.1.0/24"}
			excludedNetworks := []string{"10.1.1.1"}

			p := NewPUPolicy(
				"id1",
				AllowAll,
				IPRuleList{appACL},
				IPRuleList{netACL},
				txtags,
				rxtags,
				identity,
				annotations,
				ips,
				triremeNetworks,
				excludedNetworks,
			)

			Convey("Then I should get the right policy", func() {
				So(p, ShouldNotBeNil)
				So(p.triremeAction, ShouldEqual, AllowAll)
				So(p.applicationACLs, ShouldResemble, IPRuleList{appACL})
				So(p.networkACLs, ShouldResemble, IPRuleList{netACL})
				So(p.transmitterRules, ShouldResemble, txtags)
				So(p.receiverRules, ShouldResemble, rxtags)
				So(p.identity, ShouldResemble, identity)
				So(p.annotations, ShouldResemble, annotations)
				So(p.ips, ShouldResemble, ips)
				So(p.triremeNetworks, ShouldResemble, triremeNetworks)
				So(p.excludedNetworks, ShouldResemble, excludedNetworks)
			})
		})
	})
}

func TestNewPolicyWithDefaults(t *testing.T) {
	Convey("When I create a default policy", t, func() {
		p := NewPUPolicyWithDefaults()
		Convey("I shpuld get an empty policy", func() {
			So(p, ShouldNotBeNil)
			So(p.triremeNetworks, ShouldResemble, []string{})
			So(p.applicationACLs, ShouldNotBeNil)
			So(p.networkACLs, ShouldNotBeNil)
			So(p.triremeAction, ShouldEqual, AllowAll)
			So(p.transmitterRules, ShouldNotBeNil)
			So(p.receiverRules, ShouldNotBeNil)
			So(p.identity, ShouldNotBeNil)
			So(p.ips, ShouldNotBeNil)
			So(p.excludedNetworks, ShouldNotBeNil)
		})
	})
}

func TestFuncClone(t *testing.T) {
	Convey("When I have a default policy", t, func() {
		appACL := IPRule{
			Policy: &FlowPolicy{
				Action:   Accept,
				PolicyID: "1",
			},
			Address:  "10.0.0.0/8",
			Protocol: "tcp",
			Port:     "80",
		}

		netACL := IPRule{
			Policy: &FlowPolicy{
				Action:   Accept,
				PolicyID: "2",
			},
			Address:  "20.0.0.0/8",
			Protocol: "tcp",
			Port:     "80",
		}

		clause := KeyValueOperator{
			Key:      "app",
			Value:    []string{"web"},
			Operator: Equal,
		}

		txtags := TagSelectorList{
			TagSelector{
				Clause: []KeyValueOperator{clause},
				Policy: &FlowPolicy{Action: Accept, PolicyID: "3"},
			},
		}
		rxtags := TagSelectorList{
			TagSelector{
				Clause: []KeyValueOperator{clause},
				Policy: &FlowPolicy{Action: Reject, PolicyID: "4"},
			},
		}

		identity := NewTagStore()
		identity.AppendKeyValue("image", "nginx")

		annotations := NewTagStore()
		annotations.AppendKeyValue("image", "nginx")
		annotations.AppendKeyValue("server", "local")

		ips := ExtendedMap{DefaultNamespace: "172.0.0.1"}
		triremeNetworks := []string{"10.1.1.0/24"}
		excludedNetworks := []string{"10.1.1.1"}

		d := NewPUPolicy(
			"id1",
			AllowAll,
			IPRuleList{appACL},
			IPRuleList{netACL},
			txtags,
			rxtags,
			identity,
			annotations,
			ips,
			triremeNetworks,
			excludedNetworks,
		)
		Convey("If I clone the policy", func() {
			p := d.Clone()

			Convey("I should get the same policy", func() {
				So(p, ShouldNotBeNil)
				So(p.triremeAction, ShouldEqual, AllowAll)
				So(p.applicationACLs, ShouldResemble, IPRuleList{appACL})
				So(p.networkACLs, ShouldResemble, IPRuleList{netACL})
				So(p.transmitterRules, ShouldResemble, txtags)
				So(p.receiverRules, ShouldResemble, rxtags)
				So(p.identity, ShouldResemble, identity)
				So(p.annotations, ShouldResemble, annotations)
				So(p.ips, ShouldResemble, ips)
				So(p.triremeNetworks, ShouldResemble, triremeNetworks)
				So(p.excludedNetworks, ShouldResemble, excludedNetworks)
			})
		})
	})
}

func TestAllLockedSetGet(t *testing.T) {
	Convey("Given a good policy", t, func() {
		appACL := IPRule{
			Policy: &FlowPolicy{
				Action:   Accept,
				PolicyID: "1",
			},
			Address:  "10.0.0.0/8",
			Protocol: "tcp",
			Port:     "80",
		}

		netACL := IPRule{
			Policy: &FlowPolicy{
				Action:   Accept,
				PolicyID: "2",
			},
			Address:  "20.0.0.0/8",
			Protocol: "tcp",
			Port:     "80",
		}

		clause := KeyValueOperator{
			Key:      "app",
			Value:    []string{"web"},
			Operator: Equal,
		}

		txtags := TagSelectorList{
			TagSelector{
				Clause: []KeyValueOperator{clause},
				Policy: &FlowPolicy{Action: Accept, PolicyID: "3"},
			},
		}
		rxtags := TagSelectorList{
			TagSelector{
				Clause: []KeyValueOperator{clause},
				Policy: &FlowPolicy{Action: Reject, PolicyID: "4"},
			},
		}

		identity := NewTagStore()
		identity.AppendKeyValue("image", "nginx")

		annotations := NewTagStore()
		annotations.AppendKeyValue("image", "nginx")
		annotations.AppendKeyValue("server", "local")

		ips := ExtendedMap{DefaultNamespace: "172.0.0.1"}
		triremeNetworks := []string{"10.1.1.0/24"}
		excludedNetworks := []string{"10.1.1.1"}

		p := NewPUPolicy(
			"id1",
			AllowAll,
			IPRuleList{appACL},
			IPRuleList{netACL},
			txtags,
			rxtags,
			identity,
			annotations,
			ips,
			triremeNetworks,
			excludedNetworks,
		)

		Convey("I should be able to retrieve the management ID ", func() {
			id := p.ManagementID()
			So(id, ShouldResemble, "id1")
		})

		Convey("I should be able to retrieve the Action", func() {
			So(p.TriremeAction(), ShouldEqual, AllowAll)
		})

		Convey("I should be able to set the trireme action", func() {
			p.SetTriremeAction(Police)
			So(p.triremeAction, ShouldEqual, Police)
		})

		Convey("I should be able to retrieve the APP acls ", func() {
			So(p.ApplicationACLs(), ShouldResemble, IPRuleList{appACL})
		})

		Convey("I should be able to retrieve the NET acls", func() {
			So(p.NetworkACLs(), ShouldResemble, IPRuleList{netACL})
		})

		Convey("I should be able to retrieve the receiver rules", func() {
			So(p.ReceiverRules(), ShouldResemble, rxtags)
		})

		Convey("I should be able to retrieve the transmitter rules", func() {
			So(p.TransmitterRules(), ShouldResemble, txtags)
		})

		Convey("I should be able to retrieve the identity", func() {
			So(p.Identity(), ShouldResemble, identity)
		})

		Convey("I should be able to retrieve the annotations", func() {
			So(p.Annotations(), ShouldResemble, annotations)
		})

		Convey("I should be able to retrive the IPAddresses", func() {
			So(p.IPAddresses(), ShouldResemble, ips)
		})

		Convey("I should be able to retrieve the Trireme networks", func() {
			So(p.TriremeNetworks(), ShouldResemble, []string{"10.1.1.0/24"})
		})

		Convey("I should be able to retrieve the external networks", func() {
			So(p.ExcludedNetworks(), ShouldResemble, []string{"10.1.1.1"})
		})

		Convey("If I add an identity key/value pair, it should succeed", func() {
			p.AddIdentityTag("key", "value")
			t, ok := p.Identity().Get("key")
			So(ok, ShouldBeTrue)
			So(t, ShouldResemble, "value")
		})

		Convey("If I update the IPS, it should succeed", func() {
			p.SetIPAddresses(ExtendedMap{DefaultNamespace: "40.0.0.0/8"})
			So(p.IPAddresses(), ShouldResemble, ExtendedMap{DefaultNamespace: "40.0.0.0/8"})

			defaultIP, ok := p.DefaultIPAddress()
			So(ok, ShouldBeTrue)
			So(defaultIP, ShouldResemble, "40.0.0.0/8")
		})

		Convey("If I update the IPs with a non default bridge, I should get the default IP", func() {
			p.SetIPAddresses(ExtendedMap{"random bridge": "40.0.0.0/8"})
			defaultIP, ok := p.DefaultIPAddress()
			So(ok, ShouldBeFalse)
			So(defaultIP, ShouldResemble, "0.0.0.0/0")
		})

		Convey("If I update the trireme networks it should succeed", func() {
			p.UpdateTriremeNetworks([]string{"123.0.0.0/8"})
			So(p.TriremeNetworks(), ShouldResemble, []string{"123.0.0.0/8"})
		})

		Convey("If I update the excluded networks it should succeed", func() {
			p.UpdateExcludedNetworks([]string{"90.0.0.0"})
			So(p.ExcludedNetworks(), ShouldResemble, []string{"90.0.0.0"})
		})

		newclause := KeyValueOperator{
			Key:      "app",
			Value:    []string{"added"},
			Operator: Equal,
		}

		Convey("If I add a transmitter rule, it should succeed", func() {

			rule := TagSelector{
				Clause: []KeyValueOperator{newclause},
				Policy: &FlowPolicy{Action: Accept, PolicyID: "3"},
			}

			p.AddTransmitterRules(rule)
			So(len(p.TransmitterRules()), ShouldEqual, 2)
			So(p.TransmitterRules()[1], ShouldResemble, rule)
		})

		Convey("If I add a receiver rule, it should succeed", func() {
			rule := TagSelector{
				Clause: []KeyValueOperator{newclause},
				Policy: &FlowPolicy{Action: Reject, PolicyID: "4"},
			}
			p.AddReceiverRules(rule)
			So(len(p.ReceiverRules()), ShouldEqual, 2)
			So(p.ReceiverRules()[1], ShouldResemble, rule)
		})
	})

}

func TestPUInfo(t *testing.T) {
	Convey("Given I try to initiate a new container policy", t, func() {
		puInfor := NewPUInfo("123", constants.ContainerPU)
		policy := NewPUPolicy("123", AllowAll, nil, nil, nil, nil, nil, nil, nil, []string{}, []string{})
		runtime := NewPURuntime("", 0, "", nil, nil, constants.ContainerPU, nil)

		Convey("Then I expect the struct to be populated", func() {
			So(puInfor.ContextID, ShouldEqual, "123")
			So(puInfor.Policy, ShouldResemble, policy)
			So(puInfor.Runtime, ShouldResemble, runtime)
		})
	})
}
