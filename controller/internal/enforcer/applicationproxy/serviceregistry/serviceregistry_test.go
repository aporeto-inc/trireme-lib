package serviceregistry

import (
	"net"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	triremecommon "go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/common"
	"go.aporeto.io/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/portspec"
)

func newBaseApplicationServices(exposedPortValue, publicPortValue, privatePortValue, dependentPortValue uint16) (*policy.ApplicationService, *policy.ApplicationService) {

	_, exposed1, err := net.ParseCIDR("10.1.1.0/24")
	So(err, ShouldBeNil)
	_, exposed2, err := net.ParseCIDR("20.1.1.0/24")
	So(err, ShouldBeNil)
	_, public1, err := net.ParseCIDR("30.1.1.0/24")
	So(err, ShouldBeNil)
	_, public2, err := net.ParseCIDR("40.1.1.0/24")
	So(err, ShouldBeNil)
	_, dependent1, err := net.ParseCIDR("50.1.1.0/24")
	So(err, ShouldBeNil)
	_, dependent2, err := net.ParseCIDR("60.1.1.0/24")
	So(err, ShouldBeNil)
	exposedPort, err := portspec.NewPortSpec(exposedPortValue, exposedPortValue, nil)
	So(err, ShouldBeNil)
	publicPort, err := portspec.NewPortSpec(publicPortValue, publicPortValue, nil)
	So(err, ShouldBeNil)
	privatePort, err := portspec.NewPortSpec(privatePortValue, privatePortValue, nil)
	So(err, ShouldBeNil)
	dependentPort, err := portspec.NewPortSpec(dependentPortValue, dependentPortValue, nil)
	So(err, ShouldBeNil)

	return &policy.ApplicationService{
			ID: "policyExposed",
			NetworkInfo: &triremecommon.Service{
				Ports:    exposedPort,
				Protocol: 6,
				Addresses: []*net.IPNet{
					exposed1,
					exposed2,
				},
			},
			PublicNetworkInfo: &triremecommon.Service{
				Ports:    publicPort,
				Protocol: 6,
				Addresses: []*net.IPNet{
					public1,
				},
			},
			PrivateNetworkInfo: &triremecommon.Service{
				Ports:     privatePort,
				Protocol:  6,
				Addresses: []*net.IPNet{},
			},
			Type:               policy.ServiceHTTP,
			PublicServiceNoTLS: false,
		},
		&policy.ApplicationService{
			ID: "policyDepend",
			NetworkInfo: &triremecommon.Service{
				Ports:    dependentPort,
				Protocol: 6,
				Addresses: []*net.IPNet{
					dependent1,
					dependent2,
				},
			},
			PublicNetworkInfo: &triremecommon.Service{
				Ports:    publicPort,
				Protocol: 6,
				Addresses: []*net.IPNet{
					public2,
				},
			},
			PrivateNetworkInfo: &triremecommon.Service{
				Ports:     privatePort,
				Protocol:  6,
				Addresses: []*net.IPNet{},
			},
			Type:               policy.ServiceHTTP,
			PublicServiceNoTLS: false,
		}
}

func newPU(name string, exposedPort, publicPort, privatePort, dependentPort uint16, doubleExposed, doubleDependent bool) (*policy.PUInfo, *pucontext.PUContext, secrets.Secrets) {
	exposed, dependent := newBaseApplicationServices(exposedPort, publicPort, privatePort, dependentPort)

	exposedServices := policy.ApplicationServicesList{exposed}
	if doubleExposed {
		exposedServices = append(exposedServices, exposed)
	}

	dependentServices := policy.ApplicationServicesList{dependent}
	if doubleDependent {
		dependentServices = append(dependentServices, dependent)
	}
	plc := policy.NewPUPolicy(
		name+"-policyid1",
		policy.Police,
		policy.IPRuleList{},
		policy.IPRuleList{},
		policy.DNSRuleList{},
		policy.TagSelectorList{},
		policy.TagSelectorList{},
		policy.NewTagStore(),
		policy.NewTagStoreFromSlice([]string{"app=web", "type=aporeto"}),
		nil,
		0,
		exposedServices,
		dependentServices,
		[]string{},
	)

	puInfo := policy.NewPUInfo(name, triremecommon.ContainerPU)
	puInfo.Policy = plc
	pctx, err := pucontext.NewPU(name, puInfo, time.Second*1000)
	So(err, ShouldBeNil)
	_, s, _ := secrets.CreateCompactPKITestSecrets()
	return puInfo, pctx, s
}

func TestNewRegistry(t *testing.T) {
	Convey("When I create a new registry, it should be properly configured", t, func() {
		r := NewServiceRegistry()
		So(r, ShouldNotBeNil)
		So(r.indexByName, ShouldNotBeNil)
		So(r.indexByPort, ShouldNotBeNil)
	})
}

func TestRegister(t *testing.T) {
	Convey("Given a new registry", t, func() {
		r := NewServiceRegistry()
		Convey("When I register a new PU with no services", func() {
			puInfo, pctx, s := newPU("pu1", 8080, 443, 80, 8080, false, false)
			sctx, err := r.Register("pu1", puInfo, pctx, s)
			Convey("The data structures should be correct and I should be able to retrieve the service", func() {
				So(err, ShouldBeNil)
				So(sctx, ShouldNotBeNil)
				So(sctx.PU, ShouldResemble, puInfo)
				So(sctx.PUContext, ShouldResemble, pctx)
				So(sctx.dependentServiceCache, ShouldNotBeNil)
			})
			Convey("And I should be able to retrieve the services using the three provided methods", func() {
				serviceContext, rerr := r.RetrieveServiceByID("pu1")
				So(rerr, ShouldBeNil)
				So(serviceContext, ShouldNotBeNil)
				So(serviceContext, ShouldResemble, sctx)

				portContext, perr := r.RetrieveExposedServiceContext(net.ParseIP("10.1.1.1").To4(), 80, "")
				So(perr, ShouldBeNil)
				So(portContext, ShouldNotBeNil)
				So(portContext.ID, ShouldResemble, "pu1")
				So(portContext.TargetPort, ShouldEqual, 80)
				So(portContext.Service, ShouldResemble, puInfo.Policy.ExposedServices()[0])
				So(portContext.Type, ShouldEqual, common.HTTPSNetwork)

			})
			Convey("But I should get errors for non existing ports or services", func() {
				serviceContext, rerr := r.RetrieveServiceByID("badpu")
				So(rerr, ShouldNotBeNil)
				So(serviceContext, ShouldBeNil)

				portContext, perr := r.RetrieveExposedServiceContext(net.ParseIP("100.1.1.1").To4(), 100, "")
				So(perr, ShouldNotBeNil)
				So(portContext, ShouldBeNil)
			})

			Convey("When I register a second service with no overlaps", func() {
				puInfo, pctx, s := newPU("pu2", 8000, 4443, 8080, 10000, false, false)
				sctx, err := r.Register("pu2", puInfo, pctx, s)
				So(err, ShouldBeNil)
				So(sctx, ShouldNotBeNil)

				Convey("And I should be able to retrieve the updated services using the three provided methods", func() {
					serviceContext, rerr := r.RetrieveServiceByID("pu2")
					So(rerr, ShouldBeNil)
					So(serviceContext, ShouldNotBeNil)
					So(serviceContext, ShouldResemble, sctx)

					portContext, perr := r.RetrieveExposedServiceContext(net.ParseIP("10.1.1.1").To4(), 8080, "")
					So(perr, ShouldBeNil)
					So(portContext, ShouldNotBeNil)
					So(portContext.ID, ShouldResemble, "pu2")
					So(portContext.TargetPort, ShouldEqual, 8080)
					So(portContext.Service, ShouldResemble, puInfo.Policy.ExposedServices()[0])
					So(portContext.Type, ShouldEqual, common.HTTPSNetwork)
				})
			})

			Convey("When I register a second service with port overlaps, I should get errors", func() {
				// exposedService overlap
				puInfo, pctx, s := newPU("pu2", 8080, 4443, 8080, 10000, true, false)
				sctx, err := r.Register("pu2", puInfo, pctx, s)
				So(err, ShouldNotBeNil)
				So(sctx, ShouldBeNil)

				// dependentService overlap
				puInfo, pctx, s = newPU("pu2", 8080, 4443, 8080, 10000, false, true)
				sctx, err = r.Register("pu2", puInfo, pctx, s)
				So(err, ShouldNotBeNil)
				So(sctx, ShouldBeNil)

				// both overlaps
				puInfo, pctx, s = newPU("pu2", 8080, 4443, 8080, 10000, true, true)
				sctx, err = r.Register("pu2", puInfo, pctx, s)
				So(err, ShouldNotBeNil)
				So(sctx, ShouldBeNil)

			})

			Convey("When I re-register the service with updates on the ports", func() {
				puInfo, pctx, s := newPU("pu1", 8000, 4443, 8080, 10000, false, false)
				sctx, err := r.Register("pu1", puInfo, pctx, s)
				So(err, ShouldBeNil)
				So(sctx, ShouldNotBeNil)

				Convey("And I should be able to retrieve the updated services using the three provided methods", func() {
					serviceContext, rerr := r.RetrieveServiceByID("pu1")
					So(rerr, ShouldBeNil)
					So(serviceContext, ShouldNotBeNil)
					So(serviceContext, ShouldResemble, sctx)

					portContext, perr := r.RetrieveExposedServiceContext(net.ParseIP("10.1.1.1").To4(), 8080, "")
					So(perr, ShouldBeNil)
					So(portContext, ShouldNotBeNil)
					So(portContext.ID, ShouldResemble, "pu1")
					So(portContext.TargetPort, ShouldEqual, 8080)
					So(portContext.Service, ShouldResemble, puInfo.Policy.ExposedServices()[0])
					So(portContext.Type, ShouldEqual, common.HTTPSNetwork)
				})
			})

			Convey("When I unregister the service, it should be deleted", func() {
				uerr := r.Unregister("pu1")
				So(uerr, ShouldBeNil)
				retrievedContext, rerr := r.RetrieveServiceByID("pu1")
				So(rerr, ShouldNotBeNil)
				So(retrievedContext, ShouldBeNil)
				portContext, perr := r.RetrieveExposedServiceContext(net.ParseIP("10.1.1.1").To4(), 80, "")
				So(perr, ShouldNotBeNil)
				So(portContext, ShouldBeNil)
			})
		})
	})
}

func TestServiceTypeToNetworkListenerType(t *testing.T) {
	Convey("When I convert a network HTTP service it should be HTTPNetwork", t, func() {
		t := serviceTypeToNetworkListenerType(policy.ServiceHTTP, true)
		So(t, ShouldEqual, common.HTTPNetwork)
	})
	Convey("When I convert a network HTTPS service it should be HTTPSNetwork", t, func() {
		t := serviceTypeToNetworkListenerType(policy.ServiceHTTP, false)
		So(t, ShouldEqual, common.HTTPSNetwork)
	})
	Convey("When I convert a TCP service it should be TCPNetwork", t, func() {
		t := serviceTypeToNetworkListenerType(policy.ServiceTCP, false)
		So(t, ShouldEqual, common.TCPNetwork)
	})
}

func TestServiceTypeToApplicationListenerType(t *testing.T) {
	Convey("When I convert an application HTTP service it should be HTTPApplication", t, func() {
		t := serviceTypeToApplicationListenerType(policy.ServiceHTTP)
		So(t, ShouldEqual, common.HTTPApplication)
	})
	Convey("When I convert an application TCP service it should be TCPApplication", t, func() {
		t := serviceTypeToApplicationListenerType(policy.ServiceTCP)
		So(t, ShouldEqual, common.TCPApplication)
	})
}
