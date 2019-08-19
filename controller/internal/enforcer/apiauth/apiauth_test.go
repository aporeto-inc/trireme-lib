package apiauth

import (
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	triremecommon "go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/serviceregistry"
	"go.aporeto.io/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/portspec"
)

const (
	policyID  = "somepolicy"
	serviceID = "someservice"
	namespace = "somenamespace"
	appLabel  = "app=web"
)

func newBaseApplicationServices(id string, ipAddr string, exposedPortValue, publicPortValue, privatePortValue uint16, external bool) *policy.ApplicationService {

	_, exposedIP, err := net.ParseCIDR(ipAddr)
	So(err, ShouldBeNil)
	exposedPort, err := portspec.NewPortSpec(exposedPortValue, exposedPortValue, nil)
	So(err, ShouldBeNil)
	publicPort, err := portspec.NewPortSpec(publicPortValue, publicPortValue, nil)
	So(err, ShouldBeNil)
	privatePort, err := portspec.NewPortSpec(privatePortValue, privatePortValue, nil)
	So(err, ShouldBeNil)

	return &policy.ApplicationService{
		ID: id,
		NetworkInfo: &triremecommon.Service{
			Ports:    exposedPort,
			Protocol: 6,
			Addresses: []*net.IPNet{
				exposedIP,
			},
		},
		PublicNetworkInfo: &triremecommon.Service{
			Ports:    publicPort,
			Protocol: 6,
			Addresses: []*net.IPNet{
				exposedIP,
			},
		},
		PrivateNetworkInfo: &triremecommon.Service{
			Ports:     privatePort,
			Protocol:  6,
			Addresses: []*net.IPNet{},
		},
		Type:               policy.ServiceHTTP,
		PublicServiceNoTLS: false,
		External:           external,
		HTTPRules: []*policy.HTTPRule{
			{
				URIs:    []string{"/admin"},
				Methods: []string{"GET"},
				ClaimMatchingRules: [][]string{
					[]string{appLabel},
				},
				Public: false,
			},
			{
				URIs:    []string{"/public"},
				Methods: []string{"GET"},
				Public:  true,
			},
			{
				URIs:    []string{"/forbidden"},
				Methods: []string{"GET"},
				ClaimMatchingRules: [][]string{
					[]string{"Nobody"},
				},
				Public: false,
			},
		},
	}
}

func newAPIAuthProcessor(contextID string) (*serviceregistry.Registry, *pucontext.PUContext, secrets.Secrets) {

	baseService := newBaseApplicationServices("base", "10.1.1.0/24", uint16(80), uint16(443), uint16(80), false)
	externalService := newBaseApplicationServices("external", "45.0.0.0/8", uint16(80), uint16(443), uint16(80), true)

	exposedServices := policy.ApplicationServicesList{baseService}
	dependentServices := policy.ApplicationServicesList{baseService, externalService}

	networkACLs := policy.IPRuleList{
		policy.IPRule{
			Addresses: []string{"10.1.1.0/24"},
			Ports:     []string{"80"},
			Protocols: []string{"6"},
			Policy: &policy.FlowPolicy{
				Action:    policy.Accept,
				PolicyID:  policyID,
				ServiceID: serviceID,
				Labels:    []string{"service=external"},
			},
		},
		policy.IPRule{
			Addresses: []string{"45.0.0.0/0"},
			Ports:     []string{"80"},
			Protocols: []string{"6"},
			Policy: &policy.FlowPolicy{
				Action:    policy.Accept,
				PolicyID:  policyID,
				ServiceID: serviceID,
				Labels:    []string{"service=external"},
			},
		},
	}

	plc := policy.NewPUPolicy(
		contextID,
		namespace,
		policy.Police,
		policy.IPRuleList{},
		networkACLs,
		policy.DNSRuleList{},
		policy.TagSelectorList{},
		policy.TagSelectorList{},
		policy.NewTagStore(),
		policy.NewTagStoreFromSlice([]string{appLabel, "type=aporeto"}),
		nil,
		0,
		exposedServices,
		dependentServices,
		[]string{appLabel},
	)

	puInfo := policy.NewPUInfo(contextID, namespace, triremecommon.ContainerPU)
	puInfo.Policy = plc
	pctx, err := pucontext.NewPU(contextID, puInfo, time.Second*1000)
	So(err, ShouldBeNil)
	_, s, _ := secrets.CreateCompactPKITestSecrets()

	r := serviceregistry.NewServiceRegistry()
	_, err = r.Register(contextID, puInfo, pctx, s)
	So(err, ShouldBeNil)

	return r, pctx, s
}

func Test_New(t *testing.T) {
	Convey("When I create a new processor it should be correctly propulated", t, func() {

		r, _, s := newAPIAuthProcessor("test")
		p := New("test", r, s)

		So(p.puContext, ShouldEqual, "test")
		So(p.registry, ShouldEqual, r)
		So(p.secrets, ShouldEqual, s)
	})
}

func Test_ApplicationRequest(t *testing.T) {
	Convey("Given a valid authorization processor", t, func() {
		serviceRegistry, pctx, s := newAPIAuthProcessor("test")
		p := New("test", serviceRegistry, s)

		u, _ := url.Parse("http://www.foo.com") // nolint

		Convey("Given a request without context, it should error", func() {
			r := &Request{
				SourceAddress: &net.TCPAddr{
					IP:   net.ParseIP("10.1.1.1"),
					Port: 1000,
				},
				OriginalDestination: &net.TCPAddr{
					IP:   net.ParseIP("20.1.1.1"),
					Port: 8080,
				},
				Method:     "GET",
				URL:        u,
				RequestURI: "/public",
				Header:     http.Header{},
				Cookie:     nil,
				TLS:        nil,
			}
			_, err := p.ApplicationRequest(r)
			So(err, ShouldNotBeNil)

			authErr, ok := err.(*AuthError)
			So(ok, ShouldBeTrue)
			So(authErr.Status(), ShouldEqual, http.StatusBadGateway)
		})

		Convey("Given a request with valid context that is not external, I should get a token", func() {
			r := &Request{
				SourceAddress: &net.TCPAddr{
					IP:   net.ParseIP("10.1.1.1"),
					Port: 1000,
				},
				OriginalDestination: &net.TCPAddr{
					IP:   net.ParseIP("10.1.1.2"),
					Port: 80,
				},
				Method:     "GET",
				URL:        u,
				RequestURI: "/public",
				Header:     http.Header{},
				Cookie:     nil,
				TLS:        nil,
			}
			response, err := p.ApplicationRequest(r)
			So(err, ShouldBeNil)
			So(response, ShouldNotBeNil)
			So(len(response.Token), ShouldBeGreaterThan, 0)
			So(response.PUContext, ShouldEqual, pctx)
			So(response.TLSListener, ShouldBeTrue)
		})

		Convey("Given a request for a public external service, I should accept it", func() {
			r := &Request{
				SourceAddress: &net.TCPAddr{
					IP:   net.ParseIP("10.1.1.1"),
					Port: 1000,
				},
				OriginalDestination: &net.TCPAddr{
					IP:   net.ParseIP("45.1.1.1"),
					Port: 80,
				},
				Method:     "GET",
				URL:        u,
				RequestURI: "/public",
				Header:     http.Header{},
				Cookie:     nil,
				TLS:        nil,
			}
			response, err := p.ApplicationRequest(r)
			So(err, ShouldBeNil)
			So(response, ShouldNotBeNil)
			So(len(response.Token), ShouldEqual, 0)
			So(response.PUContext, ShouldEqual, pctx)
			So(response.TLSListener, ShouldBeTrue)
		})

		Convey("Given a request for a controlled external service with valid policy, I should accept it", func() {
			r := &Request{
				SourceAddress: &net.TCPAddr{
					IP:   net.ParseIP("10.1.1.1"),
					Port: 1000,
				},
				OriginalDestination: &net.TCPAddr{
					IP:   net.ParseIP("45.1.1.1"),
					Port: 80,
				},
				Method:     "GET",
				URL:        u,
				RequestURI: "/admin",
				Header:     http.Header{},
				Cookie:     nil,
				TLS:        nil,
			}
			response, err := p.ApplicationRequest(r)
			So(err, ShouldBeNil)
			So(response, ShouldNotBeNil)
			So(len(response.Token), ShouldEqual, 0)
			So(response.PUContext, ShouldEqual, pctx)
			So(response.TLSListener, ShouldBeTrue)
		})

		Convey("Given a request for a controlled external service with forbidden policy, I should reject it", func() {
			r := &Request{
				SourceAddress: &net.TCPAddr{
					IP:   net.ParseIP("10.1.1.1"),
					Port: 1000,
				},
				OriginalDestination: &net.TCPAddr{
					IP:   net.ParseIP("45.1.1.1"),
					Port: 80,
				},
				Method:     "GET",
				URL:        u,
				RequestURI: "/forbidden",
				Header:     http.Header{},
				Cookie:     nil,
				TLS:        nil,
			}
			_, err := p.ApplicationRequest(r)
			So(err, ShouldNotBeNil)
			authErr, ok := err.(*AuthError)
			So(ok, ShouldBeTrue)
			So(authErr.Status(), ShouldEqual, http.StatusForbidden)
		})

		Convey("Given a request for a controlled external service with an uknown URI, I should reject it", func() {
			r := &Request{
				SourceAddress: &net.TCPAddr{
					IP:   net.ParseIP("10.1.1.1"),
					Port: 1000,
				},
				OriginalDestination: &net.TCPAddr{
					IP:   net.ParseIP("45.1.1.1"),
					Port: 80,
				},
				Method:     "GET",
				URL:        u,
				RequestURI: "/random",
				Header:     http.Header{},
				Cookie:     nil,
				TLS:        nil,
			}
			_, err := p.ApplicationRequest(r)
			So(err, ShouldNotBeNil)
			authErr, ok := err.(*AuthError)
			So(ok, ShouldBeTrue)
			So(authErr.Status(), ShouldEqual, http.StatusForbidden)
		})

	})

}
