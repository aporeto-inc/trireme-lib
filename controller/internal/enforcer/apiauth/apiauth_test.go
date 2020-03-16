// +build !windows

package apiauth

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/v11/collector"
	triremecommon "go.aporeto.io/trireme-lib/v11/common"
	"go.aporeto.io/trireme-lib/v11/controller/internal/enforcer/applicationproxy/serviceregistry"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/servicetokens"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/usertokens/mockusertokens"
	"go.aporeto.io/trireme-lib/v11/policy"
	"go.aporeto.io/trireme-lib/v11/utils/portspec"
)

const (
	policyID        = "somepolicy"
	rejectPolicyID  = "somerejectepolicy"
	serviceID       = "someservice"
	rejectServiceID = "somerejectservice"
	namespace       = "somenamespace"
	appLabel        = "app=web"
)

func newBaseApplicationServices(ctrl *gomock.Controller, id string, ipAddr string, exposedPortValue, publicPortValue, privatePortValue uint16, external bool) *policy.ApplicationService {

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
					{appLabel},
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
					{"Nobody"},
				},
				Public: false,
			},
		},
		UserAuthorizationType:    policy.UserAuthorizationOIDC,
		UserAuthorizationHandler: mockusertokens.NewMockVerifier(ctrl),
	}
}

func newAPIAuthProcessor(ctrl *gomock.Controller) (*serviceregistry.Registry, *pucontext.PUContext, secrets.Secrets) {

	contextID := "test"
	baseService := newBaseApplicationServices(ctrl, "base", "10.1.1.0/24", uint16(80), uint16(443), uint16(80), false)
	externalService := newBaseApplicationServices(ctrl, "external", "45.0.0.0/8", uint16(80), uint16(443), uint16(80), true)
	externalBadService := newBaseApplicationServices(ctrl, "external", "100.0.0.0/8", uint16(80), uint16(443), uint16(80), true)

	exposedServices := policy.ApplicationServicesList{baseService}
	dependentServices := policy.ApplicationServicesList{baseService, externalService, externalBadService}

	networkACLs := policy.IPRuleList{
		{
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
		{
			Addresses: []string{"45.0.0.0/8"},
			Ports:     []string{"80"},
			Protocols: []string{"6"},
			Policy: &policy.FlowPolicy{
				Action:    policy.Accept,
				PolicyID:  policyID,
				ServiceID: serviceID,
				Labels:    []string{"service=external"},
			},
		},
		{
			Addresses: []string{"100.0.0.0/8"},
			Ports:     []string{"80"},
			Protocols: []string{"6"},
			Policy: &policy.FlowPolicy{
				Action:    policy.Reject,
				PolicyID:  rejectPolicyID,
				ServiceID: rejectServiceID,
				Labels:    []string{"service=external"},
			},
		},
	}

	applicationACLs := policy.IPRuleList{
		{
			Addresses: []string{"100.0.0.0/8"},
			Ports:     []string{"80"},
			Protocols: []string{"6"},
			Policy: &policy.FlowPolicy{
				Action:    policy.Reject,
				PolicyID:  rejectPolicyID,
				ServiceID: rejectServiceID,
				Labels:    []string{"service=external"},
			},
		},
	}

	plc := policy.NewPUPolicy(
		contextID,
		namespace,
		policy.Police,
		applicationACLs,
		networkACLs,
		policy.DNSRuleList{},
		policy.TagSelectorList{},
		policy.TagSelectorList{
			policy.TagSelector{
				Clause: []policy.KeyValueOperator{
					{
						Key:      "app",
						Value:    []string{"web"},
						Operator: policy.Equal,
						ID:       "somepolicy",
					},
				},
				Policy: &policy.FlowPolicy{
					Action:    policy.Accept,
					ServiceID: "pu" + serviceID,
					PolicyID:  "pu" + policyID,
				},
			},
			policy.TagSelector{
				Clause: []policy.KeyValueOperator{
					{
						Key:      "app",
						Value:    []string{"bad"},
						Operator: policy.Equal,
						ID:       "rejectpolicy",
					},
				},
				Policy: &policy.FlowPolicy{
					Action:   policy.Reject,
					PolicyID: "reject" + policyID,
				},
			},
		},
		policy.NewTagStore(),
		policy.NewTagStoreFromSlice([]string{appLabel, "type=aporeto"}),
		nil,
		nil,
		0,
		0,
		exposedServices,
		dependentServices,
		[]string{appLabel},
		policy.EnforcerMapping,
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
		ctrl := gomock.NewController(t)
		r, _, s := newAPIAuthProcessor(ctrl)
		p := New("test", r, s)

		So(p.puContext, ShouldEqual, "test")
		So(p.registry, ShouldEqual, r)
		So(p.secrets, ShouldEqual, s)
	})
}

func Test_ApplicationRequest(t *testing.T) {
	Convey("Given a valid authorization processor", t, func() {
		ctrl := gomock.NewController(t)
		serviceRegistry, pctx, s := newAPIAuthProcessor(ctrl)
		p := New("test", serviceRegistry, s)

		Convey("Given a request without context, it should error", func() {

			u, _ := url.Parse("http://www.foo.com/public") // nolint
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
			u, _ := url.Parse("http://www.foo.com/public") // nolint
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
			u, _ := url.Parse("http://www.foo.com/public") // nolint
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
			u, _ := url.Parse("http://www.foo.com/admin") // nolint
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
			u, _ := url.Parse("http://www.foo.com/forbidden") // nolint
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
			u, _ := url.Parse("http://www.foo.com/random") // nolint
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

		Convey("Given a request for a an external service dropped by network rules it should be rejected", func() {
			u, _ := url.Parse("http://www.foo.com/random") // nolint
			r := &Request{
				SourceAddress: &net.TCPAddr{
					IP:   net.ParseIP("10.1.1.1"),
					Port: 1000,
				},
				OriginalDestination: &net.TCPAddr{
					IP:   net.ParseIP("100.1.1.1"),
					Port: 80,
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
			So(authErr.Status(), ShouldEqual, http.StatusNetworkAuthenticationRequired)
		})
	})
}

func Test_NetworkRequest(t *testing.T) {
	Convey("Given a valid authorization processor", t, func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ctrl := gomock.NewController(t)
		serviceRegistry, pctx, s := newAPIAuthProcessor(ctrl)
		p := New("test", serviceRegistry, s)

		Convey("Requests for bad context should return errors", func() {
			u, _ := url.Parse("http://www.foo.com/public") // nolint
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
			_, err := p.NetworkRequest(ctx, r)
			So(err, ShouldNotBeNil)

			authErr, ok := err.(*AuthError)
			So(ok, ShouldBeTrue)
			So(authErr.Status(), ShouldEqual, http.StatusInternalServerError)
		})

		Convey("Requests a valid context with a drop network policy must be rejected", func() {
			u, _ := url.Parse("http://www.foo.com/public") // nolint
			r := &Request{
				SourceAddress: &net.TCPAddr{
					IP:   net.ParseIP("100.1.1.1"),
					Port: 1000,
				},
				OriginalDestination: &net.TCPAddr{
					IP:   net.ParseIP("10.1.1.1"),
					Port: 80,
				},
				Method:     "GET",
				URL:        u,
				RequestURI: "/public",
				Header:     http.Header{},
				Cookie:     nil,
				TLS:        nil,
			}
			response, err := p.NetworkRequest(ctx, r)
			So(err, ShouldNotBeNil)
			So(response, ShouldNotBeNil)

			authErr, ok := err.(*AuthError)
			So(ok, ShouldBeTrue)
			So(authErr.Status(), ShouldEqual, http.StatusNetworkAuthenticationRequired)
			So(response.NetworkPolicyID, ShouldEqual, rejectPolicyID)
			So(response.NetworkServiceID, ShouldEqual, rejectServiceID)
			So(response.DropReason, ShouldEqual, collector.PolicyDrop)
			So(response.SourceType, ShouldEqual, collector.EndPointTypeExternalIP)
		})

		Convey("Requests a valid context with an invalid token, I should get forbidden", func() {
			u, _ := url.Parse("http://www.foo.com/public") // nolint
			h := http.Header{}
			h.Add("X-APORETO-AUTH", "badvalue")
			h.Add("X-APORETO-KEY", "badvalue")

			r := &Request{
				SourceAddress: &net.TCPAddr{
					IP:   net.ParseIP("45.1.1.1"),
					Port: 1000,
				},
				OriginalDestination: &net.TCPAddr{
					IP:   net.ParseIP("10.1.1.1"),
					Port: 80,
				},
				Method:     "GET",
				URL:        u,
				RequestURI: "/public",
				Header:     h,
				Cookie:     nil,
				TLS:        nil,
			}
			response, err := p.NetworkRequest(ctx, r)
			So(err, ShouldNotBeNil)
			So(response, ShouldNotBeNil)

			authErr, ok := err.(*AuthError)
			So(ok, ShouldBeTrue)
			So(authErr.Status(), ShouldEqual, http.StatusForbidden)
			So(authErr.Message(), ShouldContainSubstring, "Invalid Authorization Token:")
			So(response.NetworkPolicyID, ShouldEqual, policyID)
			So(response.NetworkServiceID, ShouldEqual, serviceID)
			So(response.DropReason, ShouldEqual, collector.PolicyDrop)
			So(response.SourceType, ShouldEqual, collector.EndPointTypeExternalIP)
		})

		Convey("Requests a valid context with a valid Aporeto token to a public URL from a valid network it should succeed", func() {
			u, _ := url.Parse("http://www.foo.com/public") // nolint
			token, err := servicetokens.CreateAndSign(
				"somenode",
				pctx.Identity().Tags,
				pctx.Scopes(),
				pctx.ManagementID(),
				defaultValidity,
				s.EncodingKey(),
			)
			So(err, ShouldBeNil)

			h := http.Header{}
			h.Add("X-APORETO-AUTH", token)
			h.Add("X-APORETO-KEY", string(s.TransmittedKey()))

			r := &Request{
				SourceAddress: &net.TCPAddr{
					IP:   net.ParseIP("45.1.1.1"),
					Port: 1000,
				},
				OriginalDestination: &net.TCPAddr{
					IP:   net.ParseIP("10.1.1.1"),
					Port: 80,
				},
				Method:     "GET",
				URL:        u,
				RequestURI: "/public",
				Header:     h,
				Cookie:     nil,
				TLS:        nil,
			}
			response, err := p.NetworkRequest(ctx, r)
			So(err, ShouldBeNil)
			So(response.NetworkPolicyID, ShouldEqual, policyID)
			So(response.NetworkServiceID, ShouldEqual, serviceID)
			So(response.SourceType, ShouldEqual, collector.EnpointTypePU)
		})

		Convey("Requests a valid context with a valid Aporeto token based on PU network policy it should succeed", func() {
			u, _ := url.Parse("http://www.foo.com/public") // nolint
			token, err := servicetokens.CreateAndSign(
				"somenode",
				pctx.Identity().Tags,
				pctx.Scopes(),
				pctx.ManagementID(),
				defaultValidity,
				s.EncodingKey(),
			)
			So(err, ShouldBeNil)

			h := http.Header{}
			h.Add("X-APORETO-AUTH", token)
			h.Add("X-APORETO-KEY", string(s.TransmittedKey()))

			r := &Request{
				SourceAddress: &net.TCPAddr{
					IP:   net.ParseIP("60.1.1.1"),
					Port: 1000,
				},
				OriginalDestination: &net.TCPAddr{
					IP:   net.ParseIP("10.1.1.1"),
					Port: 80,
				},
				Method:     "GET",
				URL:        u,
				RequestURI: "/public",
				Header:     h,
				Cookie:     nil,
				TLS:        nil,
			}
			response, err := p.NetworkRequest(ctx, r)
			So(err, ShouldBeNil)
			So(response.NetworkPolicyID, ShouldEqual, "pu"+policyID)
			So(response.SourceType, ShouldEqual, collector.EnpointTypePU)
		})

		Convey("Requests a valid context with no Aporeto claims and no network policy, it should be dropped", func() {
			u, _ := url.Parse("http://www.foo.com/public") // nolint

			r := &Request{
				SourceAddress: &net.TCPAddr{
					IP:   net.ParseIP("60.1.1.1"),
					Port: 1000,
				},
				OriginalDestination: &net.TCPAddr{
					IP:   net.ParseIP("10.1.1.1"),
					Port: 80,
				},
				Method:     "GET",
				URL:        u,
				RequestURI: "/public",
				Header:     http.Header{},
				Cookie:     nil,
				TLS:        nil,
			}
			response, err := p.NetworkRequest(ctx, r)
			So(err, ShouldNotBeNil)
			authErr, ok := err.(*AuthError)
			So(ok, ShouldBeTrue)
			So(authErr.Status(), ShouldEqual, http.StatusNetworkAuthenticationRequired)
			So(response.NetworkPolicyID, ShouldEqual, collector.DefaultEndPoint)
			So(response.SourceType, ShouldEqual, collector.EndPointTypeExternalIP)
		})

		Convey("Requests a valid context with a valid Aporeto token but network reject, it should be rejected", func() {
			u, _ := url.Parse("http://www.foo.com/public") // nolint
			badTags := append(pctx.Identity().Tags, "app=bad")
			token, err := servicetokens.CreateAndSign(
				"badnode",
				badTags,
				pctx.Scopes(),
				"badnodeID",
				defaultValidity,
				s.EncodingKey(),
			)
			So(err, ShouldBeNil)

			h := http.Header{}
			h.Add("X-APORETO-AUTH", token)
			h.Add("X-APORETO-KEY", string(s.TransmittedKey()))

			r := &Request{
				SourceAddress: &net.TCPAddr{
					IP:   net.ParseIP("60.1.1.1"),
					Port: 1000,
				},
				OriginalDestination: &net.TCPAddr{
					IP:   net.ParseIP("10.1.1.1"),
					Port: 80,
				},
				Method:     "GET",
				URL:        u,
				RequestURI: "/public",
				Header:     h,
				Cookie:     nil,
				TLS:        nil,
			}
			response, err := p.NetworkRequest(ctx, r)
			So(err, ShouldNotBeNil)
			So(response.NetworkPolicyID, ShouldEqual, "reject"+policyID)
			So(response.SourceType, ShouldEqual, collector.EnpointTypePU)
		})

		Convey("Requests a valid context with a valid Aporeto token to a private URL it should succeed", func() {
			u, _ := url.Parse("http://www.foo.com/admin") // nolint
			token, err := servicetokens.CreateAndSign(
				"somenode",
				pctx.Identity().Tags,
				pctx.Scopes(),
				pctx.ManagementID(),
				defaultValidity,
				s.EncodingKey(),
			)
			So(err, ShouldBeNil)

			h := http.Header{}
			h.Add("X-APORETO-AUTH", token)
			h.Add("X-APORETO-KEY", string(s.TransmittedKey()))

			r := &Request{
				SourceAddress: &net.TCPAddr{
					IP:   net.ParseIP("45.1.1.1"),
					Port: 1000,
				},
				OriginalDestination: &net.TCPAddr{
					IP:   net.ParseIP("10.1.1.1"),
					Port: 80,
				},
				Method:     "GET",
				URL:        u,
				RequestURI: "/admin",
				Header:     h,
				Cookie:     nil,
				TLS:        nil,
			}
			response, err := p.NetworkRequest(ctx, r)
			So(err, ShouldBeNil)
			So(response.NetworkPolicyID, ShouldEqual, policyID)
			So(response.NetworkServiceID, ShouldEqual, serviceID)
			So(response.SourceType, ShouldEqual, collector.EnpointTypePU)
		})

		Convey("Requests a valid context with a valid Aporeto token to a forbidden URL it should return error", func() {
			u, _ := url.Parse("http://www.foo.com/forbidden") // nolint
			token, err := servicetokens.CreateAndSign(
				"somenode",
				pctx.Identity().Tags,
				pctx.Scopes(),
				"forbiddennode",
				defaultValidity,
				s.EncodingKey(),
			)
			So(err, ShouldBeNil)

			h := http.Header{}
			h.Add("X-APORETO-AUTH", token)
			h.Add("X-APORETO-KEY", string(s.TransmittedKey()))

			r := &Request{
				SourceAddress: &net.TCPAddr{
					IP:   net.ParseIP("45.1.1.1"),
					Port: 1000,
				},
				OriginalDestination: &net.TCPAddr{
					IP:   net.ParseIP("10.1.1.1"),
					Port: 80,
				},
				Method:     "GET",
				URL:        u,
				RequestURI: "/forbidden",
				Header:     h,
				Cookie:     nil,
				TLS:        nil,
			}
			response, err := p.NetworkRequest(ctx, r)
			So(err, ShouldNotBeNil)
			authError, ok := err.(*AuthError)
			So(ok, ShouldBeTrue)
			So(authError.Status(), ShouldEqual, http.StatusUnauthorized)
			So(response.NetworkPolicyID, ShouldEqual, policyID)
			So(response.NetworkServiceID, ShouldEqual, serviceID)
			So(response.SourceType, ShouldEqual, collector.EnpointTypePU)
		})
	})
}

func Test_UserCredentials(t *testing.T) {

	Convey("Given a valid authorizer", t, func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ctrl := gomock.NewController(t)
		serviceRegistry, _, s := newAPIAuthProcessor(ctrl)
		p := New("test", serviceRegistry, s)
		So(p, ShouldNotBeNil)

		portContext, err := serviceRegistry.RetrieveExposedServiceContext(net.ParseIP("10.1.1.1"), 80, "")
		So(err, ShouldBeNil)
		So(portContext, ShouldNotBeNil)

		verifier, ok := portContext.Service.UserAuthorizationHandler.(*mockusertokens.MockVerifier)
		So(ok, ShouldBeTrue)

		Convey("When the request is not TLS, there is no user data", func() {
			u, _ := url.Parse("http://www.foo.com/admin")
			d := &NetworkAuthResponse{}
			r := &Request{
				SourceAddress: &net.TCPAddr{
					IP:   net.ParseIP("45.1.1.1"),
					Port: 1000,
				},
				OriginalDestination: &net.TCPAddr{
					IP:   net.ParseIP("10.1.1.1"),
					Port: 80,
				},
				Method:     "GET",
				URL:        u,
				RequestURI: "/admin",
				Header:     http.Header{},
				Cookie:     nil,
				TLS:        nil,
			}
			userCredentials(ctx, portContext, r, d)
			So(len(d.UserAttributes), ShouldEqual, 0)
		})

		Convey("When the request is TLS and a user is identified, the claims are correct", func() {
			u, _ := url.Parse("http://www.foo.com/admin")
			d := &NetworkAuthResponse{}

			r := &Request{
				SourceAddress: &net.TCPAddr{
					IP:   net.ParseIP("45.1.1.1"),
					Port: 1000,
				},
				OriginalDestination: &net.TCPAddr{
					IP:   net.ParseIP("10.1.1.1"),
					Port: 80,
				},
				Method:     "GET",
				URL:        u,
				RequestURI: "/admin",
				Header:     http.Header{},
				Cookie:     nil,
				TLS:        &tls.ConnectionState{},
			}
			verifier.EXPECT().Validate(ctx, gomock.Any()).Return([]string{"user=flash"}, false, "", nil)
			userCredentials(ctx, portContext, r, d)
			So(len(d.UserAttributes), ShouldEqual, 1)
			So(d.UserAttributes[0], ShouldEqual, "user=flash")
			So(d.SourceType, ShouldEqual, collector.EndpointTypeClaims)
			So(d.Redirect, ShouldBeFalse)
		})

		Convey("When the request is TLS and user authorization fails with a redirect, the redirect should be set", func() {
			u, _ := url.Parse("http://www.foo.com/admin")
			d := &NetworkAuthResponse{}

			h := http.Header{}
			h.Add("Authorization", "Bearer MockJWTToken")
			r := &Request{
				SourceAddress: &net.TCPAddr{
					IP:   net.ParseIP("45.1.1.1"),
					Port: 1000,
				},
				OriginalDestination: &net.TCPAddr{
					IP:   net.ParseIP("10.1.1.1"),
					Port: 80,
				},
				Method:     "GET",
				URL:        u,
				RequestURI: "/admin",
				Header:     http.Header{},
				Cookie:     nil,
				TLS:        &tls.ConnectionState{},
			}
			verifier.EXPECT().Validate(ctx, gomock.Any()).Return(nil, true, "MockJWTToken", fmt.Errorf("auth failed"))
			userCredentials(ctx, portContext, r, d)
			So(len(d.UserAttributes), ShouldEqual, 0)
			So(d.Redirect, ShouldBeTrue)
		})

		Convey("When the request is TLS and user authorization succeeds with a refresh token, the cookie must be set", func() {
			u, _ := url.Parse("http://www.foo.com/admin")
			d := &NetworkAuthResponse{}

			h := http.Header{}
			h.Add("Authorization", "Bearer MockJWTToken")
			r := &Request{
				SourceAddress: &net.TCPAddr{
					IP:   net.ParseIP("45.1.1.1"),
					Port: 1000,
				},
				OriginalDestination: &net.TCPAddr{
					IP:   net.ParseIP("10.1.1.1"),
					Port: 80,
				},
				Method:     "GET",
				URL:        u,
				RequestURI: "/admin",
				Header:     http.Header{},
				Cookie:     nil,
				TLS:        &tls.ConnectionState{},
			}
			verifier.EXPECT().Validate(ctx, gomock.Any()).Return(nil, true, "NewToken", fmt.Errorf("auth failed"))
			userCredentials(ctx, portContext, r, d)
			So(len(d.UserAttributes), ShouldEqual, 0)
			So(d.Redirect, ShouldBeTrue)
			So(d.Cookie, ShouldNotBeNil)
			So(d.Cookie.Name, ShouldEqual, "X-APORETO-AUTH")
			So(d.Cookie.Value, ShouldEqual, "NewToken")
			So(d.Cookie.HttpOnly, ShouldBeTrue)
			So(d.Cookie.Secure, ShouldBeTrue)
			So(d.Cookie.Path, ShouldEqual, "/")
		})
	})
}
