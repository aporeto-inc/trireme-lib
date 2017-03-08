package supervisor

import (
	"fmt"
	"testing"

	"github.com/aporeto-inc/mock/gomock"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/enforcer/utils/tokens"
	"github.com/aporeto-inc/trireme/policy"
	mock_supervisor "github.com/aporeto-inc/trireme/supervisor/mock"

	. "github.com/smartystreets/goconvey/convey"
)

func createPUInfo() *policy.PUInfo {

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

	ips := policy.NewIPMap(map[string]string{
		policy.DefaultNamespace: "172.17.0.1",
	})

	runtime := policy.NewPURuntimeWithDefaults()
	runtime.SetIPAddresses(ips)
	plc := policy.NewPUPolicy("context", policy.Police, rules, rules, nil, nil, nil, nil, ips, nil)

	return policy.PUInfoFromPolicyAndRuntime("context", plc, runtime)

}

func TestNewSupervisor(t *testing.T) {
	Convey("When I try to instantiate a new supervisor ", t, func() {

		c := &collector.DefaultCollector{}
		secrets := tokens.NewPSKSecrets([]byte("test password"))
		e := enforcer.NewDefaultDatapathEnforcer("serverID", c, nil, secrets, constants.LocalContainer)
		targetNets := []string{"172.17.0.0/24"}
		mode := constants.LocalContainer
		implementation := constants.IPTables

		Convey("When I provide correct parameters", func() {
			s, err := NewSupervisor(c, e, targetNets, mode, implementation)
			Convey("I should not get an error ", func() {
				So(err, ShouldBeNil)
				So(s, ShouldNotBeNil)
				So(s.collector, ShouldEqual, c)
				So(s.mode, ShouldEqual, constants.IPTables)
			})
		})

		Convey("When I provide a nil  collector", func() {
			s, err := NewSupervisor(nil, e, targetNets, mode, implementation)
			Convey("I should get an error ", func() {
				So(err, ShouldNotBeNil)
				So(s, ShouldBeNil)
			})
		})

		Convey("When I provide a nil enforcer", func() {
			s, err := NewSupervisor(c, nil, targetNets, mode, implementation)
			Convey("I should get an error ", func() {
				So(err, ShouldNotBeNil)
				So(s, ShouldBeNil)
			})
		})

		Convey("When I provide a target networks ", func() {
			s, err := NewSupervisor(c, e, nil, mode, implementation)
			Convey("I should get an error ", func() {
				So(err, ShouldNotBeNil)
				So(s, ShouldBeNil)
			})
		})
	})
}

func TestSupervise(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("Given a valid supervisor", t, func() {
		c := &collector.DefaultCollector{}
		secrets := tokens.NewPSKSecrets([]byte("test password"))
		e := enforcer.NewDefaultDatapathEnforcer("serverID", c, nil, secrets, constants.LocalContainer)

		s, _ := NewSupervisor(c, e, []string{"172.17.0.0/24"}, constants.LocalContainer, constants.IPTables)
		impl := mock_supervisor.NewMockImplementor(ctrl)
		s.impl = impl

		Convey("When I supervise a new PU with invalid policy", func() {
			err := s.Supervise("contextID", nil)
			Convey("I should get an error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		puInfo := createPUInfo()

		Convey("When I supervise a new PU with valid policy", func() {
			impl.EXPECT().ConfigureRules(0, "contextID", puInfo).Return(nil)
			err := s.Supervise("contextID", puInfo)
			Convey("I should not get an error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I supervise a new PU with valid policy, but there is an error", func() {
			impl.EXPECT().ConfigureRules(0, "errorPU", puInfo).Return(fmt.Errorf("Error"))
			impl.EXPECT().DeleteRules(0, "errorPU", gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			err := s.Supervise("errorPU", puInfo)
			Convey("I should  get an error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I send supervise command for a second time, it should do an update", func() {
			impl.EXPECT().ConfigureRules(0, "contextID", puInfo).Return(nil)
			impl.EXPECT().UpdateRules(1, "contextID", gomock.Any()).Return(nil)
			s.Supervise("contextID", puInfo)
			err := s.Supervise("contextID", puInfo)
			Convey("I should not get an error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I send supervise command for a second time, and the update fails", func() {
			impl.EXPECT().ConfigureRules(0, "contextID", puInfo).Return(nil)
			impl.EXPECT().UpdateRules(1, "contextID", gomock.Any()).Return(fmt.Errorf("Error"))
			impl.EXPECT().DeleteRules(1, "contextID", gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			s.Supervise("contextID", puInfo)
			err := s.Supervise("contextID", puInfo)
			Convey("I should get an error", func() {
				So(err, ShouldNotBeNil)
			})
		})

	})
}

func TestUnsupervise(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("Given a properly configured supervisor", t, func() {
		c := &collector.DefaultCollector{}
		secrets := tokens.NewPSKSecrets([]byte("test password"))
		e := enforcer.NewDefaultDatapathEnforcer("serverID", c, nil, secrets, constants.LocalContainer)

		s, _ := NewSupervisor(c, e, []string{"172.17.0.0/24"}, constants.LocalContainer, constants.IPTables)
		impl := mock_supervisor.NewMockImplementor(ctrl)
		s.impl = impl

		Convey("When I try to unsupervise a PU that was not see before", func() {
			err := s.Unsupervise("badContext")
			Convey("I should get an error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		puInfo := createPUInfo()

		Convey("When I try to unsupervise a valid PU ", func() {
			impl.EXPECT().ConfigureRules(0, "contextID", puInfo).Return(nil)
			impl.EXPECT().DeleteRules(0, "contextID", gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			s.Supervise("contextID", puInfo)
			err := s.Unsupervise("contextID")
			Convey("I should get no errors", func() {
				So(err, ShouldBeNil)
			})
		})
	})
}

func TestStart(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("Given a properly configured supervisor", t, func() {
		c := &collector.DefaultCollector{}
		secrets := tokens.NewPSKSecrets([]byte("test password"))
		e := enforcer.NewDefaultDatapathEnforcer("serverID", c, nil, secrets, constants.LocalContainer)

		s, _ := NewSupervisor(c, e, []string{"172.17.0.0/24"}, constants.LocalContainer, constants.IPTables)
		impl := mock_supervisor.NewMockImplementor(ctrl)
		s.impl = impl

		Convey("When I try to start it and the implementor works", func() {
			impl.EXPECT().Start().Return(nil)
			err := s.Start()
			Convey("I should get no errors", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I try to start it and the implementor returns an error", func() {
			impl.EXPECT().Start().Return(fmt.Errorf("Error"))
			err := s.Start()
			Convey("I should get an error ", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})
}
