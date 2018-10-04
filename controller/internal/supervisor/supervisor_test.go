package supervisor

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/nfqdatapath"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/nfqdatapath/afinetrawsocket"
	"go.aporeto.io/trireme-lib/controller/internal/supervisor/mocksupervisor"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/policy"

	. "github.com/smartystreets/goconvey/convey"
)

func createPUInfo() *policy.PUInfo {

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

	ips := policy.ExtendedMap{
		policy.DefaultNamespace: "172.17.0.1",
	}

	runtime := policy.NewPURuntimeWithDefaults()
	runtime.SetIPAddresses(ips)
	plc := policy.NewPUPolicy(
		"context",
		policy.Police,
		rules,
		rules,
		nil,
		nil,
		nil,
		nil,
		nil,
		ips,
		[]string{"172.17.0.0/24"},
		[]string{},
		[]string{},
		nil,
		nil,
		[]string{},
	)

	return policy.PUInfoFromPolicyAndRuntime("context", plc, runtime)

}

func TestNewSupervisor(t *testing.T) {
	Convey("When I try to instantiate a new supervisor ", t, func() {

		c := &collector.DefaultCollector{}
		secrets := secrets.NewPSKSecrets([]byte("test password"))

		prevRawSocket := nfqdatapath.GetUDPRawSocket
		defer func() {
			nfqdatapath.GetUDPRawSocket = prevRawSocket
		}()
		nfqdatapath.GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
			return nil, nil
		}

		e := enforcer.NewWithDefaults("serverID", c, nil, secrets, constants.LocalServer, "/proc", []string{"0.0.0.0/0"})
		mode := constants.LocalServer

		Convey("When I provide correct parameters", func() {
			s, err := NewSupervisor(c, e, mode, []string{}, nil)
			Convey("I should not get an error ", func() {
				So(err, ShouldBeNil)
				So(s, ShouldNotBeNil)
				So(s.collector, ShouldEqual, c)
			})
		})

		Convey("When I provide a nil  collector", func() {
			s, err := NewSupervisor(nil, e, mode, []string{}, nil)
			Convey("I should get an error ", func() {
				So(err, ShouldNotBeNil)
				So(s, ShouldBeNil)
			})
		})

		Convey("When I provide a nil enforcer", func() {
			s, err := NewSupervisor(c, nil, mode, []string{}, nil)
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
		scrts := secrets.NewPSKSecrets([]byte("test password"))

		prevRawSocket := nfqdatapath.GetUDPRawSocket
		defer func() {
			nfqdatapath.GetUDPRawSocket = prevRawSocket
		}()
		nfqdatapath.GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
			return nil, nil
		}
		e := enforcer.NewWithDefaults("serverID", c, nil, scrts, constants.RemoteContainer, "/proc", []string{"0.0.0.0/0"})

		s, _ := NewSupervisor(c, e, constants.RemoteContainer, []string{}, nil)
		So(s, ShouldNotBeNil)

		impl := mocksupervisor.NewMockImplementor(ctrl)
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
			impl.EXPECT().ConfigureRules(0, "errorPU", puInfo).Return(errors.New("error"))
			impl.EXPECT().DeleteRules(0, "errorPU", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			err := s.Supervise("errorPU", puInfo)
			Convey("I should  get an error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I send supervise command for a second time, it should do an update", func() {
			impl.EXPECT().ConfigureRules(0, "contextID", puInfo).Return(nil)
			impl.EXPECT().UpdateRules(1, "contextID", gomock.Any(), gomock.Any()).Return(nil)
			noerr := s.Supervise("contextID", puInfo)
			So(noerr, ShouldBeNil)
			err := s.Supervise("contextID", puInfo)
			Convey("I should not get an error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I send supervise command for a second time, and the update fails", func() {
			impl.EXPECT().ConfigureRules(0, "contextID", puInfo).Return(nil)
			impl.EXPECT().UpdateRules(1, "contextID", gomock.Any(), gomock.Any()).Return(errors.New("error"))
			impl.EXPECT().DeleteRules(1, "contextID", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			serr := s.Supervise("contextID", puInfo)
			So(serr, ShouldBeNil)
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

	Convey("Given a properly configured  supervisor", t, func() {
		c := &collector.DefaultCollector{}
		scrts := secrets.NewPSKSecrets([]byte("test password"))

		prevRawSocket := nfqdatapath.GetUDPRawSocket
		defer func() {
			nfqdatapath.GetUDPRawSocket = prevRawSocket
		}()
		nfqdatapath.GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
			return nil, nil
		}

		e := enforcer.NewWithDefaults("serverID", c, nil, scrts, constants.RemoteContainer, "/proc", []string{"0.0.0.0/0"})

		s, _ := NewSupervisor(c, e, constants.RemoteContainer, []string{"172.17.0.0/16"}, nil)
		So(s, ShouldNotBeNil)

		impl := mocksupervisor.NewMockImplementor(ctrl)
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
			impl.EXPECT().DeleteRules(0, "contextID", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			serr := s.Supervise("contextID", puInfo)
			So(serr, ShouldBeNil)
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
		scrts := secrets.NewPSKSecrets([]byte("test password"))

		prevRawSocket := nfqdatapath.GetUDPRawSocket
		defer func() {
			nfqdatapath.GetUDPRawSocket = prevRawSocket
		}()
		nfqdatapath.GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
			return nil, nil
		}

		e := enforcer.NewWithDefaults("serverID", c, nil, scrts, constants.RemoteContainer, "/proc", []string{"0.0.0.0/0"})

		s, _ := NewSupervisor(c, e, constants.RemoteContainer, []string{"172.17.0.0/16"}, nil)
		So(s, ShouldNotBeNil)

		impl := mocksupervisor.NewMockImplementor(ctrl)
		s.impl = impl

		Convey("When I try to start it and the implementor works", func() {
			impl.EXPECT().Run(gomock.Any()).Return(nil)
			impl.EXPECT().SetTargetNetworks([]string{}, []string{"172.17.0.0/16"}).Return(nil)
			err := s.Run(context.Background())
			Convey("I should get no errors", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I try to start it and the implementor returns an error", func() {
			impl.EXPECT().Run(gomock.Any()).Return(errors.New("error"))
			err := s.Run(context.Background())
			Convey("I should get an error ", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})
}

func TestStop(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("Given a properly configured supervisor", t, func() {
		c := &collector.DefaultCollector{}
		scrts := secrets.NewPSKSecrets([]byte("test password"))

		prevRawSocket := nfqdatapath.GetUDPRawSocket
		defer func() {
			nfqdatapath.GetUDPRawSocket = prevRawSocket
		}()
		nfqdatapath.GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
			return nil, nil
		}

		e := enforcer.NewWithDefaults("serverID", c, nil, scrts, constants.RemoteContainer, "/proc", []string{"0.0.0.0/0"})

		s, _ := NewSupervisor(c, e, constants.RemoteContainer, []string{"172.17.0.0/16"}, nil)
		So(s, ShouldNotBeNil)

		impl := mocksupervisor.NewMockImplementor(ctrl)
		s.impl = impl

		Convey("When I try to start it and the implementor works", func() {
			impl.EXPECT().Run(gomock.Any()).Return(nil)
			impl.EXPECT().SetTargetNetworks([]string{}, []string{"172.17.0.0/16"}).Return(nil)
			err := s.Run(context.Background())
			Convey("I should get no errors", func() {
				So(err, ShouldBeNil)
			})
		})
	})
}
