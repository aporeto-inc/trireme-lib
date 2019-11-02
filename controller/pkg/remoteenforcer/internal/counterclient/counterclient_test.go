package counterclient

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/v11/collector"
	"go.aporeto.io/trireme-lib/v11/controller/constants"
	"go.aporeto.io/trireme-lib/v11/controller/internal/enforcer/utils/rpcwrapper"
	"go.aporeto.io/trireme-lib/v11/controller/internal/enforcer/utils/rpcwrapper/mockrpcwrapper"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/remoteenforcer/internal/statscollector"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/remoteenforcer/internal/statscollector/mockstatscollector"
)

func TestNewCounterClient(t *testing.T) {
	Convey("Given i call newcounterclient", t, func() {
		Convey("The channel path is not set in the environment", func() {
			client, err := NewCounterClient(statscollector.NewCollector())
			So(err, ShouldNotBeNil)
			So(client, ShouldBeNil)
		})
		Convey("The channel path is set in the environment and secret is not ", func() {
			os.Setenv(constants.EnvStatsChannel, "/tmp/a") // nolint
			client, err := NewCounterClient(statscollector.NewCollector())
			So(err, ShouldNotBeNil)
			So(client, ShouldBeNil)
		})
		Convey("The required environment variables are available ", func() {
			os.Setenv(constants.EnvStatsChannel, "/tmp/a")  // nolint
			os.Setenv(constants.EnvStatsSecret, "adrehgfh") // nolint
			client, err := NewCounterClient(statscollector.NewCollector())
			So(err, ShouldBeNil)
			So(client, ShouldNotBeNil)
		})
	})
}

func TestSendData(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	Convey("Given i call sendData", t, func() {
		os.Setenv(constants.EnvStatsChannel, "/tmp/a")  // nolint
		os.Setenv(constants.EnvStatsSecret, "adrehgfh") // nolint
		client, err := NewCounterClient(statscollector.NewCollector())
		So(err, ShouldBeNil)
		mockrpchdl := mockrpcwrapper.NewMockRPCClient(ctrl)
		client.(*counterClient).rpchdl = mockrpchdl
		records := []*collector.CounterReport{}
		request := rpcwrapper.Request{
			Payload: &rpcwrapper.CounterReportPayload{
				CounterReports: records,
			},
		}
		mockrpchdl.EXPECT().RemoteCall(counterContextID, counterRPCCommand, &request, gomock.Any()).Return(nil).Times(1)
		err = client.(*counterClient).sendData(records)
		So(err, ShouldBeNil)
	})
}

func TestSendCounterReports(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	Convey("Given i call sendCounterReport", t, func() {
		Convey("Given i call with a single record", func() {

			os.Setenv(constants.EnvStatsChannel, "/tmp/a")  // nolint
			os.Setenv(constants.EnvStatsSecret, "adrehgfh") // nolint
			mockCollector := mockstatscollector.NewMockCollector(ctrl)
			client, err := NewCounterClient(mockCollector)
			mockrpchdl := mockrpcwrapper.NewMockRPCClient(ctrl)
			client.(*counterClient).rpchdl = mockrpchdl
			client.(*counterClient).counterInterval = 2 * time.Second
			So(err, ShouldBeNil)
			So(client, ShouldNotBeNil)
			mockCollector.EXPECT().GetAllCounterReports().Return([]*collector.CounterReport{
				{
					Namespace: "/ns1",
					ContextID: "contextID1",
					Counters: []collector.Counters{
						{
							Name:  "SYNNOTSEEN",
							Value: 1,
						},
					},
				},
			}).Times(1)
			mockrpchdl.EXPECT().RemoteCall(counterContextID, counterRPCCommand, gomock.Any(), gomock.Any()).Return(nil).Times(1)
			ctx, cancel := context.WithCancel(context.Background())
			go client.(*counterClient).sendCounterReports(ctx)
			<-time.After(1 * time.Second)
			cancel()
			<-time.After(1 * time.Second)
		})
	})
}
