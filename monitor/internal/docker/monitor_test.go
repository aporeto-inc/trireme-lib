package dockermonitor

import (
	"context"
	"errors"
	"os"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/collector"
	tevents "go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/monitor/config"
	"go.aporeto.io/trireme-lib/monitor/constants"
	"go.aporeto.io/trireme-lib/monitor/extractors"
	"go.aporeto.io/trireme-lib/monitor/internal/docker/mockdocker"
	"go.aporeto.io/trireme-lib/policy/mockpolicy"
	"go.aporeto.io/trireme-lib/utils/cgnetcls/mockcgnetcls"
)

var (
	testDockerMetadataExtractor extractors.DockerMetadataExtractor
	ID                          string
)

func init() {
	ID = "74cc486f9ec3256d7bee789853ce05510167c7daf893f90a7577cdcba259d063"
}

func eventCollector() collector.EventCollector {
	newEvent := &collector.DefaultCollector{}
	return newEvent
}

func initTestDockerInfo(id string, nwmode container.NetworkMode, state bool) *types.ContainerJSON {
	var testInfoBase types.ContainerJSON
	var testInfo types.ContainerJSONBase
	var testConfig container.Config
	var testNetwork types.NetworkSettings
	var testDefaultNW types.DefaultNetworkSettings
	var testContainer types.ContainerState
	var testHostConfig container.HostConfig

	m := make(map[string]string)
	m["role"] = "client"
	m["vendor"] = "CentOS"
	m["$id"] = "598a35a60f79af0001b52ef5"
	m["$namespace"] = "/sibicentos"
	m["build-date"] = "20170801"
	m["license"] = "GPLv2"
	m["name"] = "CentOS Base Image"

	testDefaultNW.IPAddress = "172.17.0.2"

	testNetwork.DefaultNetworkSettings = testDefaultNW

	testConfig.Image = "centos"
	testConfig.Labels = m

	testInfo.Name = "/priceless_rosalind"
	testInfo.State = &testContainer
	testInfo.HostConfig = &testHostConfig

	testContainer.Pid = 4912
	testContainer.Running = state

	testHostConfig.NetworkMode = nwmode

	testInfoBase.NetworkSettings = &testNetwork
	testInfoBase.ContainerJSONBase = &testInfo
	testInfoBase.Config = &testConfig
	testInfoBase.ID = id
	testInfoBase.Config.Labels["storedTags"] = "$id=5a3b4e903653d4000133254f,$namespace=/test"

	return &testInfoBase
}

func initTestMessage(id string) *events.Message {
	var testMessage events.Message

	testMessage.ID = id

	return &testMessage
}

func defaultContainer(host bool) types.ContainerJSON {

	networkMode := "bridge"
	if host {
		networkMode = "host"
	}
	c := types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID: ID,
			State: &types.ContainerState{
				Running: true,
				Paused:  false,
			},
			HostConfig: &container.HostConfig{
				NetworkMode: container.NetworkMode(networkMode),
			},
		},
		Mounts: nil,
		Config: &container.Config{
			Labels: map[string]string{"app": "web"},
		},
		NetworkSettings: &types.NetworkSettings{
			DefaultNetworkSettings: types.DefaultNetworkSettings{
				IPAddress: "172.17.0.1",
			},
		},
	}

	return c
}

func TestNewDockerMonitor(t *testing.T) {

	Convey("When I try to initialize a new docker monitor", t, func() {
		dm := New()
		err := dm.SetupConfig(nil, &Config{
			EventMetadataExtractor: testDockerMetadataExtractor,
		})
		So(err, ShouldBeNil)

		Convey("Then docker monitor should not be nil", func() {
			So(dm, ShouldNotBeNil)
		})
	})
}

func TestInitDockerClient(t *testing.T) {

	Convey("When I try to initialize a new docker client as unix", t, func() {
		dc, err := initDockerClient(constants.DefaultDockerSocketType, constants.DefaultDockerSocket)

		Convey("Then docker client should not be nil", func() {
			So(dc, ShouldNotBeNil)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I try to initialize a new docker client as tcp", t, func() {
		dc, err := initDockerClient("tcp", constants.DefaultDockerSocket)

		Convey("Then docker client should not be nil", func() {
			So(dc, ShouldNotBeNil)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I try to initialize a new docker client with some random type", t, func() {
		dc, err := initDockerClient("wrongtype", constants.DefaultDockerSocket)

		Convey("Then docker client should be nil and I should get error", func() {
			So(dc, ShouldBeNil)
			So(err, ShouldResemble, errors.New("bad socket type: wrongtype"))
		})
	})

	Convey("When I try to initialize a new docker client with some random path", t, func() {
		dc, err := initDockerClient(constants.DefaultDockerSocketType, "/var/random.sock")

		Convey("Then docker client should be nil and I should get error", func() {
			So(dc, ShouldBeNil)
			So(err, ShouldResemble, &os.PathError{Op: "stat", Path: "/var/random.sock", Err: syscall.Errno(2)})
		})
	})
}

func TestContextIDFromDockerID(t *testing.T) {
	Convey("When I try to retrieve contextID from dockerID", t, func() {
		cID, err := puIDFromDockerID(ID)
		cID1 := "74cc486f9ec3"

		Convey("Then contextID should match and I should not get any error", func() {
			So(cID, ShouldEqual, cID1)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I try to retrieve contextID when dockerID length less than 12", t, func() {
		cID, err := puIDFromDockerID("6f47830f64")

		Convey("Then I should get error", func() {
			So(cID, ShouldEqual, "")
			So(err, ShouldResemble, errors.New("unable to generate context id: dockerid smaller than 12 characters: 6f47830f64"))
		})
	})

	Convey("When I try to retrieve contextID when no dockerID given", t, func() {
		cID, err := puIDFromDockerID("")

		Convey("Then I should get error", func() {
			So(cID, ShouldEqual, "")
			So(err, ShouldResemble, errors.New("unable to generate context id: empty docker id"))
		})
	})
}

func TestDefaultDockerMetadataExtractor(t *testing.T) {
	Convey("When I try to extract metadata from default docker container", t, func() {
		puR, err := extractors.DefaultMetadataExtractor(initTestDockerInfo(ID, "default", false))

		Convey("Then I should not get any error", func() {
			So(puR, ShouldNotBeNil)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I try to extract metadata from host docker container", t, func() {
		puR, err := extractors.DefaultMetadataExtractor(initTestDockerInfo(ID, "host", false))

		Convey("Then I should not get any error", func() {
			So(puR, ShouldNotBeNil)
			So(err, ShouldBeNil)
		})
	})
}

func setupDockerMonitor(ctrl *gomock.Controller) (*DockerMonitor, *mockpolicy.MockResolver) {

	dm := New()
	mockPolicy := mockpolicy.NewMockResolver(ctrl)

	dm.SetupHandlers(&config.ProcessorConfig{
		Collector: eventCollector(),
		Policy:    mockPolicy,
	})
	err := dm.SetupConfig(nil, &Config{
		EventMetadataExtractor: testDockerMetadataExtractor,
	})
	So(err, ShouldBeNil)

	mockDocker := mockdocker.NewMockCommonAPIClient(ctrl)
	dm.dockerClient = mockDocker

	// ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	// defer cancel()
	// // mockDocker.EXPECT().Ping(gomock.Any()).Return(types.Ping{}, nil)

	// err = dm.Run(ctx)
	// err = dm.waitForDockerDaemon(ctx)
	So(err, ShouldBeNil)
	return dm, mockPolicy
}

func TestStopDockerContainer(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("When I try to initialize a new docker monitor", t, func() {

		dm, mockPU := setupDockerMonitor(ctrl)
		Convey("Then docker monitor should not be nil", func() {
			So(dm, ShouldNotBeNil)
			So(dm, ShouldNotBeNil)
		})

		Convey("When I try to stop a container", func() {
			mockPU.EXPECT().HandlePUEvent(gomock.Any(), "74cc486f9ec3", tevents.EventStop, gomock.Any()).Times(1).Return(nil)
			dm.SetupHandlers(&config.ProcessorConfig{
				Collector: eventCollector(),
				Policy:    mockPU,
			})

			err := dm.handleDieEvent(context.Background(), &events.Message{ID: "74cc486f9ec3"})

			Convey("Then I should not get any error", func() {
				So(err, ShouldBeNil)
			})
		})
	})
}

func TestHandleCreateEvent(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("When I try to initialize a new docker monitor", t, func() {

		dmi, mockPU := setupDockerMonitor(ctrl)
		Convey("Then docker monitor should not be nil", func() {
			So(dmi, ShouldNotBeNil)
		})

		Convey("When I try to handle create event", func() {
			dmi.SetupHandlers(&config.ProcessorConfig{
				Collector: eventCollector(),
				Policy:    mockPU,
			})

			dmi.dockerClient.(*mockdocker.MockCommonAPIClient).EXPECT().
				ContainerInspect(gomock.Any(), ID).Return(defaultContainer(false), nil)
			mockPU.EXPECT().
				HandlePUEvent(gomock.Any(), ID[:12], tevents.EventCreate, gomock.Any()).Times(1).Return(nil)

			err := dmi.handleCreateEvent(context.Background(), initTestMessage(ID))

			Convey("Then I should not get any error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I try to handle create event with failed container ", func() {
			dmi.SetupHandlers(&config.ProcessorConfig{
				Collector: eventCollector(),
				Policy:    mockPU,
			})

			dmi.dockerClient.(*mockdocker.MockCommonAPIClient).EXPECT().
				ContainerInspect(gomock.Any(), ID).Return(defaultContainer(false), errors.New("error1"))
			err := dmi.handleCreateEvent(context.Background(), initTestMessage(ID))

			Convey("Then I should get error", func() {
				So(err, ShouldResemble, errors.New("unable to read container information: container 74cc486f9ec3256d7bee789853ce05510167c7daf893f90a7577cdcba259d063 kept alive per policy: error1"))
			})
		})

		Convey("When I try to handle create event with no ID given", func() {
			err := dmi.handleCreateEvent(context.Background(), initTestMessage(""))

			Convey("Then I should get error", func() {
				So(err, ShouldResemble, errors.New("unable to generate context id: empty docker id"))
			})
		})
	})
}

func TestHandleStartEvent(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("When I try to initialize a new docker monitor", t, func() {

		dmi, mockPU := setupDockerMonitor(ctrl)
		Convey("Then docker monitor should not be nil", func() {
			So(dmi, ShouldNotBeNil)
		})

		dmi.SetupHandlers(&config.ProcessorConfig{
			Collector: eventCollector(),
			Policy:    mockPU,
		})

		Convey("When I try to handle start event with a valid container", func() {
			dmi.dockerClient.(*mockdocker.MockCommonAPIClient).EXPECT().
				ContainerInspect(gomock.Any(), ID).Return(defaultContainer(false), nil)
			mockPU.EXPECT().
				HandlePUEvent(gomock.Any(), ID[:12], tevents.EventStart, gomock.Any()).Times(1).Return(nil)

			err := dmi.handleStartEvent(context.Background(), initTestMessage(ID))
			Convey("Then I should get no errors", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I try to handle start event with a bad container", func() {
			dmi.dockerClient.(*mockdocker.MockCommonAPIClient).EXPECT().
				ContainerInspect(gomock.Any(), ID).Return(defaultContainer(false), errors.New("error"))

			err := dmi.handleStartEvent(context.Background(), initTestMessage(ID))

			Convey("Then I should get error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I try to handle start event with no ID given", func() {
			c := defaultContainer(false)
			c.ID = ""
			dmi.dockerClient.(*mockdocker.MockCommonAPIClient).EXPECT().
				ContainerInspect(gomock.Any(), gomock.Any()).Return(c, nil)

			err := dmi.handleStartEvent(context.Background(), initTestMessage(""))

			Convey("Then I should get error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I try to handle start event with a valid container and policy fails", func() {
			dmi.dockerClient.(*mockdocker.MockCommonAPIClient).EXPECT().
				ContainerInspect(gomock.Any(), ID).Return(defaultContainer(false), nil)
			mockPU.EXPECT().
				HandlePUEvent(gomock.Any(), ID[:12], tevents.EventStart, gomock.Any()).Times(1).Return(errors.New("policy"))

			err := dmi.handleStartEvent(context.Background(), initTestMessage(ID))
			Convey("Then I should an error", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})
}

func TestHandleDieEvent(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("When I try to initialize a new docker monitor", t, func() {

		dmi, mockPU := setupDockerMonitor(ctrl)
		Convey("Then docker monitor should not be nil", func() {
			So(dmi, ShouldNotBeNil)
		})

		Convey("When I try to handle die event", func() {
			mockPU.EXPECT().HandlePUEvent(gomock.Any(), "74cc486f9ec3", tevents.EventStop, gomock.Any()).Times(1).Return(nil)
			dmi.SetupHandlers(&config.ProcessorConfig{
				Collector: eventCollector(),
				Policy:    mockPU,
			})
			err := dmi.handleDieEvent(context.Background(), initTestMessage(ID))

			Convey("Then I should not get any error", func() {
				So(err, ShouldBeNil)
			})
		})
	})
}

func TestHandleDestroyEvent(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("When I try to initialize a new docker monitor", t, func() {

		dmi, mockPU := setupDockerMonitor(ctrl)

		Convey("Then docker monitor should not be nil", func() {
			So(dmi, ShouldNotBeNil)
		})

		mockCG := mockcgnetcls.NewMockCgroupnetcls(ctrl)

		Convey("When I try to handle destroy event", func() {
			mockPU.EXPECT().HandlePUEvent(gomock.Any(), "74cc486f9ec3", tevents.EventDestroy, gomock.Any()).Times(1).Return(nil)
			mockCG.EXPECT().DeleteCgroup("74cc486f9ec3").Times(1).Return(nil)
			dmi.SetupHandlers(&config.ProcessorConfig{
				Collector: eventCollector(),
				Policy:    mockPU,
			})
			dmi.netcls = mockCG
			err := dmi.handleDestroyEvent(context.Background(), initTestMessage(ID))

			Convey("Then I should not get any error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I try to handle destroy event with no docker ID", func() {
			err := dmi.handleDestroyEvent(context.Background(), initTestMessage(""))

			Convey("Then I should get error", func() {
				So(err, ShouldResemble, errors.New("unable to generate context id: empty docker id"))
			})
		})
	})
}

func TestHandlePauseEvent(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("When I try to initialize a new docker monitor", t, func() {

		dmi, mockPU := setupDockerMonitor(ctrl)

		Convey("Then docker monitor should not be nil", func() {
			So(dmi, ShouldNotBeNil)
		})

		Convey("When I try to handle pause event", func() {
			mockPU.EXPECT().HandlePUEvent(gomock.Any(), "74cc486f9ec3", tevents.EventPause, gomock.Any()).Times(1).Return(nil)
			dmi.SetupHandlers(&config.ProcessorConfig{
				Collector: eventCollector(),
				Policy:    mockPU,
			})
			err := dmi.handlePauseEvent(context.Background(), initTestMessage(ID))

			Convey("Then I should not get any error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I try to handle pause event with no ID", func() {
			err := dmi.handlePauseEvent(context.Background(), initTestMessage(""))

			Convey("Then I should get error", func() {
				So(err, ShouldResemble, errors.New("unable to generate context id: empty docker id"))
			})
		})
	})
}

func TestHandleUnpauseEvent(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("When I try to initialize a new docker monitor", t, func() {

		dmi, mockPU := setupDockerMonitor(ctrl)

		Convey("Then docker monitor should not be nil", func() {
			So(dmi, ShouldNotBeNil)
		})

		Convey("When I try to handle unpause event", func() {
			mockPU.EXPECT().HandlePUEvent(gomock.Any(), "74cc486f9ec3", tevents.EventUnpause, gomock.Any()).Times(1).Return(nil)
			dmi.SetupHandlers(&config.ProcessorConfig{
				Collector: eventCollector(),
				Policy:    mockPU,
			})
			err := dmi.handleUnpauseEvent(context.Background(), initTestMessage(ID))

			Convey("Then I should not get any error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I try to handle unpause event with no ID", func() {
			err := dmi.handleUnpauseEvent(context.Background(), initTestMessage(""))

			Convey("Then I should get error", func() {
				So(err, ShouldResemble, errors.New("unable to generate context id: empty docker id"))
			})
		})
	})
}

func TestExtractMetadata(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("When I try to initialize a new docker monitor", t, func() {

		dmi, _ := setupDockerMonitor(ctrl)

		Convey("Then docker monitor should not be nil", func() {
			So(dmi, ShouldNotBeNil)
		})

		Convey("When I try to call extractmetadata with nil docker info", func() {
			puR, err := dmi.extractMetadata(nil)

			Convey("I should get error", func() {
				So(puR, ShouldBeNil)
				So(err, ShouldResemble, errors.New("docker info is empty"))
			})
		})
	})
}

func TestSyncContainers(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("When I try to initialize a new docker monitor", t, func() {

		dmi, mockPU := setupDockerMonitor(ctrl)
		dmi.SetupHandlers(&config.ProcessorConfig{
			Collector: eventCollector(),
			Policy:    mockPU,
		})

		Convey("Then docker monitor should not be nil", func() {
			So(dmi, ShouldNotBeNil)
		})

		Convey("If I try to sync containers where when SyncAtStart is not set, I should get nil", func() {
			dmi.syncAtStart = false
			err := dmi.Resync(context.Background())
			So(err, ShouldBeNil)
		})

		Convey("If I try to sync containers and docker list fails, I should get an error", func() {
			dmi.syncAtStart = true
			dmi.dockerClient.(*mockdocker.MockCommonAPIClient).EXPECT().
				ContainerList(gomock.Any(), gomock.Any()).Return([]types.Container{{ID: ID}}, errors.New("error"))

			err := dmi.Resync(context.Background())
			So(err, ShouldNotBeNil)
		})

		Convey("When I try to call sync containers and a policy call fails", func() {
			dmi.syncAtStart = true

			dmi.dockerClient.(*mockdocker.MockCommonAPIClient).EXPECT().
				ContainerList(gomock.Any(), gomock.Any()).Return([]types.Container{{ID: ID}}, nil)

			dmi.dockerClient.(*mockdocker.MockCommonAPIClient).EXPECT().
				ContainerInspect(gomock.Any(), ID).Return(defaultContainer(false), nil).MaxTimes(2)

			mockPU.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("blah"))

			err := dmi.Resync(context.Background())

			Convey("Then I should  get  error since we ignore bad containers", func() {
				So(err, ShouldBeNil)
			})

		})

		Convey("When I try to call sync containers", func() {
			dmi.syncAtStart = true

			dmi.dockerClient.(*mockdocker.MockCommonAPIClient).EXPECT().
				ContainerList(gomock.Any(), gomock.Any()).Return([]types.Container{{ID: ID}}, nil)

			dmi.dockerClient.(*mockdocker.MockCommonAPIClient).EXPECT().
				ContainerInspect(gomock.Any(), ID).Return(defaultContainer(false), nil).MaxTimes(2)

			mockPU.EXPECT().HandlePUEvent(gomock.Any(), ID[:12], tevents.EventStart, gomock.Any()).AnyTimes().Return(nil)

			err := dmi.Resync(context.Background())

			Convey("Then I should not get no error ", func() {
				So(err, ShouldBeNil)
			})

		})

		Convey("When I try to call sync host containers", func() {
			dmi.syncAtStart = true
			hostContainer := types.Container{
				ID: ID,
				HostConfig: struct {
					NetworkMode string `json:",omitempty"`
				}{NetworkMode: "host"}}

			dmi.dockerClient.(*mockdocker.MockCommonAPIClient).EXPECT().
				ContainerList(gomock.Any(), gomock.Any()).Return([]types.Container{hostContainer}, nil)

			dmi.dockerClient.(*mockdocker.MockCommonAPIClient).EXPECT().
				ContainerInspect(gomock.Any(), ID).Return(defaultContainer(true), nil).MaxTimes(2)

			mockPU.EXPECT().HandlePUEvent(gomock.Any(), ID[:12], tevents.EventStart, gomock.Any()).AnyTimes().Return(nil)

			err := dmi.Resync(context.Background())

			Convey("Then I should not get no error ", func() {
				So(err, ShouldBeNil)
			})

		})
	})
}

func Test_initTestDockerInfo(t *testing.T) {
	type args struct {
		id     string
		nwmode container.NetworkMode
		state  bool
	}
	tests := []struct {
		name string
		args args
		want *types.ContainerJSON
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := initTestDockerInfo(tt.args.id, tt.args.nwmode, tt.args.state); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("initTestDockerInfo() = %v, want %v", got, tt.want)
			}
		})
	}
}

func testWaitForDockerDaemon(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("If docker daemon is not running and setup docker daemon returns an error", t, func() {

		dmi, _ := setupDockerMonitor(ctrl)
		dmi.dockerClient.(*mockdocker.MockCommonAPIClient).EXPECT().Ping(gomock.Any()).Return(errors.New("Ping Error"))
		// 30*time.Second is greater then dockerInitializationwait
		waitforDockerInitializationTimeout := dockerInitializationWait + 5*time.Second
		expiryTime := time.Now().Add(waitforDockerInitializationTimeout)
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(waitforDockerInitializationTimeout))
		err := dmi.waitForDockerDaemon(ctx)
		So(err, ShouldBeNil)
		So(time.Now(), ShouldHappenBefore, expiryTime)
		// this will kill the Goroutine
		cancel()
	})
}
