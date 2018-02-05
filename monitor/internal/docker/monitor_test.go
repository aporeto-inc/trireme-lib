package dockermonitor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/aporeto-inc/trireme-lib/collector"
	tevents "github.com/aporeto-inc/trireme-lib/common"
	"github.com/aporeto-inc/trireme-lib/monitor/config"
	"github.com/aporeto-inc/trireme-lib/monitor/constants"
	"github.com/aporeto-inc/trireme-lib/monitor/extractors"
	"github.com/aporeto-inc/trireme-lib/policy/mock"
	"github.com/aporeto-inc/trireme-lib/utils/cgnetcls/mock"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"
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

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	err = dm.Run(ctx)
	// err = dm.waitForDockerDaemon(ctx)
	So(err, ShouldBeNil)
	return dm, mockPolicy
}

func TestStartDockerContainer(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("When I try to initialize a new docker monitor", t, func() {

		dm, mockPU := setupDockerMonitor(ctrl)

		mockCG := mockcgnetcls.NewMockCgroupnetcls(ctrl)
		Convey("Then docker monitor should not be nil", func() {
			So(dm, ShouldNotBeNil)
		})

		Convey("When I try to start default docker container", func() {
			mockPU.EXPECT().HandlePUEvent(gomock.Any(), "74cc486f9ec3", tevents.EventStart, gomock.Any()).Times(1).Return(nil)
			err := dm.startDockerContainer(context.Background(), initTestDockerInfo(ID, "default", true))
			Convey("Then I should not get error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I try to start default docker container and state running set to false", func() {
			err := dm.startDockerContainer(context.Background(), initTestDockerInfo(ID, "default", false))
			Convey("Then I should not get error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I try to start default docker container with empty ID", func() {
			err := dm.startDockerContainer(context.Background(), initTestDockerInfo("", "default", true))
			Convey("Then I should get error", func() {
				So(err, ShouldResemble, errors.New("unable to generate context id: empty docker id"))
			})
		})

		Convey("When I try to start default docker container with invalid context ID and killContainerOnPolicyError not set", func() {
			mockPU.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any(), tevents.EventStart, gomock.Any()).Times(1).Return(fmt.Errorf("Error"))
			err := dm.startDockerContainer(context.Background(), initTestDockerInfo(ID, "default", true))

			Convey("Then I should get error", func() {
				So(err, ShouldResemble, errors.New("unable to set policy: container 74cc486f9ec3 kept alive per policy: Error"))
			})
		})

		Convey("When I try to start from default docker container with invalid context ID", func() {
			dm.killContainerOnPolicyError = true

			mockPU.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any(), tevents.EventStart, gomock.Any()).Times(1).Return(fmt.Errorf("Error"))
			err := dm.startDockerContainer(context.Background(), initTestDockerInfo(ID, "default", true))
			Convey("Then I should get error", func() {
				So(err, ShouldResemble, errors.New("unable to set policy: container 74cc486f9ec3 kept alive per policy: Error"))
			})
		})

		Convey("When I try to start host docker container", func() {
			mockPU.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any(), tevents.EventStart, gomock.Any()).Times(1).Return(nil)
			mockCG.EXPECT().Creategroup("74cc486f9ec3").Times(1).Return(nil)
			mockCG.EXPECT().AssignMark("74cc486f9ec3", uint64(102)).Times(1).Return(nil)
			mockCG.EXPECT().AddProcess("74cc486f9ec3", int(4912)).Times(1).Return(nil)
			dm.netcls = mockCG
			err := dm.startDockerContainer(context.Background(), initTestDockerInfo(ID, "host", true))

			Convey("Then I should not get any error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I try to start host docker container with error in assigning mark", func() {
			mockPU.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any(), tevents.EventStart, gomock.Any()).Times(1).Return(nil)
			mockCG.EXPECT().Creategroup("74cc486f9ec3").Times(1).Return(nil)
			mockCG.EXPECT().AssignMark(gomock.Any(), gomock.Any()).Times(1).Return(errors.New("error"))
			mockCG.EXPECT().DeleteCgroup("74cc486f9ec3").Times(1).Return(nil)
			dm.netcls = mockCG
			err := dm.startDockerContainer(context.Background(), initTestDockerInfo(ID, "host", true))

			Convey("Then I should get error", func() {
				So(err, ShouldResemble, errors.New("unable to setup host mode for container 74cc486f9ec3: error"))
			})
		})

		Convey("When I try start docker container with error adding process", func() {
			mockPU.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any(), tevents.EventStart, gomock.Any()).Times(1).Return(nil)
			mockCG.EXPECT().Creategroup("74cc486f9ec3").Times(1).Return(nil)
			mockCG.EXPECT().AssignMark("74cc486f9ec3", uint64(104)).Times(1).Return(nil)
			mockCG.EXPECT().AddProcess(gomock.Any(), gomock.Any()).Times(1).Return(errors.New("error"))
			mockCG.EXPECT().DeleteCgroup("74cc486f9ec3").Times(1).Return(nil)
			dm.netcls = mockCG
			err := dm.startDockerContainer(context.Background(), initTestDockerInfo(ID, "host", true))

			Convey("Then I should get error", func() {
				So(err, ShouldResemble, errors.New("unable to setup host mode for container 74cc486f9ec3: error"))
			})
		})

		Convey("When I try to start host docker container with error in create group", func() {
			mockPU.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any(), tevents.EventStart, gomock.Any()).Times(1).Return(nil)
			mockCG.EXPECT().Creategroup(gomock.Any()).Times(1).Return(fmt.Errorf("Error"))
			dm.netcls = mockCG
			err := dm.startDockerContainer(context.Background(), initTestDockerInfo(ID, "host", true))

			Convey("Then I should get error", func() {
				So(err, ShouldResemble, errors.New("unable to setup host mode for container 74cc486f9ec3: Error"))
			})
		})
	})
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

// func TestHandleCreateEvent(t *testing.T) {
// 	ctrl := gomock.NewController(t)
// 	defer ctrl.Finish()

// 	Convey("When I try to initialize a new docker monitor", t, func() {

// 		dmi, mockPU := setupDockerMonitor(ctrl)

// 		Convey("Then docker monitor should not be nil", func() {
// 			So(dmi, ShouldNotBeNil)
// 		})

// 		Convey("When I try to handle create event", func() {
// 			mockPU.EXPECT().HandlePUEvent(gomock.Any(), "74cc486f9ec3", tevents.EventCreate, gomock.Any()).Times(1).Return(nil)
// 			dmi.SetupHandlers(&config.ProcessorConfig{
// 				Collector: eventCollector(),
// 				Policy:    mockPU,
// 			})
// 			err := dmi.handleCreateEvent(context.Background(), initTestMessage(ID))

// 			Convey("Then I should not get any error", func() {
// 				So(err, ShouldBeNil)
// 			})
// 		})

// 		Convey("When I try to handle create event with no ID given", func() {
// 			err := dmi.handleCreateEvent(context.Background(), initTestMessage(""))

// 			Convey("Then I should get error", func() {
// 				So(err, ShouldResemble, errors.New("unable to generate context id: empty docker id"))
// 			})
// 		})
// 	})
// }

// func TestHandleStartEvent(t *testing.T) {
// 	ctrl := gomock.NewController(t)
// 	defer ctrl.Finish()

// 	Convey("When I try to initialize a new docker monitor", t, func() {

// 		dmi, _ := setupDockerMonitor(ctrl)

// 		Convey("Then docker monitor should not be nil", func() {
// 			So(dmi, ShouldNotBeNil)
// 		})

// 		Convey("When I try to handle start event", func() {
// 			options := types.ContainerListOptions{All: true}
// 			containers, err := dmi.dockerClient.ContainerList(context.Background(), options)

// 			if err == nil && len(containers) > 0 {

// 				err = dmi.handleStartEvent(context.Background(), initTestMessage(ID))

// 				Convey("Then I should get error", func() {
// 					So(err, ShouldResemble, errors.New("unable to read container information: container 74cc486f9ec3 kept alive per policy: Error: No such container: 74cc486f9ec3256d7bee789853ce05510167c7daf893f90a7577cdcba259d063"))
// 				})
// 			}
// 		})

// 		Convey("When I try to handle start event with no ID given", func() {
// 			err := dmi.handleStartEvent(context.Background(), initTestMessage(""))

// 			Convey("Then I should get error", func() {
// 				So(err, ShouldResemble, errors.New("unable to generate context id: empty docker id"))
// 			})
// 		})

// 		Convey("When I try to handle start event with invalid ID given and killContainerOnPolicyError is set", func() {
// 			dmi.killContainerOnPolicyError = true
// 			err := dmi.handleStartEvent(context.Background(), initTestMessage("74cc486f9ec3256d7bee789853ce05510117c7daf893f90a7577cdcba259d063"))

// 			Convey("Then I should get error", func() {
// 				So(err, ShouldResemble, errors.New("unable to read container information: container 74cc486f9ec3 killed: Error: No such container: 74cc486f9ec3256d7bee789853ce05510117c7daf893f90a7577cdcba259d063"))
// 			})
// 		})

// 		Convey("When I try to handle start event with invalid ID given", func() {
// 			err := dmi.handleStartEvent(context.Background(), initTestMessage("abcc486f9ec3256d7bee789853ce05510117c7daf893f90a7577cdcba259d063"))

// 			Convey("Then I should get error", func() {
// 				So(err, ShouldResemble, errors.New("unable to read container information: container abcc486f9ec3 kept alive per policy: Error: No such container: abcc486f9ec3256d7bee789853ce05510117c7daf893f90a7577cdcba259d063"))
// 			})
// 		})
// 	})
// }

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

		Convey("Then docker monitor should not be nil", func() {
			So(dmi, ShouldNotBeNil)
		})

		Convey("When I try to call sync containers", func() {
			options := types.ContainerListOptions{All: true}
			containers, err := dmi.dockerClient.ContainerList(context.Background(), options)
			if err == nil && len(containers) > 0 {
				mockPU.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any(), tevents.EventStart, gomock.Any()).AnyTimes().Return(nil)
				dmi.SetupHandlers(&config.ProcessorConfig{
					Collector: eventCollector(),
					Policy:    mockPU,
				})
				err = dmi.ReSync(context.Background())

				Convey("Then I should not get any error", func() {
					So(err, ShouldBeNil)
				})
			}
		})
	})

	Convey("When I try to initialize a new docker monitor with synchandler", t, func() {

		dmi, mockPU := setupDockerMonitor(ctrl)

		Convey("Then docker monitor should not be nil", func() {
			So(dmi, ShouldNotBeNil)
		})

		Convey("When I try to call sync containers", func() {
			options := types.ContainerListOptions{All: true}
			containers, err := dmi.dockerClient.ContainerList(context.Background(), options)
			if err == nil && len(containers) > 0 {
				mockPU.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any(), tevents.EventStart, gomock.Any()).AnyTimes().Return(nil)
				dmi.SetupHandlers(&config.ProcessorConfig{
					Collector: eventCollector(),
					Policy:    mockPU,
				})
				err = dmi.ReSync(context.Background())

				Convey("Then I should not get any error", func() {
					So(err, ShouldBeNil)
				})
			}
		})
	})
}

func TestStart(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("When I try to initialize a new docker monitor with syncatstart set to false", t, func() {

		dmi, _ := setupDockerMonitor(ctrl)

		Convey("Then docker monitor should not be nil", func() {
			So(dmi, ShouldNotBeNil)
		})

		Convey("When I try to call extractmetadata with nil docker info", func() {

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, pingerr := dmi.dockerClient.Ping(ctx)
			if pingerr != nil {
				err := dmi.Run(context.Background())
				Convey("I should get error", func() {
					So(err, ShouldResemble, errors.New("docker daemon not running"))
				})
			} else {

				err := dmi.Run(context.Background())
				Convey("I should not get error", func() {
					So(err, ShouldBeNil)
				})
			}
		})
	})

	Convey("When I try to initialize a new docker monitor", t, func() {

		dmi, mockPU := setupDockerMonitor(ctrl)

		Convey("Then docker monitor should not be nil", func() {
			So(dmi, ShouldNotBeNil)
		})

		Convey("When I try to call extractmetadata with nil docker info", func() {
			options := types.ContainerListOptions{All: true}
			containers, err := dmi.dockerClient.ContainerList(context.Background(), options)
			if err == nil && len(containers) > 0 {
				mockPU.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any(), tevents.EventStart, gomock.Any()).AnyTimes().Return(nil)
				dmi.SetupHandlers(&config.ProcessorConfig{
					Collector: eventCollector(),
					Policy:    mockPU,
				})
				err := dmi.Run(context.Background())

				Convey("I should not get any error", func() {
					So(err, ShouldBeNil)
				})
			}
		})
	})
}
