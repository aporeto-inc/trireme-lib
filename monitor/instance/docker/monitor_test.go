package dockermonitor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/aporeto-inc/trireme-lib/cgnetcls/mock"
	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/constants"
	tevents "github.com/aporeto-inc/trireme-lib/monitor/rpc/events"
	"github.com/aporeto-inc/trireme-lib/monitor/rpc/processor"
	"github.com/aporeto-inc/trireme-lib/monitor/rpc/processor/mock"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"
)

var (
	testDockerMetadataExtractor MetadataExtractor
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
		cID, err := contextIDFromDockerID(ID)
		cID1 := "74cc486f9ec3"

		Convey("Then contextID should match and I should not get any error", func() {
			So(cID, ShouldEqual, cID1)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I try to retrieve contextID when dockerID length less than 12", t, func() {
		cID, err := contextIDFromDockerID("6f47830f64")

		Convey("Then I should get error", func() {
			So(cID, ShouldEqual, "")
			So(err, ShouldResemble, errors.New("unable to generate context id: dockerid smaller than 12 characters: 6f47830f64"))
		})
	})

	Convey("When I try to retrieve contextID when no dockerID given", t, func() {
		cID, err := contextIDFromDockerID("")

		Convey("Then I should get error", func() {
			So(cID, ShouldEqual, "")
			So(err, ShouldResemble, errors.New("unable to generate context id: empty docker id"))
		})
	})
}

func TestDefaultDockerMetadataExtractor(t *testing.T) {
	Convey("When I try to extract metadata from default docker container", t, func() {
		puR, err := defaultMetadataExtractor(initTestDockerInfo(ID, "default", false))

		Convey("Then I should not get any error", func() {
			So(puR, ShouldNotBeNil)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I try to extract metadata from host docker container", t, func() {
		puR, err := defaultMetadataExtractor(initTestDockerInfo(ID, "host", false))

		Convey("Then I should not get any error", func() {
			So(puR, ShouldNotBeNil)
			So(err, ShouldBeNil)
		})
	})
}

func TestStartDockerContainer(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("When I try to initialize a new docker monitor", t, func() {

		dm := New()
		mockPU := mockprocessor.NewMockProcessingUnitsHandler(ctrl)
		mockSH := mockprocessor.NewMockSynchronizationHandler(ctrl)
		dm.SetupHandlers(&processor.Config{
			Collector:   eventCollector(),
			PUHandler:   mockPU,
			SyncHandler: mockSH,
		})
		err := dm.SetupConfig(nil, &Config{
			EventMetadataExtractor: testDockerMetadataExtractor,
		})
		So(err, ShouldBeNil)

		mockCG := mockcgnetcls.NewMockCgroupnetcls(ctrl)

		Convey("Then docker monitor should not be nil", func() {
			So(dm, ShouldNotBeNil)
		})

		Convey("When I try to start default docker container", func() {
			mockPU.EXPECT().CreatePURuntime("74cc486f9ec3", gomock.Any()).Times(1).Return(nil)
			mockPU.EXPECT().HandlePUEvent("74cc486f9ec3", tevents.EventStart).Times(1).Return(nil)
			err := dm.(*dockerMonitor).startDockerContainer(initTestDockerInfo(ID, "default", true))

			Convey("Then I should not get error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I try to start default docker container and state running set to false", func() {
			err := dm.(*dockerMonitor).startDockerContainer(initTestDockerInfo(ID, "default", false))

			Convey("Then I should not get error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I try to start default docker container with empty ID", func() {
			err := dm.(*dockerMonitor).startDockerContainer(initTestDockerInfo("", "default", true))

			Convey("Then I should get error", func() {
				So(err, ShouldResemble, errors.New("unable to generate context id: empty docker id"))
			})
		})

		Convey("When I try to start default docker container with invalid context ID and killContainerOnPolicyError not set", func() {
			mockPU.EXPECT().CreatePURuntime(gomock.Any(), gomock.Any()).Times(1).Return(nil)
			mockPU.EXPECT().HandlePUEvent(gomock.Any(), tevents.EventStart).Times(1).Return(fmt.Errorf("Error"))
			err := dm.(*dockerMonitor).startDockerContainer(initTestDockerInfo(ID, "default", true))

			Convey("Then I should get error", func() {
				So(err, ShouldResemble, errors.New("unable to set policy: container 74cc486f9ec3 kept alive per policy: Error"))
			})
		})

		Convey("When I try to start from default docker container with invalid context ID", func() {
			err := dm.SetupConfig(nil, &Config{
				EventMetadataExtractor:     testDockerMetadataExtractor,
				KillContainerOnPolicyError: true,
			})
			So(err, ShouldBeNil)

			mockPU.EXPECT().CreatePURuntime(gomock.Any(), gomock.Any()).Times(1).Return(nil)
			mockPU.EXPECT().HandlePUEvent(gomock.Any(), tevents.EventStart).Times(1).Return(fmt.Errorf("Error"))

			err = dm.(*dockerMonitor).startDockerContainer(initTestDockerInfo(ID, "default", true))

			Convey("Then I should get error", func() {
				So(err, ShouldResemble, errors.New("unable to set policy: killed container 74cc486f9ec3: Error"))
			})
		})

		Convey("When I try to start host docker container", func() {
			mockPU.EXPECT().CreatePURuntime(gomock.Any(), gomock.Any()).Times(1).Return(nil)
			mockPU.EXPECT().HandlePUEvent(gomock.Any(), tevents.EventStart).Times(1).Return(nil)
			mockCG.EXPECT().Creategroup("74cc486f9ec3").Times(1).Return(nil)
			mockCG.EXPECT().AssignMark("74cc486f9ec3", uint64(102)).Times(1).Return(nil)
			mockCG.EXPECT().AddProcess("74cc486f9ec3", int(4912)).Times(1).Return(nil)
			dm.(*dockerMonitor).netcls = mockCG
			err := dm.(*dockerMonitor).startDockerContainer(initTestDockerInfo(ID, "host", true))

			Convey("Then I should not get any error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I try to start host docker container with error in assigning mark", func() {
			mockPU.EXPECT().CreatePURuntime(gomock.Any(), gomock.Any()).Times(1).Return(nil)
			mockPU.EXPECT().HandlePUEvent(gomock.Any(), tevents.EventStart).Times(1).Return(nil)
			mockCG.EXPECT().Creategroup("74cc486f9ec3").Times(1).Return(nil)
			mockCG.EXPECT().AssignMark(gomock.Any(), gomock.Any()).Times(1).Return(errors.New("error"))
			mockCG.EXPECT().DeleteCgroup("74cc486f9ec3").Times(1).Return(nil)
			dm.(*dockerMonitor).netcls = mockCG
			err := dm.(*dockerMonitor).startDockerContainer(initTestDockerInfo(ID, "host", true))

			Convey("Then I should get error", func() {
				So(err, ShouldResemble, errors.New("unable to setup host mode for container 74cc486f9ec3: error"))
			})
		})

		Convey("When I try start docker container with error adding process", func() {
			mockPU.EXPECT().CreatePURuntime(gomock.Any(), gomock.Any()).Times(1).Return(nil)
			mockPU.EXPECT().HandlePUEvent(gomock.Any(), tevents.EventStart).Times(1).Return(nil)
			mockCG.EXPECT().Creategroup("74cc486f9ec3").Times(1).Return(nil)
			mockCG.EXPECT().AssignMark("74cc486f9ec3", uint64(104)).Times(1).Return(nil)
			mockCG.EXPECT().AddProcess(gomock.Any(), gomock.Any()).Times(1).Return(errors.New("error"))
			mockCG.EXPECT().DeleteCgroup("74cc486f9ec3").Times(1).Return(nil)
			dm.(*dockerMonitor).netcls = mockCG
			err := dm.(*dockerMonitor).startDockerContainer(initTestDockerInfo(ID, "host", true))

			Convey("Then I should get error", func() {
				So(err, ShouldResemble, errors.New("unable to setup host mode for container 74cc486f9ec3: error"))
			})
		})

		Convey("When I try to start host docker container with error in create group", func() {
			mockPU.EXPECT().CreatePURuntime(gomock.Any(), gomock.Any()).Times(1).Return(nil)
			mockPU.EXPECT().HandlePUEvent(gomock.Any(), tevents.EventStart).Times(1).Return(nil)
			mockCG.EXPECT().Creategroup(gomock.Any()).Times(1).Return(fmt.Errorf("Error"))
			dm.(*dockerMonitor).netcls = mockCG
			err := dm.(*dockerMonitor).startDockerContainer(initTestDockerInfo(ID, "host", true))

			Convey("Then I should get error", func() {
				So(err, ShouldResemble, errors.New("unable to setup host mode for container 74cc486f9ec3: Error"))
			})
		})

		Convey("When I try to start host docker container with error in set PU", func() {
			mockPU.EXPECT().CreatePURuntime(gomock.Any(), gomock.Any()).Times(1).Return(fmt.Errorf("Error"))
			err := dm.(*dockerMonitor).startDockerContainer(initTestDockerInfo(ID, "host", true))

			Convey("Then I should get error", func() {
				So(err, ShouldResemble, errors.New("Error"))
			})
		})
	})
}

func TestStopDockerContainer(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("When I try to initialize a new docker monitor", t, func() {
		dm := New()
		mockPU := mockprocessor.NewMockProcessingUnitsHandler(ctrl)
		mockSH := mockprocessor.NewMockSynchronizationHandler(ctrl)
		dm.SetupHandlers(&processor.Config{
			Collector:   eventCollector(),
			PUHandler:   mockPU,
			SyncHandler: mockSH,
		})
		dm.SetupConfig(nil, Config{
			EventMetadataExtractor: testDockerMetadataExtractor,
		})

		Convey("Then docker monitor should not be nil", func() {
			So(dm, ShouldNotBeNil)
		})

		Convey("When I try to stop a container", func() {
			mockPU.EXPECT().HandlePUEvent("74cc486f9ec3", tevents.EventStop).Times(1).Return(nil)
			dm.SetupHandlers(&processor.Config{
				Collector:   eventCollector(),
				PUHandler:   mockPU,
				SyncHandler: mockSH,
			})
			err := dm.(*dockerMonitor).stopDockerContainer(ID)

			Convey("Then I should not get any error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I try to stop a container with no ID given", func() {
			err := dm.(*dockerMonitor).stopDockerContainer("")

			Convey("Then I should get error", func() {
				So(err, ShouldResemble, errors.New("unable to generate context id: empty docker id"))
			})
		})
	})
}

func TestHandleCreateEvent(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("When I try to initialize a new docker monitor", t, func() {
		dm := New()
		mockPU := mockprocessor.NewMockProcessingUnitsHandler(ctrl)
		mockSH := mockprocessor.NewMockSynchronizationHandler(ctrl)
		dm.SetupHandlers(&processor.Config{
			Collector:   eventCollector(),
			PUHandler:   mockPU,
			SyncHandler: mockSH,
		})
		dm.SetupConfig(nil, Config{
			EventMetadataExtractor: testDockerMetadataExtractor,
		})

		Convey("Then docker monitor should not be nil", func() {
			So(dm, ShouldNotBeNil)
		})

		Convey("When I try to handle create event", func() {
			mockPU.EXPECT().HandlePUEvent("74cc486f9ec3", tevents.EventCreate).Times(1).Return(nil)
			dm.SetupHandlers(&processor.Config{
				Collector:   eventCollector(),
				PUHandler:   mockPU,
				SyncHandler: mockSH,
			})
			err := dm.(*dockerMonitor).handleCreateEvent(initTestMessage(ID))

			Convey("Then I should not get any error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I try to handle create event with no ID given", func() {
			err := dm.(*dockerMonitor).handleCreateEvent(initTestMessage(""))

			Convey("Then I should get error", func() {
				So(err, ShouldResemble, errors.New("unable to generate context id: empty docker id"))
			})
		})
	})
}

func TestHandleStartEvent(t *testing.T) {

	Convey("When I try to initialize a new docker monitor", t, func() {
		dm := New()
		So(dm, ShouldNotBeNil)
		dm.SetupHandlers(&processor.Config{
			Collector: eventCollector(),
		})
		err := dm.SetupConfig(nil, &Config{
			EventMetadataExtractor: testDockerMetadataExtractor,
		})
		So(err, ShouldBeNil)

		Convey("Then docker monitor should not be nil", func() {
			So(dm, ShouldNotBeNil)
		})

		Convey("When I try to handle start event", func() {
			options := types.ContainerListOptions{All: true}
			containers, err := dm.(*dockerMonitor).dockerClient.ContainerList(context.Background(), options)

			if err == nil && len(containers) > 0 {

				err = dm.(*dockerMonitor).handleStartEvent(initTestMessage(ID))

				Convey("Then I should get error", func() {
					So(err, ShouldResemble, errors.New("unable to read container information: container 74cc486f9ec3 kept alive per policy: Error: No such container: 74cc486f9ec3256d7bee789853ce05510167c7daf893f90a7577cdcba259d063"))
				})
			}
		})

		Convey("When I try to handle start event with no ID given", func() {
			err := dm.(*dockerMonitor).handleStartEvent(initTestMessage(""))

			Convey("Then I should get error", func() {
				So(err, ShouldResemble, errors.New("unable to generate context id: empty docker id"))
			})
		})

		Convey("When I try to handle start event with invalid ID given and killContainerOnPolicyError is set", func() {
			dm.(*dockerMonitor).killContainerOnPolicyError = true
			err := dm.(*dockerMonitor).handleStartEvent(initTestMessage("74cc486f9ec3256d7bee789853ce05510117c7daf893f90a7577cdcba259d063"))

			Convey("Then I should get error", func() {
				So(err, ShouldResemble, errors.New("unable to read container information: container 74cc486f9ec3 killed: Error: No such container: 74cc486f9ec3256d7bee789853ce05510117c7daf893f90a7577cdcba259d063"))
			})
		})

		Convey("When I try to handle start event with invalid ID given", func() {
			err := dm.(*dockerMonitor).handleStartEvent(initTestMessage("abcc486f9ec3256d7bee789853ce05510117c7daf893f90a7577cdcba259d063"))

			Convey("Then I should get error", func() {
				So(err, ShouldResemble, errors.New("unable to read container information: container abcc486f9ec3 kept alive per policy: Error: No such container: abcc486f9ec3256d7bee789853ce05510117c7daf893f90a7577cdcba259d063"))
			})
		})
	})
}

func TestHandleDieEvent(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("When I try to initialize a new docker monitor", t, func() {
		dm := New()
		mockPU := mockprocessor.NewMockProcessingUnitsHandler(ctrl)
		mockSH := mockprocessor.NewMockSynchronizationHandler(ctrl)
		dm.SetupHandlers(&processor.Config{
			Collector:   eventCollector(),
			PUHandler:   mockPU,
			SyncHandler: mockSH,
		})
		dm.SetupConfig(nil, Config{
			EventMetadataExtractor: testDockerMetadataExtractor,
		})

		Convey("Then docker monitor should not be nil", func() {
			So(dm, ShouldNotBeNil)
		})

		Convey("When I try to handle die event", func() {
			mockPU.EXPECT().HandlePUEvent("74cc486f9ec3", tevents.EventStop).Times(1).Return(nil)
			dm.SetupHandlers(&processor.Config{
				Collector:   eventCollector(),
				PUHandler:   mockPU,
				SyncHandler: mockSH,
			})
			err := dm.(*dockerMonitor).handleDieEvent(initTestMessage(ID))

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
		dm := New()
		mockPU := mockprocessor.NewMockProcessingUnitsHandler(ctrl)
		mockSH := mockprocessor.NewMockSynchronizationHandler(ctrl)
		dm.SetupHandlers(&processor.Config{
			Collector:   eventCollector(),
			PUHandler:   mockPU,
			SyncHandler: mockSH,
		})
		dm.SetupConfig(nil, Config{
			EventMetadataExtractor: testDockerMetadataExtractor,
		})
		mockCG := mockcgnetcls.NewMockCgroupnetcls(ctrl)

		Convey("Then docker monitor should not be nil", func() {
			So(dm, ShouldNotBeNil)
		})

		Convey("When I try to handle destroy event", func() {
			mockPU.EXPECT().HandlePUEvent("74cc486f9ec3", tevents.EventDestroy).Times(1).Return(nil)
			mockCG.EXPECT().DeleteCgroup("74cc486f9ec3").Times(1).Return(nil)
			dm.SetupHandlers(&processor.Config{
				Collector:   eventCollector(),
				PUHandler:   mockPU,
				SyncHandler: mockSH,
			})
			dm.(*dockerMonitor).netcls = mockCG
			err := dm.(*dockerMonitor).handleDestroyEvent(initTestMessage(ID))

			Convey("Then I should not get any error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I try to handle destroy event with no docker ID", func() {
			err := dm.(*dockerMonitor).handleDestroyEvent(initTestMessage(""))

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
		dm := New()
		mockPU := mockprocessor.NewMockProcessingUnitsHandler(ctrl)
		mockSH := mockprocessor.NewMockSynchronizationHandler(ctrl)
		dm.SetupHandlers(&processor.Config{
			Collector:   eventCollector(),
			PUHandler:   mockPU,
			SyncHandler: mockSH,
		})
		dm.SetupConfig(nil, Config{
			EventMetadataExtractor: testDockerMetadataExtractor,
		})

		Convey("Then docker monitor should not be nil", func() {
			So(dm, ShouldNotBeNil)
		})

		Convey("When I try to handle pause event", func() {
			mockPU.EXPECT().HandlePUEvent("74cc486f9ec3", tevents.EventPause).Times(1).Return(nil)
			dm.SetupHandlers(&processor.Config{
				Collector:   eventCollector(),
				PUHandler:   mockPU,
				SyncHandler: mockSH,
			})
			err := dm.(*dockerMonitor).handlePauseEvent(initTestMessage(ID))

			Convey("Then I should not get any error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I try to handle pause event with no ID", func() {
			err := dm.(*dockerMonitor).handlePauseEvent(initTestMessage(""))

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

		dm := New()
		mockPU := mockprocessor.NewMockProcessingUnitsHandler(ctrl)
		mockSH := mockprocessor.NewMockSynchronizationHandler(ctrl)
		dm.SetupHandlers(&processor.Config{
			Collector:   eventCollector(),
			PUHandler:   mockPU,
			SyncHandler: mockSH,
		})
		dm.SetupConfig(nil, Config{
			EventMetadataExtractor: testDockerMetadataExtractor,
		})

		Convey("Then docker monitor should not be nil", func() {
			So(dm, ShouldNotBeNil)
		})

		Convey("When I try to handle unpause event", func() {
			mockPU.EXPECT().HandlePUEvent("74cc486f9ec3", tevents.EventUnpause).Times(1).Return(nil)
			dm.SetupHandlers(&processor.Config{
				Collector:   eventCollector(),
				PUHandler:   mockPU,
				SyncHandler: mockSH,
			})
			err := dm.(*dockerMonitor).handleUnpauseEvent(initTestMessage(ID))

			Convey("Then I should not get any error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I try to handle unpause event with no ID", func() {
			err := dm.(*dockerMonitor).handleUnpauseEvent(initTestMessage(""))

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

		dm := New()
		mockPU := mockprocessor.NewMockProcessingUnitsHandler(ctrl)
		mockSH := mockprocessor.NewMockSynchronizationHandler(ctrl)
		dm.SetupHandlers(&processor.Config{
			Collector:   eventCollector(),
			PUHandler:   mockPU,
			SyncHandler: mockSH,
		})
		dm.SetupConfig(nil, Config{
			EventMetadataExtractor: testDockerMetadataExtractor,
		})
		Convey("Then docker monitor should not be nil", func() {
			So(dm, ShouldNotBeNil)
		})

		Convey("When I try to call extractmetadata with nil docker info", func() {
			puR, err := dm.(*dockerMonitor).extractMetadata(nil)

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
		dm := New()
		So(dm, ShouldNotBeNil)
		mockPU := mockprocessor.NewMockProcessingUnitsHandler(ctrl)
		mockSH := mockprocessor.NewMockSynchronizationHandler(ctrl)
		dm.SetupHandlers(&processor.Config{
			Collector:   eventCollector(),
			PUHandler:   mockPU,
			SyncHandler: mockSH,
		})
		err := dm.SetupConfig(nil, &Config{
			EventMetadataExtractor: testDockerMetadataExtractor,
		})
		So(err, ShouldBeNil)

		Convey("Then docker monitor should not be nil", func() {
			So(dm, ShouldNotBeNil)
		})

		Convey("When I try to call sync containers", func() {
			options := types.ContainerListOptions{All: true}
			containers, err := dm.(*dockerMonitor).dockerClient.ContainerList(context.Background(), options)
			if err == nil && len(containers) > 0 {
				mockPU.EXPECT().CreatePURuntime(gomock.Any(), gomock.Any()).AnyTimes().Return(nil)
				mockPU.EXPECT().HandlePUEvent(gomock.Any(), tevents.EventStart).AnyTimes().Return(nil)
				mockSH.EXPECT().HandleSynchronization(gomock.Any(), tevents.StateStarted, gomock.Any(), processor.SynchronizationTypeInitial)
				mockSH.EXPECT().HandleSynchronizationComplete(gomock.Any())
				dm.SetupHandlers(&processor.Config{
					Collector:   eventCollector(),
					PUHandler:   mockPU,
					SyncHandler: mockSH,
				})
				err = dm.(*dockerMonitor).ReSync()

				Convey("Then I should not get any error", func() {
					So(err, ShouldBeNil)
				})
			}
		})
	})

	Convey("When I try to initialize a new docker monitor with synchandler", t, func() {
		dm := New()
		mockPU := mockprocessor.NewMockProcessingUnitsHandler(ctrl)
		mockSH := mockprocessor.NewMockSynchronizationHandler(ctrl)
		dm.SetupHandlers(&processor.Config{
			Collector:   eventCollector(),
			PUHandler:   mockPU,
			SyncHandler: mockSH,
		})
		err := dm.SetupConfig(nil, &Config{
			EventMetadataExtractor: testDockerMetadataExtractor,
		})
		So(err, ShouldBeNil)

		Convey("Then docker monitor should not be nil", func() {
			So(dm, ShouldNotBeNil)
		})

		Convey("When I try to call sync containers", func() {
			options := types.ContainerListOptions{All: true}
			containers, err := dm.(*dockerMonitor).dockerClient.ContainerList(context.Background(), options)
			if err == nil && len(containers) > 0 {
				mockSH.EXPECT().HandleSynchronization(gomock.Any(), gomock.Any(), gomock.Any(), processor.SynchronizationTypeInitial).AnyTimes().Return(nil)
				mockSH.EXPECT().HandleSynchronizationComplete(processor.SynchronizationTypeInitial).AnyTimes()
				mockPU.EXPECT().CreatePURuntime(gomock.Any(), gomock.Any()).AnyTimes().Return(nil)
				mockPU.EXPECT().HandlePUEvent(gomock.Any(), tevents.EventStart).AnyTimes().Return(nil)
				dm.SetupHandlers(&processor.Config{
					Collector:   eventCollector(),
					PUHandler:   mockPU,
					SyncHandler: mockSH,
				})
				err = dm.(*dockerMonitor).ReSync()

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
		dm := New()
		mockPU := mockprocessor.NewMockProcessingUnitsHandler(ctrl)
		mockSH := mockprocessor.NewMockSynchronizationHandler(ctrl)
		dm.SetupHandlers(&processor.Config{
			Collector:   eventCollector(),
			PUHandler:   mockPU,
			SyncHandler: mockSH,
		})
		err := dm.SetupConfig(nil, &Config{
			EventMetadataExtractor: testDockerMetadataExtractor,
		})
		So(err, ShouldBeNil)

		Convey("Then docker monitor should not be nil", func() {
			So(dm, ShouldNotBeNil)
		})

		Convey("When I try to call extractmetadata with nil docker info", func() {

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, pingerr := dm.(*dockerMonitor).dockerClient.Ping(ctx)
			if pingerr != nil {
				err := dm.(*dockerMonitor).Start()
				Convey("I should get error", func() {
					So(err, ShouldResemble, errors.New("docker daemon not running"))
				})
			} else {

				err := dm.(*dockerMonitor).Start()
				Convey("I should not get error", func() {
					So(err, ShouldBeNil)
				})
			}
		})
	})

	Convey("When I try to initialize a new docker monitor", t, func() {
		dm := New()
		mockPU := mockprocessor.NewMockProcessingUnitsHandler(ctrl)
		mockSH := mockprocessor.NewMockSynchronizationHandler(ctrl)
		dm.SetupHandlers(&processor.Config{
			Collector:   eventCollector(),
			PUHandler:   mockPU,
			SyncHandler: mockSH,
		})
		err := dm.SetupConfig(nil, &Config{
			EventMetadataExtractor: testDockerMetadataExtractor,
		})
		So(err, ShouldBeNil)

		Convey("Then docker monitor should not be nil", func() {
			So(dm, ShouldNotBeNil)
		})

		Convey("When I try to call extractmetadata with nil docker info", func() {
			options := types.ContainerListOptions{All: true}
			containers, err := dm.(*dockerMonitor).dockerClient.ContainerList(context.Background(), options)
			if err == nil && len(containers) > 0 {
				mockPU.EXPECT().CreatePURuntime(gomock.Any(), gomock.Any()).AnyTimes().Return(nil)
				mockPU.EXPECT().HandlePUEvent(gomock.Any(), tevents.EventStart).AnyTimes().Return(nil)
				mockSH.EXPECT().HandleSynchronization(gomock.Any(), tevents.StateStarted, gomock.Any(), processor.SynchronizationTypeInitial)
				mockSH.EXPECT().HandleSynchronizationComplete(gomock.Any())
				dm.SetupHandlers(&processor.Config{
					Collector:   eventCollector(),
					PUHandler:   mockPU,
					SyncHandler: mockSH,
				})
				err := dm.(*dockerMonitor).Start()

				Convey("I should not get any error", func() {
					So(err, ShouldBeNil)
				})
			}
		})
	})
}
