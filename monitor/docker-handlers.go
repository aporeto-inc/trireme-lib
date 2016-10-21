package monitor

import (
	"context"
	"fmt"
	"time"

	"github.com/aporeto-inc/trireme/eventlog"
	"github.com/docker/docker/api/types/events"
	"github.com/golang/glog"
)

//handleStartEvent will notify the agent immediately about the event in order
//to start the implementation of the functions. The agent must query
//the policy engine for details on what to do with this container.
func (d *dockerMonitor) handleStartEvent(event *events.Message) error {

	timeout := time.Second * 0
	id := event.ID

	info, err := d.dockerClient.ContainerInspect(context.Background(), id)
	if err != nil {
		glog.V(2).Infoln("Killing container because inspect returned error")
		//If we see errors, we will kill the container for security reasons.
		d.dockerClient.ContainerStop(context.Background(), id, &timeout)
		d.Logger.ContainerEvent(id[:12], "", nil, eventlog.ContainerFailed)
		return fmt.Errorf("Cannot read container information. Killing container. ")
	}

	if err := d.addOrUpdateDockerContainer(&info); err != nil {
		glog.V(2).Infof("Error while trying to add container: %s", err)
		return err
	}
	return nil
}

//handleDie event is called when a container dies. It updates the agent
//data structures and stops enforcement.
func (d *dockerMonitor) handleDieEvent(event *events.Message) error {

	containerID := event.ID

	d.removeDockerContainer(containerID)
	d.Logger.ContainerEvent(containerID[:12], "", nil, eventlog.ContainerStop)

	return nil
}

// handleDestroyEvent handles destroy events from Docker
func (d *dockerMonitor) handleDestroyEvent(event *events.Message) error {
	containerID := event.ID
	// Clear the policy cache
	d.PUHandler.HandleDelete(containerID[:12])
	d.Logger.ContainerEvent(containerID[:12], "", nil, eventlog.UnknownContainerDelete)

	return nil
}

func (d *dockerMonitor) handleNetworkConnectEvent(event *events.Message) error {

	id := event.Actor.Attributes["container"]

	container, err := d.dockerClient.ContainerInspect(context.Background(), id)
	if err != nil {
		glog.V(2).Infoln("Failed to read the affected container.")
	}
	glog.V(5).Infoln(container)
	return nil
}
