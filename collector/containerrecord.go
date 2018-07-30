package collector

import (
	"go.aporeto.io/trireme-lib/policy"
)

// Container event description
const (
	// ContainerStart indicates a container start event
	ContainerStart = "start"
	// ContainerStop indicates a container stop event
	ContainerStop = "stop"
	// ContainerCreate indicates a container create event
	ContainerCreate = "create"
	// ContainerDelete indicates a container delete event
	ContainerDelete = "delete"
	// ContainerUpdate indicates a container policy update event
	ContainerUpdate = "update"
	// ContainerFailed indicates an event that a container was stopped because of policy issues
	ContainerFailed = "forcestop"
	// ContainerIgnored indicates that the container will be ignored by Trireme
	ContainerIgnored = "ignore"
	// ContainerDeleteUnknown indicates that policy for an unknown  container was deleted
	ContainerDeleteUnknown = "unknowncontainer"
)

// ContainerRecord is a statistics record for a container
type ContainerRecord struct {
	ContextID string
	IPAddress policy.ExtendedMap
	Tags      *policy.TagStore
	Event     string
}
