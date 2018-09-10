package fqconfig

type filterQueueAccessor struct {
	direction string
	fqconfig  *FilterQueue
}

// NewFilterQueueAccessor accessor to extract values depending on direction
func NewFilterQueueAccessor(fqconfig *FilterQueue, direction string) FilterQueueAccessor {
	return &filterQueueAccessor{
		direction: direction,
		fqconfig:  fqconfig,
	}
}

//GetNumQueues return number of queues
func (f *filterQueueAccessor) GetNumQueues() uint16 {
	if f.direction == "network" {
		return f.fqconfig.GetNumNetworkQueues()
	}

	return f.fqconfig.GetNumApplicationQueues()

}

// GetMarkValue return the markvalue
func (f *filterQueueAccessor) GetMarkValue() int {
	return f.fqconfig.GetMarkValue()

}

// GetQueueStart returns the first queue index
func (f *filterQueueAccessor) GetQueueStart() uint16 {
	if f.direction == "network" {
		return f.fqconfig.GetNetworkQueueStart()
	}

	return f.fqconfig.GetApplicationQueueStart()
}

// GetQueueSize returns the queue size
func (f *filterQueueAccessor) GetQueueSize() uint32 {
	if f.direction == "network" {
		return f.fqconfig.GetNetworkQueueSize()
	}

	return f.fqconfig.GetApplicationQueueSize()
}

// GetQueueSynStr returns the queue user for syn packets are received
func (f *filterQueueAccessor) GetQueueSynStr() string {
	if f.direction == "network" {
		return f.fqconfig.GetNetworkQueueSynStr()
	}

	return f.fqconfig.GetApplicationQueueSynStr()

}

// GetQueueAckStr return the queue used for ack packets
func (f *filterQueueAccessor) GetQueueAckStr() string {
	if f.direction == "network" {
		return f.fqconfig.GetNetworkQueueAckStr()
	}

	return f.fqconfig.GetApplicationQueueAckStr()
}

// GetQueueSynAckStr returns the queue used for synack packets
func (f *filterQueueAccessor) GetQueueSynAckStr() string {
	if f.direction == "network" {
		return f.fqconfig.GetNetworkQueueSynAckStr()
	}

	return f.fqconfig.GetApplicationQueueSynAckStr()
}

// GetQueueSvcStr returns the queue used by service packets
func (f *filterQueueAccessor) GetQueueSvcStr() string {
	if f.direction == "network" {
		return f.fqconfig.GetNetworkQueueSvcStr()
	}

	return f.fqconfig.GetApplicationQueueSvcStr()
}
