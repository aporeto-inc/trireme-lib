package fqconfig

type FilterQueueAccessor interface {
	GetNumQueues() uint16
	GetMarkValue() int
	GetQueueStart() uint16
	GetQueueSize() uint32
	GetQueueSynStr() string
	GetQueueAckStr() string
	GetQueueSynAckStr() string
	GetQueueSvcStr() string
}
