package nfqparser

import "fmt"

// NFQLayout is the layout of /proc/net/netfilter/nfnetlink_queue
type NFQLayout struct {
	QueueNum string
	// process ID of software listening to the queue
	PeerPortID string
	// current number of packets waiting in the queue
	QueueTotal string
	// 0 and 1 only message only provide meta data. If 2, the message provides a part of packet of size copy range.
	CopyMode string
	// length of packet data to put in message
	CopyRange string
	// number of packets dropped because queue was full
	QueueDropped string
	// number of packets dropped because netlink message could not be sent to userspace.
	// If this counter is not zero, try to increase netlink buffer size. On the application side,
	// you will see gap in packet id if netlink message are lost.
	UserDropped string
	// packet id of last packet
	IDSequence string
}

//  String returns string representation of particular queue
func (n *NFQLayout) String() string {

	if n == nil {
		return ""
	}

	return fmt.Sprintf("%v", *n)
}
