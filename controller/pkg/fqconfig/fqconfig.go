package fqconfig

// FilterQueue captures the runtime configuration like the number of queues, dns servers.
type FilterQueue interface {
	GetNumQueues() int
	GetDNSServerAddresses() []string
}

type filterQueue struct {
	//NumNFQueues
	numNFQueues int
	// DNSServerAddress
	DNSServerAddress []string
}

// NewFilterQueue returns an instance of FilterQueue
func NewFilterQueue(numNFQueues int, dnsServerAddress []string) FilterQueue {
	return &filterQueue{
		numNFQueues:      numNFQueues,
		DNSServerAddress: dnsServerAddress,
	}
}

// GetMarkValue returns a mark value to be used by iptables action
func (f *filterQueue) GetNumQueues() int {
	return f.numNFQueues
}

func (f *filterQueue) GetDNSServerAddresses() []string {
	return f.DNSServerAddress
}
