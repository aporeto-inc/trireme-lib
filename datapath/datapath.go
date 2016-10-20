package datapath

// Go libraries
import (
	"fmt"
	"os"

	"github.com/aporeto-inc/trireme/datapath/lookup"
	"github.com/aporeto-inc/trireme/datapath/netfilter"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/golang/glog"
)

// Start starts the application and network interceptors
func (d *DataPath) Start() error {

	d.StartApplicationInterceptor()

	d.StartNetworkInterceptor()

	return nil
}

// Stop stops the datapath
func (d *DataPath) Stop() error {
	return nil
}

func createRuleDB(policyRules []policy.TagSelector) *lookup.PolicyDB {

	rules := lookup.NewPolicyDB()
	for _, rule := range policyRules {
		rules.AddPolicy(rule)
	}

	return rules
}

// AddPU updates the path with the information about a new container
func (d *DataPath) AddPU(contextID string, puInfo *policy.PUInfo) error {

	rules := createRuleDB(puInfo.Policy.Rules)

	pu := &PUContext{
		ID:        contextID,
		Extension: puInfo.Policy.Extensions,
		rules:     rules,
		Tags:      puInfo.Policy.PolicyTags,
	}

	ip, _ := puInfo.Runtime.DefaultIPAddress()
	d.puTracker.AddOrUpdate(ip, pu)

	return nil
}

// UpdatePU updates a container with a new set of rules
func (d *DataPath) UpdatePU(ipaddress string, containerInfo *policy.PUInfo) error {

	container, err := d.puTracker.Get(ipaddress)
	if err != nil {
		return fmt.Errorf("Couldn't find PU in Datapath cache: %s", err)
	}

	container.(*PUContext).rules = createRuleDB(containerInfo.Policy.Rules)
	container.(*PUContext).Extension = containerInfo.Policy.Extensions
	container.(*PUContext).Tags = containerInfo.Policy.PolicyTags

	return nil
}

// DeletePU removes container information from the data path
func (d *DataPath) DeletePU(ip string) error {

	return d.puTracker.Remove(ip)

}

// StartApplicationInterceptor will create a interceptor that processes
// packets originated from a local application
func (d *DataPath) StartApplicationInterceptor() {
	var err error

	nfq := make([]*netfilter.NFQueue, d.FilterQueue.NumberOfApplicationQueues)

	for i := uint16(0); i < d.FilterQueue.NumberOfApplicationQueues; i++ {
		nfq[i], err = netfilter.NewNFQueue(d.FilterQueue.ApplicationQueue+i, d.FilterQueue.ApplicationQueueSize, netfilter.NfDefaultPacketSize, d.processApplicationPacketsFromNFQ)
		if err != nil {
			glog.Error(err, "Unable to initialize netfilter queue - Aborting")
			os.Exit(1)
		}
	}
}

// StartNetworkInterceptor will the process that processes  packets from the network
// Still has one more copy than needed. Can be improved.
func (d *DataPath) StartNetworkInterceptor() {
	var err error

	nfq := make([]*netfilter.NFQueue, d.FilterQueue.NumberOfNetworkQueues)

	for i := uint16(0); i < d.FilterQueue.NumberOfNetworkQueues; i++ {

		// Initalize all the queues
		nfq[i], err = netfilter.NewNFQueue(d.FilterQueue.NetworkQueue+i, d.FilterQueue.NetworkQueueSize, netfilter.NfDefaultPacketSize, d.processNetworkPacketsFromNFQ)
		if err != nil {
			glog.Error(err, "Unable to initialize netfilter queue - Aborting")
			os.Exit(1)
		}
	}
}
