package supervisor

import (
	"fmt"
	"strconv"

	log "github.com/Sirupsen/logrus"

	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/policy"
)

const appSet = "TriremeSet"

type ipsetSupervisor struct {
	ipt               IptablesProvider
	collector         collector.EventCollector
	networkQueues     string
	applicationQueues string
	targetNetworks    []string
	triremeSet        IpsetProvider
}

// NewIPSetSupervisor returns a new implementation of the Supervisor based on IPSets.
func NewIPSetSupervisor(collector collector.EventCollector, enforcer enforcer.PolicyEnforcer, iptablesProvider IptablesProvider, targetNetworks []string) (Supervisor, error) {
	if collector == nil {
		log.WithFields(log.Fields{
			"package": "supervisor",
		}).Error("Collector cannot be nil in NewIPSetSupervisor")

		return nil, fmt.Errorf("Collector cannot be nil")
	}

	if enforcer == nil {
		log.WithFields(log.Fields{
			"package": "supervisor",
		}).Error("Enforcer cannot be nil in NewIPSetSupervisor")

		return nil, fmt.Errorf("Enforcer cannot be nil")
	}

	if targetNetworks == nil {
		log.WithFields(log.Fields{
			"package": "supervisor",
		}).Error("TargetNetworks cannot be nil in NewIPSetSupervisor")

		return nil, fmt.Errorf("TargetNetworks cannot be nil")
	}

	filterQueue := enforcer.GetFilterQueue()

	if filterQueue == nil {
		log.WithFields(log.Fields{
			"package":  "supervisor",
			"enforcer": enforcer,
		}).Error("Enforcer FilterQueues cannot be nil in NewIPSetSupervisor")

		return nil, fmt.Errorf("Enforcer FilterQueues cannot be nil")
	}

	s := &ipsetSupervisor{
		targetNetworks:    targetNetworks,
		collector:         collector,
		networkQueues:     strconv.Itoa(int(filterQueue.NetworkQueue)) + ":" + strconv.Itoa(int(filterQueue.NetworkQueue+filterQueue.NumberOfNetworkQueues-1)),
		applicationQueues: strconv.Itoa(int(filterQueue.ApplicationQueue)) + ":" + strconv.Itoa(int(filterQueue.ApplicationQueue+filterQueue.NumberOfApplicationQueues-1)),
	}

	s.ipt = iptablesProvider

	return s, nil
}

func (s *ipsetSupervisor) Supervise(contextID string, containerInfo *policy.PUInfo) error {
	return nil
}

func (s *ipsetSupervisor) Unsupervise(contextID string) error {
	return nil
}

func (s *ipsetSupervisor) Start() error {
	return nil
}

func (s *ipsetSupervisor) Stop() error {
	return nil
}

func (s *ipsetSupervisor) createInitialConfig() error {
	return nil
}

func (s *ipsetSupervisor) cleanACLs() error {
	return nil
}

func (s *ipsetSupervisor) AddExcludedIP(ip string) error {
	return nil
}

func (s *ipsetSupervisor) RemoveExcludedIP(ip string) error {
	return nil
}
