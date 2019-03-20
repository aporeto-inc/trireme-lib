import (
	"fmt"

	"github.com/aporeto-inc/go-ipset/ipset"
	provider "go.aporeto.io/trireme-lib/controller/pkg/aclprovider"
	"go.aporeto.io/trireme-lib/controller/runtime"
)

// SetTargetNetworks updates ths target networks. There are three different
// types of target networks:
//   - TCPTargetNetworks for TCP traffic (by default 0.0.0.0/0)
//   - UDPTargetNetworks for UDP traffic (by default empty)
//   - ExcludedNetworks that are always ignored (by default empty)

const (
	ipv4 = "ipv4"
)

var ipsetV4Param *ipset.Params

func init() {
	ipsetV4Param = &ipset.Params{}
}

func (i *Instance) setupIPv4(cfg) {

	iptv4, err := provider.NewGoIPTablesProviderV4([]string{"mangle"})
	if err != nil {
		return nil, fmt.Errorf("unable to initialize iptables provider: %s", err)
	}

	// Create all the basic target sets. These are the global target sets
	// that do not depend on policy configuration. If they already exist
	// we will delete them and start again.
	ips := provider.NewGoIPsetProvider()

	targetTCPSet, targetUDPSet, excludedSet, err := createGlobalSets(ipv4, ips, ipsetV4Param)
	if err != nil {
		return fmt.Errorf("unable to create global sets: %s", err)
	}

	filterV4Ips(cfg)
	if err := i.updateAllTargetNetworks(i.iptInstance.cfg, &runtime.Configuration{}); err != nil {
		// If there is a failure try to clean up on exit.
		i.iptInstance.ipset.DestroyAll(chainPrefix) // nolint errcheck
		return fmt.Errorf("unable to initialize target networks: %s", err)
	}

	return &iptablesInstance{
		ipt:                iptv4,
		ipset:              ips,
		targetTCPSet:       targetTCPSet,
		targetUDPSet:       targetUDPSet,
		excludedNetworkSet: excludedSet,
		cfg:                cfg,
	}
}

func (i *Instance) SetTargetNetworks(c *runtime.Configuration) error {

	if c == nil {
		return nil
	}

	cfg := c.DeepCopy()

	var oldConfig *runtime.Configuration
	if i.iptInstance.cfg == nil {
		oldConfig = &runtime.Configuration{}
	} else {
		oldConfig = i.iptInstance.cfg.DeepCopy()
	}

	// If there are no target networks, capture all traffic
	if len(cfg.TCPTargetNetworks) == 0 {
		cfg.TCPTargetNetworks = []string{"0.0.0.0/1", "128.0.0.0/1"}
	}

	if err := i.updateAllTargetNetworks(cfg, oldConfig); err != nil {
		return err
	}

	i.iptInstance.cfg = cfg

	return nil
}
