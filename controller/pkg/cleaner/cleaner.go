package cleaner

import (
	"fmt"

	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/supervisor/iptablesctrl"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
)

// CleanAllTriremeACLs cleans up all previous Trireme ACLs. It can be called from
// other packages for housekeeping.
// TODO: fix this, this was ok before, but it's ugly now because we have to
//       injecting iptablesLockfile here..
//       iptables and it's configuration is part of trireme and iptables cleanup should
//       be done when the trireme instance starts up.
func CleanAllTriremeACLs(iptablesLockfile string) error {

	fq := fqconfig.NewFilterQueue(0, nil)

	ipt, err := iptablesctrl.NewInstance(fq, constants.LocalServer, true, nil, iptablesLockfile, policy.None)
	if err != nil {
		return fmt.Errorf("unable to initialize cleaning iptables controller: %s", err)
	}

	return ipt.CleanUp()
}
