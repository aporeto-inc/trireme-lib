package cleaner

import (
	"fmt"

	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/supervisor/iptablesctrl"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/controller/runtime"
)

// CleanAllTriremeACLs cleans up all previous Trireme ACLs. It can be called from
// other packages for housekeeping.
func CleanAllTriremeACLs() error {
	ipt, err := iptablesctrl.NewInstance(fqconfig.NewFilterQueueWithDefaults(), constants.LocalServer, &runtime.Configuration{})
	if err != nil {
		return fmt.Errorf("unable to initialize cleaning iptables controller:  %s", err)
	}

	return ipt.CleanUp()
}
