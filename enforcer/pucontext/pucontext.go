package pucontext

import (
	"sync"
	"time"

	"github.com/aporeto-inc/trireme-lib/utils/cache"
	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/enforcer/acls"
	"github.com/aporeto-inc/trireme-lib/enforcer/lookup"
	"github.com/aporeto-inc/trireme-lib/policy"
)

// PUContext holds data indexed by the PU ID
type PUContext struct {
	ID                string
	ManagementID      string
	Identity          *policy.TagStore
	Annotations       *policy.TagStore
	AcceptTxtRules    *lookup.PolicyDB
	RejectTxtRules    *lookup.PolicyDB
	AcceptRcvRules    *lookup.PolicyDB
	RejectRcvRules    *lookup.PolicyDB
	ApplicationACLs   *acls.ACLCache
	NetworkACLS       *acls.ACLCache
	ExternalIPCache   cache.DataStore
	Extension         interface{}
	IP                string
	Mark              string
	ProxyPort         string
	Ports             []string
	PUType            constants.PUType
	SynToken          []byte
	SynServiceContext []byte
	SynExpiration     time.Time
	sync.Mutex
}
