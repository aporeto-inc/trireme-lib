package enforcer

import (
	"sync"
	"time"

	"github.com/aporeto-inc/trireme-lib/cache"
	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/enforcer/acls"
	"github.com/aporeto-inc/trireme-lib/enforcer/connection"
	"github.com/aporeto-inc/trireme-lib/enforcer/lookup"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/fqconfig"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/packet"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/secrets"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/tokens"
	"github.com/aporeto-inc/trireme-lib/policy"
)

// PublicKeyAdder register a publicKey for a Node.
type PublicKeyAdder interface {

	// PublicKeyAdd adds the given cert for the given host.
	PublicKeyAdd(host string, cert []byte) error
}

// PacketProcessor is an interface implemented to stitch into our enforcer
type PacketProcessor interface {
	// Initialize  initializes the secrets of the processor
	Initialize(s secrets.Secrets, fq *fqconfig.FilterQueue)

	// PreProcessTCPAppPacket will be called for application packets and return value of false means drop packet.
	PreProcessTCPAppPacket(p *packet.Packet, context *PUContext, conn *connection.TCPConnection) bool

	// PostProcessTCPAppPacket will be called for application packets and return value of false means drop packet.
	PostProcessTCPAppPacket(p *packet.Packet, action interface{}, context *PUContext, conn *connection.TCPConnection) bool

	// PreProcessTCPNetPacket will be called for network packets and return value of false means drop packet
	PreProcessTCPNetPacket(p *packet.Packet, context *PUContext, conn *connection.TCPConnection) bool

	// PostProcessTCPNetPacket will be called for network packets and return value of false means drop packet
	PostProcessTCPNetPacket(p *packet.Packet, action interface{}, claims *tokens.ConnectionClaims, context *PUContext, conn *connection.TCPConnection) bool
}

// PUContext holds data indexed by the PU ID
type PUContext struct {
	ID              string
	ManagementID    string
	Identity        *policy.TagStore
	Annotations     *policy.TagStore
	AcceptTxtRules  *lookup.PolicyDB
	RejectTxtRules  *lookup.PolicyDB
	AcceptRcvRules  *lookup.PolicyDB
	RejectRcvRules  *lookup.PolicyDB
	ApplicationACLs *acls.ACLCache
	NetworkACLS     *acls.ACLCache
	externalIPCache cache.DataStore
	Extension       interface{}
	IP              string
	Mark            string
	ProxyPort       string
	Ports           []string
	PUType          constants.PUType
	synToken        []byte
	synExpiration   time.Time
	sync.Mutex
}
