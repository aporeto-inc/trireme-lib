package enforcer

// Go libraries
import (
	"fmt"
	"os/exec"
	"time"

	"go.uber.org/zap"

	"github.com/aporeto-inc/netlink-go/conntrack"
	"github.com/aporeto-inc/trireme/cache"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/enforcer/pucontext"
	"github.com/aporeto-inc/trireme/enforcer/utils/fqconfig"
	"github.com/aporeto-inc/trireme/enforcer/utils/secrets"
	"github.com/aporeto-inc/trireme/enforcer/utils/tokens"
	"github.com/aporeto-inc/trireme/policy"
)

// DefaultExternalIPTimeout is the default used for the cache for External IPTimeout.
const DefaultExternalIPTimeout = "500ms"

// Datapath is the structure holding all information about a connection filter
type Datapath struct {

	// Configuration parameters
	filterQueue    *fqconfig.FilterQueue
	tokenEngine    tokens.TokenEngine
	collector      collector.EventCollector
	service        PacketProcessor
	secrets        secrets.Secrets
	nflogger       nfLogger
	procMountPoint string

	// Internal structures and caches
	// Key=ContextId Value=ContainerIP
	contextTracker cache.DataStore
	puFromIP       cache.DataStore
	puFromMark     cache.DataStore
	puFromPort     cache.DataStore

	// Hash based on source IP/Port to capture SynAck packets with possible NAT.
	// When a new connection is created, we has the source IP/port. A return
	// poacket might come with a different source IP NAT is done later.
	// If we don't receife a return SynAck in 20 seconds, it expires
	sourcePortConnectionCache cache.DataStore

	// Hash on full five-tuple and return the connection
	// These are auto-expired connections after 60 seconds of inactivity.
	appOrigConnectionTracker  cache.DataStore
	appReplyConnectionTracker cache.DataStore
	netOrigConnectionTracker  cache.DataStore
	netReplyConnectionTracker cache.DataStore

	// CacheTimeout used for Trireme auto-detecion
	externalIPCacheTimeout time.Duration

	// connctrack handle
	conntrackHdl conntrack.Conntrack

	// mode captures the mode of the enforcer
	mode constants.ModeType

	// stop signals
	netStop []chan bool
	appStop []chan bool

	// ack size
	ackSize uint32

	mutualAuthorization bool
}

// New will create a new data path structure. It instantiates the data stores
// needed to track sessions. The data path is started with a different call.
// Only required parameters must be provided. Rest a pre-populated with defaults.
func New(
	mutualAuth bool,
	filterQueue *fqconfig.FilterQueue,
	collector collector.EventCollector,
	service PacketProcessor,
	secrets secrets.Secrets,
	serverID string,
	validity time.Duration,
	mode constants.ModeType,
	procMountPoint string,
	externalIPCacheTimeout time.Duration,
) PolicyEnforcer {

	if externalIPCacheTimeout <= 0 {
		var err error
		externalIPCacheTimeout, err = time.ParseDuration(DefaultExternalIPTimeout)
		if err != nil {
			externalIPCacheTimeout = time.Second
		}
	}

	if mode == constants.RemoteContainer || mode == constants.LocalServer {
		// Make conntrack liberal for TCP

		sysctlCmd, err := exec.LookPath("sysctl")
		if err != nil {
			zap.L().Fatal("sysctl command must be installed", zap.Error(err))
		}

		cmd := exec.Command(sysctlCmd, "-w", "net.netfilter.nf_conntrack_tcp_be_liberal=1")
		if err := cmd.Run(); err != nil {
			zap.L().Fatal("Failed to set conntrack options", zap.Error(err))
		}

	}

	tokenEngine, err := tokens.NewJWT(validity, serverID, secrets)
	if err != nil {
		zap.L().Fatal("Unable to create TokenEngine in enforcer", zap.Error(err))
	}

	d := &Datapath{
		puFromIP:   cache.NewCache(),
		puFromMark: cache.NewCache(),
		puFromPort: cache.NewCache(),

		contextTracker: cache.NewCache(),

		sourcePortConnectionCache: cache.NewCacheWithExpiration(time.Second * 24),
		appOrigConnectionTracker:  cache.NewCacheWithExpiration(time.Second * 24),
		appReplyConnectionTracker: cache.NewCacheWithExpiration(time.Second * 24),
		netOrigConnectionTracker:  cache.NewCacheWithExpiration(time.Second * 24),
		netReplyConnectionTracker: cache.NewCacheWithExpiration(time.Second * 24),
		externalIPCacheTimeout:    externalIPCacheTimeout,
		filterQueue:               filterQueue,
		mutualAuthorization:       mutualAuth,
		service:                   service,
		collector:                 collector,
		tokenEngine:               tokenEngine,
		secrets:                   secrets,
		ackSize:                   secrets.AckSize(),
		mode:                      mode,
		procMountPoint:            procMountPoint,
		conntrackHdl:              conntrack.NewHandle(),
	}

	if d.tokenEngine == nil {
		zap.L().Fatal("Unable to create enforcer")
	}

	d.nflogger = newNFLogger(11, 10, d.puInfoDelegate, collector)

	return d
}

// NewWithDefaults create a new data path with most things used by default
func NewWithDefaults(
	serverID string,
	collector collector.EventCollector,
	service PacketProcessor,
	secrets secrets.Secrets,
	mode constants.ModeType,
	procMountPoint string,
) PolicyEnforcer {

	if collector == nil {
		zap.L().Fatal("Collector must be given to NewDefaultDatapathEnforcer")
	}

	defaultMutualAuthorization := false
	defaultFQConfig := fqconfig.NewFilterQueueWithDefaults()
	defaultValidity := time.Hour * 8760
	defaultExternalIPCacheTimeout, err := time.ParseDuration(DefaultExternalIPTimeout)
	if err != nil {
		defaultExternalIPCacheTimeout = time.Second
	}

	return New(
		defaultMutualAuthorization,
		defaultFQConfig,
		collector,
		service,
		secrets,
		serverID,
		defaultValidity,
		mode,
		procMountPoint,
		defaultExternalIPCacheTimeout,
	)
}

// Enforce implements the Enforce interface method and configures the data path for a new PU
func (d *Datapath) Enforce(contextID string, puInfo *policy.PUInfo) error {

	// Always create a new PU context
	pu, err := pucontext.NewPU(contextID, puInfo, d.externalIPCacheTimeout)
	if err != nil {
		return err
	}

	// Cache PUs for retrieval based on packet information
	if pu.Type() == constants.LinuxProcessPU {
		mark, ports := pu.GetProcessKeys()
		d.puFromMark.AddOrUpdate(mark, pu)
		for _, port := range ports {
			d.puFromPort.AddOrUpdate(port, pu)
		}
	} else {
		if ip, ok := puInfo.Runtime.DefaultIPAddress(); ok {
			d.puFromIP.AddOrUpdate(ip, pu)
		} else {
			d.puFromIP.AddOrUpdate(DefaultNetwork, pu)
		}
	}

	// Cache PU from contextID for management and policy updates
	d.contextTracker.AddOrUpdate(contextID, pu)

	return nil
}

// Unenforce removes the configuration for the given PU
func (d *Datapath) Unenforce(contextID string) error {

	puContext, err := d.contextTracker.Get(contextID)
	if err != nil {
		return fmt.Errorf("ContextID not found in Enforcer")
	}

	pu := puContext.(*pucontext.PU)
	if err := d.puFromIP.Remove(pu.IP()); err != nil {
		zap.L().Warn("Unable to remove cache entry during unenforcement",
			zap.String("IP", pu.IP()),
			zap.Error(err),
		)
	}

	if err := d.puFromIP.Remove(pu.Mark()); err != nil {
		zap.L().Warn("Unable to remove cache entry during unenforcement",
			zap.String("Mark", pu.Mark()),
			zap.Error(err),
		)
	}

	for _, port := range pu.Ports() {
		if err := d.puFromIP.Remove(port); err != nil {
			zap.L().Warn("Unable to remove cache entry during unenforcement",
				zap.String("Port", port),
				zap.Error(err),
			)
		}
	}

	if err := d.contextTracker.RemoveWithDelay(contextID, 10*time.Second); err != nil {
		zap.L().Warn("Unable to remove context from cache",
			zap.String("contextID", contextID),
			zap.Error(err),
		)
	}

	return nil
}

// GetFilterQueue returns the filter queues used by the data path
func (d *Datapath) GetFilterQueue() *fqconfig.FilterQueue {

	return d.filterQueue
}

// Start starts the application and network interceptors
func (d *Datapath) Start() error {

	zap.L().Debug("Start enforcer", zap.Int("mode", int(d.mode)))
	if d.service != nil {
		d.service.Initialize(d.secrets, d.filterQueue)
	}

	d.startApplicationInterceptor()
	d.startNetworkInterceptor()

	go d.nflogger.start()

	return nil
}

// Stop stops the enforcer
func (d *Datapath) Stop() error {

	zap.L().Debug("Stoping enforcer")

	for i := uint16(0); i < d.filterQueue.GetNumApplicationQueues(); i++ {
		d.appStop[i] <- true
	}

	for i := uint16(0); i < d.filterQueue.GetNumNetworkQueues(); i++ {
		d.netStop[i] <- true
	}

	d.nflogger.stop()

	return nil
}

func (d *Datapath) puInfoDelegate(contextID string) (ID string, tags *policy.TagStore) {

	item, err := d.contextTracker.Get(contextID)
	if err != nil {
		return
	}

	ctx := item.(*pucontext.PU)

	ID = ctx.ManagementID()
	tags = ctx.Annotations().Copy()

	return
}
