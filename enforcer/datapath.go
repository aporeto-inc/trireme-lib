package enforcer

// Go libraries
import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme/cache"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/enforcer/utils/fqconfig"
	"github.com/aporeto-inc/trireme/enforcer/utils/secrets"
	"github.com/aporeto-inc/trireme/enforcer/utils/tokens"
	"github.com/aporeto-inc/trireme/monitor/linuxmonitor/cgnetcls"
	"github.com/aporeto-inc/trireme/policy"
)

// InterfaceStats for interface
type InterfaceStats struct {
	IncomingPackets     uint32
	OutgoingPackets     uint32
	ProtocolDropPackets uint32
	CreateDropPackets   uint32
}

// PacketStats for interface
type PacketStats struct {
	IncomingPackets        uint32
	OutgoingPackets        uint32
	AuthDropPackets        uint32
	ServicePreDropPackets  uint32
	ServicePostDropPackets uint32
}

// Datapath is the structure holding all information about a connection filter
type Datapath struct {

	// Configuration parameters
	filterQueue    *fqconfig.FilterQueue
	tokenEngine    tokens.TokenEngine
	collector      collector.EventCollector
	service        PacketProcessor
	secrets        secrets.Secrets
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

	// stats
	net    InterfaceStats
	app    InterfaceStats
	netTCP PacketStats
	appTCP PacketStats

	// mode captures the mode of the enforcer
	mode constants.ModeType

	// stop signals
	netStop []chan bool
	appStop []chan bool

	// ack size
	ackSize uint32

	mutualAuthorization bool

	sync.Mutex
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
) PolicyEnforcer {

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

	fmt.Printf("Initializing remote with fq %+v", filterQueue)
	d := &Datapath{
		puFromIP:   cache.NewCache(),
		puFromMark: cache.NewCache(),
		puFromPort: cache.NewCache(),

		contextTracker: cache.NewCache(),

		sourcePortConnectionCache: cache.NewCacheWithExpiration(time.Second * 60),
		appOrigConnectionTracker:  cache.NewCacheWithExpiration(time.Second * 60),
		appReplyConnectionTracker: cache.NewCacheWithExpiration(time.Second * 60),
		netOrigConnectionTracker:  cache.NewCacheWithExpiration(time.Second * 60),
		netReplyConnectionTracker: cache.NewCacheWithExpiration(time.Second * 60),
		filterQueue:               filterQueue,
		mutualAuthorization:       mutualAuth,
		service:                   service,
		collector:                 collector,
		tokenEngine:               tokenEngine,
		secrets:                   secrets,
		net:                       InterfaceStats{},
		app:                       InterfaceStats{},
		netTCP:                    PacketStats{},
		appTCP:                    PacketStats{},
		ackSize:                   secrets.AckSize(),
		mode:                      mode,
		procMountPoint:            procMountPoint,
	}

	if d.tokenEngine == nil {
		zap.L().Fatal("Unable to create enforcer")
	}

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

	mutualAuthorization := false
	fqConfig := fqconfig.NewFilterQueueWithDefaults()

	validity := time.Hour * 8760

	return New(
		mutualAuthorization,
		fqConfig,
		collector,
		service,
		secrets,
		serverID,
		validity,
		mode,
		procMountPoint,
	)
}

// Enforce implements the Enforce interface method and configures the data path for a new PU
func (d *Datapath) Enforce(contextID string, puInfo *policy.PUInfo) error {

	puContext, err := d.contextTracker.Get(contextID)
	if err != nil {
		return d.doCreatePU(contextID, puInfo)
	}

	return d.doUpdatePU(puContext.(*PUContext), puInfo)
}

// Unenforce removes the configuration for the given PU
func (d *Datapath) Unenforce(contextID string) error {

	puContext, err := d.contextTracker.Get(contextID)
	if err != nil {
		return fmt.Errorf("ContextID not found in Enforcer")
	}

	puContext.(*PUContext).Lock()
	defer puContext.(*PUContext).Unlock()

	pu := puContext.(*PUContext)
	if err := d.puFromIP.Remove(pu.IP); err != nil {
		zap.L().Warn("Unable to remove cache entry during unenforcement",
			zap.String("IP", pu.IP),
			zap.Error(err),
		)
	}

	if err := d.puFromIP.Remove(pu.Mark); err != nil {
		zap.L().Warn("Unable to remove cache entry during unenforcement",
			zap.String("Mark", pu.Mark),
			zap.Error(err),
		)
	}

	for _, port := range pu.Ports {
		if err := d.puFromIP.Remove(port); err != nil {
			zap.L().Warn("Unable to remove cache entry during unenforcement",
				zap.String("Port", port),
				zap.Error(err),
			)
		}
	}

	if err := d.contextTracker.Remove(contextID); err != nil {
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

	return nil
}

func (d *Datapath) getProcessKeys(puInfo *policy.PUInfo) (string, []string) {

	mark, ok := puInfo.Runtime.Options().Get(cgnetcls.CgroupMarkTag)
	if !ok {
		mark = ""
	}

	ports, ok := puInfo.Runtime.Options().Get(cgnetcls.PortTag)
	if !ok {
		ports = "0"
	}

	portlist := strings.Split(ports, ",")

	return mark, portlist
}

func (d *Datapath) doCreatePU(contextID string, puInfo *policy.PUInfo) error {

	ip, ok := puInfo.Runtime.DefaultIPAddress()
	if !ok {
		if d.mode == constants.LocalContainer {
			return fmt.Errorf("No IP provided for Local Container")
		}
		ip = DefaultNetwork
	}

	pu := &PUContext{
		ID:           contextID,
		ManagementID: puInfo.Policy.ManagementID,
		PUType:       puInfo.Runtime.PUType(),
		IP:           ip,
	}

	// Cache PUs for retrieval based on packet information
	if pu.PUType == constants.LinuxProcessPU {
		pu.Mark, pu.Ports = d.getProcessKeys(puInfo)
		d.puFromMark.AddOrUpdate(pu.Mark, pu)
		for _, port := range pu.Ports {
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

	return d.doUpdatePU(pu, puInfo)
}

func (d *Datapath) doUpdatePU(puContext *PUContext, containerInfo *policy.PUInfo) error {

	puContext.Lock()
	defer puContext.Unlock()

	puContext.AcceptRcvRules, puContext.RejectRcvRules = createRuleDBs(containerInfo.Policy.ReceiverRules())

	puContext.AcceptTxtRules, puContext.RejectTxtRules = createRuleDBs(containerInfo.Policy.TransmitterRules())

	puContext.Identity = containerInfo.Policy.Identity()

	puContext.Annotations = containerInfo.Policy.Annotations()

	return nil
}
