package nfqdatapath

// Go libraries
import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"github.com/blang/semver"
	"go.aporeto.io/enforcerd/trireme-lib/collector"
	"go.aporeto.io/enforcerd/trireme-lib/common"
	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/acls"
	enforcerconstants "go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/constants"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/dnsproxy"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/nfqdatapath/afinetrawsocket"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/nfqdatapath/nflog"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/nfqdatapath/tokenaccessor"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/utils/ephemeralkeys"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/connection"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/counters"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/ebpf"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/flowtracking"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packet"
	tpacket "go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packetprocessor"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packettracing"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/enforcerd/trireme-lib/controller/runtime"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.aporeto.io/enforcerd/trireme-lib/utils/cache"
	"go.aporeto.io/enforcerd/trireme-lib/utils/portcache"
	"go.aporeto.io/enforcerd/trireme-lib/utils/portspec"
	"go.uber.org/zap"
)

// DefaultExternalIPTimeout is the default used for the cache for External IPTimeout.
const DefaultExternalIPTimeout = "500ms"

var collectCounterInterval = 30 * time.Second

// GetUDPRawSocket is placeholder for createSocket function. It is useful to mock tcp unit tests.
var GetUDPRawSocket = afinetrawsocket.CreateSocket

type debugpacketmessage struct {
	Mark    int
	p       *packet.Packet
	tcpConn *connection.TCPConnection
	udpConn *connection.UDPConnection
	err     error
	network bool
}

// Datapath is the structure holding all information about a connection filter
type Datapath struct {

	// Configuration parameters
	filterQueue    fqconfig.FilterQueue
	collector      collector.EventCollector
	tokenAccessor  tokenaccessor.TokenAccessor
	service        packetprocessor.PacketProcessor
	scrts          secrets.Secrets
	nflogger       nflog.NFLogger
	procMountPoint string

	targetNetworks *acls.ACLCache
	// Internal structures and caches
	// Key=ContextId Value=puContext
	puFromContextID cache.DataStore
	puFromMark      cache.DataStore
	puFromHash      cache.DataStore
	// hostPU is the host PU context associated with the datapath.
	// There can not be more than one host PU.
	hostPU *pucontext.PUContext

	contextIDFromTCPPort *portcache.PortCache
	contextIDFromUDPPort *portcache.PortCache
	// For remotes this is a reverse link to the context
	puFromIP *pucontext.PUContext

	//tcpClient and tcpServer is a connection cache with key being the flow hash
	// and the value being the connection object.
	tcpClient connection.TCPCache
	tcpServer connection.TCPCache

	tcpConnectionExpirationNotifier func(*connection.TCPConnection)

	udpSourcePortConnectionCache cache.DataStore

	// Hash on full five-tuple and return the connection
	// These are auto-expired connections after 60 seconds of inactivity.
	udpAppOrigConnectionTracker  cache.DataStore
	udpAppReplyConnectionTracker cache.DataStore
	udpNetOrigConnectionTracker  cache.DataStore
	udpNetReplyConnectionTracker cache.DataStore
	udpNatConnectionTracker      cache.DataStore
	udpFinPacketTracker          cache.DataStore
	// CacheTimeout used for Trireme auto-detecion
	ExternalIPCacheTimeout time.Duration

	// Packettracing Cache :: We don't mark this in pucontext since it gets recreated on every policy update and we need to persist across them
	packetTracingCache cache.DataStore

	// mode captures the mode of the enforcer
	mode constants.ModeType

	// ack size
	ackSize uint32

	// conntrack is the conntrack client
	conntrack flowtracking.FlowClient
	dnsProxy  dnsproxy.DNSProxy

	mutualAuthorization bool
	packetLogs          bool

	// udp socket fd for application.
	udpSocketWriter afinetrawsocket.SocketWriter

	puToPortsMap map[string]map[string]bool
	// bpf module
	bpf ebpf.BPFModule

	agentVersion semver.Version

	secretsLock        sync.RWMutex
	logLevelLock       sync.RWMutex
	targetNetworksLock sync.RWMutex

	// defines if serviceMesh is enabled and tells which type of serviceMesh is enabled
	serviceMeshType policy.ServiceMesh
}

type tracingCacheEntry struct {
	direction packettracing.TracingDirection
}

func createPolicy(networks []string) policy.IPRuleList {
	var rules policy.IPRuleList

	f := policy.FlowPolicy{
		Action: policy.Accept,
	}

	addresses := []string{}

	addresses = append(addresses, networks...)

	iprule := policy.IPRule{
		Addresses: addresses,
		Ports:     []string{"0:65535"},
		Protocols: []string{constants.TCPProtoNum},
		Policy:    &f,
	}

	rules = append(rules, iprule)
	return rules
}

func (d *Datapath) cachePut(cache connection.TCPCache, key string, conn *connection.TCPConnection) {
	cache.Put(key, conn)
	conn.StartTimer(func() {
		cache.Remove(key)
		d.tcpConnectionExpirationNotifier(conn)
	})
}

func (d *Datapath) cacheGet(cache connection.TCPCache, key string) (*connection.TCPConnection, bool) {
	return cache.Get(key)
}

func (d *Datapath) cacheRemove(cache connection.TCPCache, key string) {
	conn, exists := cache.Get(key)
	if exists {
		conn.StopTimer()
		cache.Remove(key)
	}
}

const waitBeforeRemovingConn = 5 * time.Second

// New will create a new data path structure. It instantiates the data stores
// needed to track sessions. The data path is started with a different call.
// Only required parameters must be provided. Rest a pre-populated with defaults.
func New(
	mutualAuth bool,
	filterQueue fqconfig.FilterQueue,
	collector collector.EventCollector,
	serverID string,
	validity time.Duration,
	secrets secrets.Secrets,
	mode constants.ModeType,
	procMountPoint string,
	ExternalIPCacheTimeout time.Duration,
	packetLogs bool,
	tokenaccessor tokenaccessor.TokenAccessor,
	puFromContextID cache.DataStore,
	cfg *runtime.Configuration,
	isBPFEnabled bool,
	agentVersion semver.Version,
	serviceMeshType policy.ServiceMesh,
) *Datapath {

	if ExternalIPCacheTimeout <= 0 {
		var err error
		ExternalIPCacheTimeout, err = time.ParseDuration(enforcerconstants.DefaultExternalIPTimeout)
		if err != nil {
			ExternalIPCacheTimeout = time.Second
		}
	}

	var bpf ebpf.BPFModule

	if isBPFEnabled {
		if bpf = ebpf.LoadBPF(); bpf != nil {
			zap.L().Info("eBPF is Enabled in the system")

			cmd := exec.Command("aporeto-conntrack", "-F")
			if err := cmd.Run(); err != nil {
				zap.L().Error("Failed to flush conntrack", zap.Error(err))
			}
		} else {
			zap.L().Info("eBPF is disabled as it is not supported")
		}
	} else {
		zap.L().Info("eBPF is disabled as it is not supported")
	}

	if mode == constants.RemoteContainer || mode == constants.LocalServer {
		// Make conntrack liberal for TCP
		adjustConntrack(mode)
	}

	contextIDFromTCPPort := portcache.NewPortCache("contextIDFromTCPPort")
	contextIDFromUDPPort := portcache.NewPortCache("contextIDFromUDPPort")

	udpSocketWriter, err := GetUDPRawSocket(afinetrawsocket.ApplicationRawSocketMark, "udp")

	if err != nil {
		zap.L().Error("Unable to create raw socket for udp packet transmission", zap.Error(err))
	}

	d := &Datapath{}
	d.puFromMark = cache.NewCache("puFromMark")
	d.puFromHash = cache.NewCache("puFromHash")
	d.contextIDFromTCPPort = contextIDFromTCPPort
	d.contextIDFromUDPPort = contextIDFromUDPPort

	d.puFromContextID = puFromContextID
	d.tcpClient = connection.NewTCPConnectionCache()
	d.tcpServer = connection.NewTCPConnectionCache()
	d.tcpConnectionExpirationNotifier = d.tcpConnectionExpirationFunc

	d.udpSourcePortConnectionCache = cache.NewCacheWithExpiration("udpSourcePortConnectionCache", time.Second*60)
	d.udpAppOrigConnectionTracker = cache.NewCacheWithExpiration("udpAppOrigConnectionTracker", time.Second*60)
	d.udpAppReplyConnectionTracker = cache.NewCacheWithExpiration("udpAppReplyConnectionTracker", time.Second*60)
	d.udpNetOrigConnectionTracker = cache.NewCacheWithExpiration("udpNetOrigConnectionTracker", time.Second*60)
	d.udpNetReplyConnectionTracker = cache.NewCacheWithExpiration("udpNetReplyConnectionTracker", time.Second*60)
	d.udpNatConnectionTracker = cache.NewCacheWithExpiration("udpNatConnectionTracker", time.Second*60)
	d.udpFinPacketTracker = cache.NewCacheWithExpiration("udpFinPacketTracker", time.Second*60)
	d.packetTracingCache = cache.NewCache("PacketTracingCache")
	d.targetNetworks = acls.NewACLCache()
	d.ExternalIPCacheTimeout = ExternalIPCacheTimeout
	d.filterQueue = filterQueue
	d.mutualAuthorization = mutualAuth
	d.collector = collector
	d.tokenAccessor = tokenaccessor
	d.scrts = secrets
	d.ackSize = secrets.AckSize()
	d.mode = mode
	d.procMountPoint = procMountPoint
	d.packetLogs = packetLogs
	d.udpSocketWriter = udpSocketWriter
	d.puToPortsMap = map[string]map[string]bool{}
	d.bpf = bpf
	d.agentVersion = agentVersion
	d.serviceMeshType = serviceMeshType

	if err = d.SetTargetNetworks(cfg); err != nil {
		zap.L().Error("Error adding target networks to the ACLs", zap.Error(err))
	}

	d.nflogger = nflog.NewNFLogger(11, 10, d.puContextDelegate, collector)

	ephemeralkeys.UpdateDatapathSecrets(secrets)

	if mode != constants.RemoteContainer {
		go d.autoPortDiscovery()
	}

	return d
}

func (d *Datapath) collectCounters() {

	keysList := d.puFromContextID.KeyList()
	for _, keys := range keysList {
		val, err := d.puFromContextID.Get(keys)
		if err != nil {
			continue
		}
		counters := val.(*pucontext.PUContext).Counters().GetErrorCounters()
		d.collector.CollectCounterEvent(
			&collector.CounterReport{
				PUID:      val.(*pucontext.PUContext).ManagementID(),
				Counters:  counters,
				Namespace: val.(*pucontext.PUContext).ManagementNamespace(),
			})
	}

	counters := counters.GetErrorCounters()
	d.collector.CollectCounterEvent(
		&collector.CounterReport{
			PUID:      "",
			Counters:  counters,
			Namespace: "",
		})
}

func (d *Datapath) counterCollector(ctx context.Context) {

	for {
		select {
		case <-ctx.Done():
			d.collectCounters()
			return
		case <-time.After(collectCounterInterval):
			d.collectCounters()
		}
	}
}

func (d *Datapath) reportErrorCounters(pu *pucontext.PUContext) {

	counters := pu.Counters().GetErrorCounters()
	d.collector.CollectCounterEvent(&collector.CounterReport{
		PUID:      pu.ManagementID(),
		Counters:  counters,
		Namespace: pu.ManagementNamespace(),
	})
}

// Enforce implements the Enforce interface method and configures the data path for a new PU
func (d *Datapath) Enforce(ctx context.Context, contextID string, puInfo *policy.PUInfo) error {
	// Always create a new PU context
	pu, err := pucontext.NewPU(contextID, puInfo, d.tokenAccessor, d.ExternalIPCacheTimeout)
	if err != nil {
		return fmt.Errorf("error creating new pu: %s", err)
	}

	// Cache PUs for retrieval based on packet information
	if pu.Type() != common.ContainerPU {

		mark, tcpPorts, udpPorts := pu.GetProcessKeys()
		d.puFromMark.AddOrUpdate(mark, pu)

		for _, port := range tcpPorts {
			if port == "0" {
				continue
			}

			portSpec, err := portspec.NewPortSpecFromString(port, contextID)
			if err != nil {
				continue
			}

			if puInfo.Runtime.PUType() == common.HostPU {
				d.contextIDFromTCPPort.AddPortSpecToEnd(portSpec)
			} else {
				d.contextIDFromTCPPort.AddPortSpec(portSpec)
			}
		}

		for _, port := range udpPorts {

			portSpec, err := portspec.NewPortSpecFromString(port, contextID)
			if err != nil {
				continue
			}

			// check for host pu and add its ports to the end.
			if puInfo.Runtime.PUType() == common.HostPU {
				d.contextIDFromUDPPort.AddPortSpecToEnd(portSpec)
				d.hostPU = pu
			} else {
				d.contextIDFromUDPPort.AddPortSpec(portSpec)
			}
		}

	} else {
		d.puFromIP = pu
	}

	oldPU, err := d.puFromContextID.Get(contextID)
	if err != nil {
		// start the dns proxy server for the first time.
		if err := d.dnsProxy.StartDNSServer(ctx, contextID, puInfo.Policy.DNSProxyPort()); err != nil {
			zap.L().Error("could not start dns server for PU", zap.String("contexID", contextID), zap.Error(err))
		}
	} else {
		old := oldPU.(*pucontext.PUContext)
		old.StopProcessing()
		d.reportErrorCounters(old)
	}
	if err := d.dnsProxy.Enforce(ctx, contextID, puInfo); err != nil {
		zap.L().Error("Unable to update dns proxy config", zap.Error(err))
	}
	// Cache PU to its contextID hash.
	d.puFromHash.AddOrUpdate(pu.HashID(), pu)

	// Cache PU from contextID for management and policy updates
	d.puFromContextID.AddOrUpdate(contextID, pu)

	if d.dnsProxy != nil {
		if err := d.dnsProxy.SyncWithPlatformCache(ctx, pu); err != nil {
			zap.L().Warn("error syncing with DNS cache", zap.Error(err))
		}
	}

	return nil
}

// Unenforce removes the configuration for the given PU
func (d *Datapath) Unenforce(ctx context.Context, contextID string) error {

	var err error

	puContext, err := d.puFromContextID.Get(contextID)
	if err != nil {
		return fmt.Errorf("contextid not found in enforcer: %s", err)
	}
	// Pu is being unenforcer. Collect its counters
	pu := puContext.(*pucontext.PUContext)
	// this context pointer is about to get lost. reclaims its counters
	d.reportErrorCounters(pu)

	// Cleanup the mark information
	if pu.Mark() != "" {
		if err = d.puFromMark.Remove(pu.Mark()); err != nil {
			zap.L().Debug("Unable to remove cache entry during unenforcement",
				zap.String("Mark", pu.Mark()),
				zap.Error(err),
			)
		}
	}

	// Cleanup the port cache
	for _, port := range pu.TCPPorts() {
		if port == "0" {
			continue
		}

		if err := d.contextIDFromTCPPort.RemoveStringPorts(port); err != nil {
			zap.L().Debug("Unable to remove cache entry during unenforcement",
				zap.String("TCPPort", port),
				zap.Error(err),
			)
		}
	}

	for _, port := range pu.UDPPorts() {
		if port == "0" {
			continue
		}

		if err := d.contextIDFromUDPPort.RemoveStringPorts(port); err != nil {
			zap.L().Debug("Unable to remove cache entry during unenforcement",
				zap.String("UDPPort", port),
				zap.Error(err),
			)
		}
	}

	// Cleanup the contextID hash cache.
	if err := d.puFromHash.RemoveWithDelay(pu.HashID(), 10*time.Second); err != nil {
		zap.L().Warn("unable to remove pucontext from hash cache",
			zap.String("hash", pu.HashID()),
			zap.Error(err),
		)
	}

	// Cleanup the contextID cache
	if err := d.puFromContextID.RemoveWithDelay(contextID, 10*time.Second); err != nil {
		zap.L().Warn("Unable to remove context from cache",
			zap.String("contextID", contextID),
			zap.Error(err),
		)
	}
	if err := d.dnsProxy.Unenforce(ctx, contextID); err != nil {
		zap.L().Warn("Unable to unenforce dnsproxy",
			zap.String("contextID", contextID),
			zap.Error(err),
		)
	}

	return nil
}

// SetTargetNetworks sets new target networks used by datapath
func (d *Datapath) SetTargetNetworks(cfg *runtime.Configuration) error {

	var err error
	networks := cfg.TCPTargetNetworks

	if len(networks) == 0 {
		networks = []string{"0.0.0.0/1", "128.0.0.0/1", "::/0"}
	}

	targetNetworks := acls.NewACLCache()
	targetacl := createPolicy(networks)

	if err = targetNetworks.AddRuleList(targetacl); err == nil {
		d.targetNetworksLock.Lock()
		d.targetNetworks = targetNetworks
		d.targetNetworksLock.Unlock()
		return nil
	}

	return err
}

// GetBPFObject returns the bpf object
func (d *Datapath) GetBPFObject() ebpf.BPFModule {
	return d.bpf
}

// GetFilterQueue returns the filter queues used by the data path
func (d *Datapath) GetFilterQueue() fqconfig.FilterQueue {

	return d.filterQueue
}

// Run starts the application and network interceptors
func (d *Datapath) Run(ctx context.Context) error {

	zap.L().Debug("Start datapath tracking and network interceptor", zap.Int("mode", int(d.mode)))

	if d.conntrack == nil {
		conntrackClient, err := flowtracking.NewClient(ctx)
		if err != nil {
			return err
		}
		d.conntrack = conntrackClient
	}

	if d.dnsProxy == nil {
		d.dnsProxy = dnsproxy.New(ctx, d.puFromContextID, d.conntrack, d.collector)
	}

	d.startInterceptors(ctx)
	go d.nflogger.Run(ctx)
	go d.counterCollector(ctx)
	return nil
}

// UpdateSecrets updates the secrets used for signing communication between trireme instances
func (d *Datapath) UpdateSecrets(s secrets.Secrets) error {

	d.secretsLock.Lock()
	d.scrts = s
	d.secretsLock.Unlock()

	ephemeralkeys.UpdateDatapathSecrets(s)
	return nil
}

func (d *Datapath) secrets() secrets.Secrets {

	d.secretsLock.RLock()
	defer d.secretsLock.RUnlock()

	return d.scrts
}

// PacketLogsEnabled returns true if the packet logs are enabled.
func (d *Datapath) PacketLogsEnabled() bool {
	d.logLevelLock.RLock()
	defer d.logLevelLock.RUnlock()

	return d.packetLogs
}

// SetLogLevel sets log level.
func (d *Datapath) SetLogLevel(level constants.LogLevel) error {

	d.logLevelLock.Lock()
	defer d.logLevelLock.Unlock()

	d.packetLogs = false
	if level == constants.Trace {
		d.packetLogs = true
	}

	return nil
}

// CleanUp implements the cleanup interface.
func (d *Datapath) CleanUp() error {

	if d.bpf != nil {
		d.bpf.Cleanup()
	}
	d.cleanupPlatform()

	return nil
}

func (d *Datapath) puContextDelegate(hash string) (*pucontext.PUContext, error) {

	pu, err := d.puFromHash.Get(hash)
	if err != nil {
		return nil, fmt.Errorf("unable to find pucontext in cache with hash %s: %v", hash, err)
	}

	return pu.(*pucontext.PUContext), nil
}

func (d *Datapath) reportFlow(p *packet.Packet, src, dst *collector.EndPoint, context *pucontext.PUContext,
	mode string, report *policy.FlowPolicy, actual *policy.FlowPolicy,
	sourceController string, destinationController string) {

	c := &collector.FlowRecord{
		ContextID:   context.ID(),
		Source:      *src,
		Destination: *dst,
		//
		Action:                actual.Action,
		DropReason:            mode,
		PolicyID:              actual.PolicyID,
		L4Protocol:            p.IPProto(),
		Namespace:             context.ManagementNamespace(),
		Count:                 1,
		SourceController:      sourceController,
		DestinationController: destinationController,
		RuleName:              actual.RuleName,
	}

	if context.Annotations() != nil {
		c.Tags = context.Annotations().GetSlice()
	}

	if report.ObserveAction.Observed() {
		c.ObservedAction = report.Action
		c.ObservedPolicyID = report.PolicyID
		c.ObservedActionType = report.ObserveAction
	}

	d.collector.CollectFlowEvent(c)
}

// contextFromIP returns the PU context from the default IP if remote. Otherwise
// it returns the context from the port or mark values of the packet. Synack
// packets are again special and the flow is reversed. If a container doesn't supply
// its IP information, we use the default IP. This will only work with remotes
// and Linux processes.
func (d *Datapath) contextFromIP(app bool, mark string, port uint16, protocol uint8) (*pucontext.PUContext, error) {

	if d.puFromIP != nil {
		return d.puFromIP, nil
	}

	if protocol == packet.IPProtocolICMP {
		if d.hostPU != nil {
			return d.hostPU, nil
		}
	}

	if app {
		pu, err := d.puFromMark.Get(mark)

		if err != nil {
			zap.L().Error("Unable to find context for application flow with mark",
				zap.String("mark", mark),
				zap.Int("protocol", int(protocol)),
				zap.Int("port", int(port)),
			)
			return nil, counters.CounterError(counters.ErrMarkNotFound, errors.New("Mark Not Found"))
		}
		return pu.(*pucontext.PUContext), nil
	}

	// Network packets for non container traffic
	if protocol == packet.IPProtocolTCP {
		contextID, err := d.contextIDFromTCPPort.GetSpecValueFromPort(port)
		if err != nil {
			zap.L().Debug("Could not find PU context for TCP server port", zap.Uint16("port", port))
			return nil, counters.CounterError(counters.ErrPortNotFound, fmt.Errorf(" TCP Port Not Found %v", port))
		}

		pu, err := d.puFromContextID.Get(contextID)
		if err != nil {
			return nil, counters.CounterError(counters.ErrContextIDNotFound, err)
		}
		return pu.(*pucontext.PUContext), nil
	}

	// This is the UDP case
	contextID, err := d.contextIDFromUDPPort.GetSpecValueFromPort(port)
	if err != nil {
		zap.L().Debug("Could not find PU context for UDP server port", zap.Uint16("port", port))
		return nil, counters.CounterError(counters.ErrPortNotFound, fmt.Errorf("UDP Port Not Found %v", port))
	}

	pu, err := d.puFromContextID.Get(contextID)
	if err != nil {
		return nil, counters.CounterError(counters.ErrContextIDNotFound, fmt.Errorf("contextID %s not Found", contextID))
	}

	return pu.(*pucontext.PUContext), nil
}

// EnableDatapathPacketTracing enable nfq datapath packet tracing
func (d *Datapath) EnableDatapathPacketTracing(ctx context.Context, contextID string, direction packettracing.TracingDirection, interval time.Duration) error {

	if _, err := d.puFromContextID.Get(contextID); err != nil {
		return fmt.Errorf("contextID %s does not exist", contextID)
	}
	d.packetTracingCache.AddOrUpdate(contextID, &tracingCacheEntry{
		direction: direction,
	})
	go func() {
		<-time.After(interval)
		d.packetTracingCache.Remove(contextID) // nolint
	}()

	return nil
}

// EnableIPTablesPacketTracing enable iptables -j trace for the particular pu and is much wider packet stream.
func (d *Datapath) EnableIPTablesPacketTracing(ctx context.Context, contextID string, interval time.Duration) error {
	return nil
}

// DebugCollect collects debug information for remote enforcers
func (d *Datapath) DebugCollect(ctx context.Context, contextID string, debugConfig *policy.DebugConfig) error {
	// this is handled in remoteenforcer
	return nil
}

func (d *Datapath) collectUDPPacket(msg *debugpacketmessage) {
	var value interface{}
	var err error
	report := &collector.PacketReport{
		Payload: make([]byte, 64),
	}
	if msg.udpConn == nil {
		if d.puFromIP == nil {
			return
		}
		if value, err = d.packetTracingCache.Get(d.puFromIP.ID()); err != nil {
			//not being traced return
			return
		}

		report.Claims = d.puFromIP.Identity().GetSlice()
		report.PUID = d.puFromIP.ManagementID()
		report.Namespace = d.puFromIP.ManagementNamespace()
		report.Encrypt = false

	} else {
		//udpConn is not nil
		if value, err = d.packetTracingCache.Get(msg.udpConn.Context.ID()); err != nil {
			return
		}
		report.Encrypt = msg.udpConn.ServiceConnection
		report.Claims = msg.udpConn.Context.Identity().GetSlice()
		report.PUID = msg.udpConn.Context.ManagementID()
		report.Namespace = msg.udpConn.Context.ManagementNamespace()
	}

	if msg.network && !packettracing.IsNetworkPacketTraced(value.(*tracingCacheEntry).direction) {
		return
	} else if !msg.network && !packettracing.IsApplicationPacketTraced(value.(*tracingCacheEntry).direction) {
		return
	}
	report.Protocol = int(packet.IPProtocolUDP)
	report.DestinationIP = msg.p.DestinationAddress().String()
	report.SourceIP = msg.p.SourceAddress().String()
	report.DestinationPort = int(msg.p.DestPort())
	report.SourcePort = int(msg.p.SourcePort())
	if msg.err != nil {
		report.DropReason = msg.err.Error()
		report.Event = packettracing.PacketDropped
	} else {
		report.DropReason = ""
		report.Event = packettracing.PacketReceived
	}
	report.Length = int(msg.p.IPTotalLen())
	report.Mark = msg.Mark
	report.PacketID, _ = strconv.Atoi(msg.p.ID())
	report.TriremePacket = true
	buf := msg.p.GetBuffer(0)
	if len(buf) > 64 {
		copy(report.Payload, msg.p.GetBuffer(0)[0:64])
	} else {
		copy(report.Payload, msg.p.GetBuffer(0))
	}

	d.collector.CollectPacketEvent(report)
}

func (d *Datapath) collectTCPPacket(msg *debugpacketmessage) {
	var value interface{}
	var err error
	var report *collector.PacketReport

	if msg.tcpConn == nil {
		if d.puFromIP == nil {
			return
		}

		if value, err = d.packetTracingCache.Get(d.puFromIP.ID()); err != nil {
			//not being traced return
			return
		}

		report = &collector.PacketReport{}
		report.Claims = d.puFromIP.Identity().GetSlice()
		report.PUID = d.puFromIP.ManagementID()
		report.Encrypt = false
		report.Namespace = d.puFromIP.ManagementNamespace()

	} else {

		if value, err = d.packetTracingCache.Get(msg.tcpConn.Context.ID()); err != nil {
			//not being traced return
			return
		}

		report = &collector.PacketReport{}
		report.Encrypt = msg.tcpConn.ServiceConnection
		report.Claims = msg.tcpConn.Context.Identity().GetSlice()
		report.PUID = msg.tcpConn.Context.ManagementID()
		report.Namespace = msg.tcpConn.Context.ManagementNamespace()
	}

	if msg.network && !packettracing.IsNetworkPacketTraced(value.(*tracingCacheEntry).direction) {
		return
	} else if !msg.network && !packettracing.IsApplicationPacketTraced(value.(*tracingCacheEntry).direction) {
		return
	}

	report.TCPFlags = int(msg.p.GetTCPFlags())
	report.Protocol = int(packet.IPProtocolTCP)
	report.DestinationIP = msg.p.DestinationAddress().String()
	report.SourceIP = msg.p.SourceAddress().String()
	report.DestinationPort = int(msg.p.DestPort())
	report.SourcePort = int(msg.p.SourcePort())
	if msg.err != nil {
		report.DropReason = msg.err.Error()
		report.Event = packettracing.PacketDropped
	} else {
		report.DropReason = ""
		report.Event = packettracing.PacketReceived
	}
	report.Length = int(msg.p.IPTotalLen())
	report.Mark = msg.Mark
	report.PacketID, _ = strconv.Atoi(msg.p.ID())
	report.TriremePacket = true
	// Memory allocation must be done only if we are sure we transmitting
	// the report. Leads to unnecessary memory operations otherwise
	// that affect performance
	report.Payload = make([]byte, 64)
	buf := msg.p.GetBuffer(0)
	if len(buf) > 64 {
		copy(report.Payload, msg.p.GetBuffer(0)[0:64])
	} else {
		copy(report.Payload, msg.p.GetBuffer(0))
	}

	d.collector.CollectPacketEvent(report)
}

// Ping runs ping to the given config.
func (d *Datapath) Ping(ctx context.Context, contextID string, pingConfig *policy.PingConfig) error {

	if pingConfig == nil {
		return nil
	}

	item, err := d.puFromContextID.Get(contextID)
	if err != nil {
		return fmt.Errorf("unable to find context with ID %s in cache: %v", contextID, err)
	}

	context, ok := item.(*pucontext.PUContext)
	if !ok {
		return fmt.Errorf("invalid pu context: %v", contextID)
	}

	return d.initiatePingHandshake(ctx, context, pingConfig)
}

// tcpConnectionExpirationNotifier handles processing the expiration of an element
func (d *Datapath) tcpConnectionExpirationFunc(conn *connection.TCPConnection) {

	if conn.PingEnabled() {

		if !conn.PingConfig.SocketClosed() {
			if err := close(conn); err != nil {
				zap.L().Warn("unable to close socket", zap.Reflect("fd", conn.PingConfig.SocketFd()), zap.Error(err))
			}
		}

		if d.collector != nil && conn.PingConfig.PingReport() != nil {
			d.collector.CollectPingEvent(conn.PingConfig.PingReport())
		}

		return
	}

	if conn.GetState() == connection.TCPSynSend || conn.GetState() == connection.TCPSynAckSend {

		reason := conn.GetReportReason()
		if reason == "" {
			reason = "expired"
		}

		connectionReport := &collector.ConnectionExceptionReport{
			Timestamp:       time.Now(),
			PUID:            conn.Context.ManagementID(),
			Namespace:       conn.Context.ManagementNamespace(),
			Protocol:        tpacket.IPProtocolTCP,
			SourceIP:        conn.TCPtuple.SourceAddress.String(),
			DestinationIP:   conn.TCPtuple.DestinationAddress.String(),
			DestinationPort: conn.TCPtuple.DestinationPort,
			Reason:          reason,
			Value:           conn.GetCounterAndReset(),
			State:           conn.GetStateString(),
		}

		d.collector.CollectConnectionExceptionReport(connectionReport)
	}

	conn.Cleanup()
}

// GetServiceMeshType gets the service mesh that is enabled on this datapath
func (d *Datapath) GetServiceMeshType() policy.ServiceMesh {
	return d.serviceMeshType
}
