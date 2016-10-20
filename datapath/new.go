package datapath

// Go libraries
import (
	"time"

	"github.com/aporeto-inc/trireme/cache"
	"github.com/aporeto-inc/trireme/datapath/tokens"
	"github.com/aporeto-inc/trireme/eventlog"
)

// Default parameters for the NFQUEUE configuration. Parameters can be
// changed after an isolator has been created and before its started.
// Change in parameters after the isolator is started has no effect
const (
	// DefaultNumberOfQueues  is the default number of queues used in NFQUEUE
	DefaultNumberOfQueues = 4
	// DefaultApplicationQueue represents the queue for application packets
	DefaultApplicationQueue = 0
	// DefaultNetworkQueue represents the queue for the network packets
	DefaultNetworkQueue = 4
	// DefaultQueueSize is the size of the queues
	DefaultQueueSize = 100
)

// New will create a new data path structure. It instantiates the data stores
// needed to track sessions. The data path is started with a different call.
// Only required parameters must be provided. Rest a pre-populated with defaults.
func New(
	mutualAuth bool,
	filterQueue *FilterQueueConfig,
	logger eventlog.EventLogger,
	service Service,
	secrets tokens.Secrets,
	serverID string,
	validity time.Duration,
) *DataPath {

	d := &DataPath{
		puTracker:                cache.NewCache(nil),
		networkConnectionTracker: cache.NewCacheWithExpiration(time.Second*60, 100000),
		appConnectionTracker:     cache.NewCacheWithExpiration(time.Second*60, 100000),
		contextConnectionTracker: cache.NewCacheWithExpiration(time.Second*60, 100000),
		FilterQueue:              filterQueue,
		mutualAuthorization:      mutualAuth,
		service:                  service,
		logger:                   logger,
		tokenEngine:              tokens.NewJWT(validity, serverID, secrets),
		net:                      &PacketStats{},
		app:                      &PacketStats{},
		ackSize:                  secrets.AckSize(),
	}

	if d.tokenEngine == nil {
		return nil
	}

	return d

}

// NewDefault create a new data path with most things used by default
func NewDefault(
	serverID string,
	secrets tokens.Secrets,
) *DataPath {

	mutualAuthorization := false
	fqConfig := &FilterQueueConfig{
		NetworkQueue:              DefaultNetworkQueue,
		NetworkQueueSize:          DefaultQueueSize,
		NumberOfNetworkQueues:     DefaultNumberOfQueues,
		ApplicationQueue:          DefaultApplicationQueue,
		ApplicationQueueSize:      DefaultQueueSize,
		NumberOfApplicationQueues: DefaultNumberOfQueues,
	}
	eventLogger := &eventlog.DefaultLogger{}
	validity := time.Hour * 8760

	dp := New(
		mutualAuthorization,
		fqConfig,
		eventLogger,
		nil,
		secrets,
		serverID,
		validity,
	)
	return dp
}
