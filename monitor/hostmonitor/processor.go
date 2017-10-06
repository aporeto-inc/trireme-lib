package hostmonitor

import (
	"fmt"
	"io/ioutil"
	"strconv"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/monitor/contextstore"
	"github.com/aporeto-inc/trireme/monitor/linuxmonitor/cgnetcls"
	"github.com/aporeto-inc/trireme/monitor/rpcmonitor"
	"github.com/aporeto-inc/trireme/policy"
)

// HostProcessor captures all the monitor processor information
// It implements the MonitorProcessor interface of the rpc monitor
type HostProcessor struct {
	collector         collector.EventCollector
	puHandler         monitor.ProcessingUnitsHandler
	metadataExtractor rpcmonitor.RPCMetadataExtractor
	contextStore      contextstore.ContextStore
	storePath         string
}

// NewCustomHostProcessor initializes a processor with a given store path
func NewCustomHostProcessor(storePath string, collector collector.EventCollector, puHandler monitor.ProcessingUnitsHandler, metadataExtractor rpcmonitor.RPCMetadataExtractor) *HostProcessor {

	return &HostProcessor{
		collector:         collector,
		puHandler:         puHandler,
		metadataExtractor: metadataExtractor,
		contextStore:      contextstore.NewContextStore(storePath),
		storePath:         storePath,
	}
}

// NewHostProcessor initializes the default host processor
func NewHostProcessor(collector collector.EventCollector, puHandler monitor.ProcessingUnitsHandler, metadataExtractor rpcmonitor.RPCMetadataExtractor) *HostProcessor {
	return NewCustomHostProcessor("/var/run/trireme/host", collector, puHandler, metadataExtractor)
}

// Create handles create events
func (p *HostProcessor) Create(eventInfo *rpcmonitor.EventInfo) error {
	return nil
}

// Start handles start events
func (p *HostProcessor) Start(eventInfo *rpcmonitor.EventInfo) error {

	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return err
	}

	runtimeInfo, err := p.metadataExtractor(eventInfo)
	if err != nil {
		return err
	}

	if err = p.puHandler.SetPURuntime(contextID, runtimeInfo); err != nil {
		return err
	}

	defaultIP, _ := runtimeInfo.DefaultIPAddress()

	if perr := p.puHandler.HandlePUEvent(contextID, monitor.EventStart); perr != nil {
		zap.L().Error("Failed to activate process", zap.Error(perr))
		return perr
	}

	if eventInfo.ControlApplicationTraffic {
		markval := runtimeInfo.Options().CgroupMark
		mark, _ := strconv.ParseUint(markval, 10, 32)
		hexmark := "0x" + (strconv.FormatUint(mark, 16))
		if err := ioutil.WriteFile("/sys/fs/cgroup/net_cls,net_prio/net_cls.classid", []byte(hexmark), 0644); err != nil {
			return fmt.Errorf("Failed to  write to net_cls.classid file for new cgroup")
		}
	}

	p.collector.CollectContainerEvent(&collector.ContainerRecord{
		ContextID: contextID,
		IPAddress: defaultIP,
		Tags:      runtimeInfo.Tags(),
		Event:     collector.ContainerStart,
	})

	// Store the state in the context store for future access
	return p.contextStore.StoreContext(contextID, eventInfo)
}

// Stop handles a stop event
func (p *HostProcessor) Stop(eventInfo *rpcmonitor.EventInfo) error {
	fmt.Printf("Stop: %+v \n", eventInfo)
	contextID, err := generateContextID(eventInfo)
	if err != nil {
		return fmt.Errorf("Couldn't generate a contextID: %s", err)
	}

	return p.puHandler.HandlePUEvent(contextID, monitor.EventStop)
}

// Destroy handles a destroy event
func (p *HostProcessor) Destroy(eventInfo *rpcmonitor.EventInfo) error {
	fmt.Printf("Destroy: %+v \n", eventInfo)
	return nil
}

// Pause handles a pause event
func (p *HostProcessor) Pause(eventInfo *rpcmonitor.EventInfo) error {
	fmt.Printf("Pause: %+v \n", eventInfo)
	return nil
}

// generateContextID creates the contextID from the event information
func generateContextID(eventInfo *rpcmonitor.EventInfo) (string, error) {

	if eventInfo.Name == "" {
		return "", fmt.Errorf("PUID is empty from eventInfo")
	}

	if len(eventInfo.PUID) > 12 {
		return "", fmt.Errorf("PUID is limited")
	}

	return eventInfo.PUID[:12], nil
}

// DefaultHostMetadataExtractor is a host specific metadata extractor
func DefaultHostMetadataExtractor(event *rpcmonitor.EventInfo) (*policy.PURuntime, error) {

	if event.Name == "" {
		return nil, fmt.Errorf("EventInfo PU Name is empty")
	}

	if event.PID == "" {
		return nil, fmt.Errorf("EventInfo PID is empty")
	}

	if event.PUID == "" {
		return nil, fmt.Errorf("EventInfo PUID is empty")
	}

	runtimeTags := policy.NewTagStore()

	for k, v := range event.Tags {
		runtimeTags.AppendKeyValue("@usr:"+k, v)
	}

	options := &policy.OptionsType{
		CgroupName: event.PUID,
		CgroupMark: strconv.FormatUint(cgnetcls.MarkVal(), 10),
		Services:   event.Services,
	}

	runtimeIps := policy.ExtendedMap{"bridge": "0.0.0.0/0"}

	runtimePID, err := strconv.Atoi(event.PID)

	if err != nil {
		return nil, fmt.Errorf("PID is invalid: %s", err)
	}

	return policy.NewPURuntime(event.Name, runtimePID, "", runtimeTags, runtimeIps, constants.HostPU, options), nil
}
