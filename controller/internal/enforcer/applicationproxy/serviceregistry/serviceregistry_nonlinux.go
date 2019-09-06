// +build !linux

// Package serviceregistry implementation for windows.
// This needs to be revisted when we do actual api services and host service
package serviceregistry

import (
	"crypto/x509"
	"fmt"
	"net"
	"sync"

	triremecommon "go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/common"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/servicecache"
	"go.aporeto.io/trireme-lib/controller/pkg/auth"
	"go.aporeto.io/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/controller/pkg/urisearch"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/portspec"
	"go.uber.org/zap"
)

// ServiceContext includes all the all the service related information
// for dependent services. It is indexed by the PU ID and a PU can
// easily retrieve all the state with a simple lookup. Note, that
// there is one ServiceContext for every PU.
type ServiceContext struct {
	PU        *policy.PUInfo
	PUContext *pucontext.PUContext
	RootCA    [][]byte

	// The dependent service cache is only accessible internally,
	// so that all types are properly converted.
	dependentServiceCache *servicecache.ServiceCache
}

// DependentServiceData are the data that are held for each service
// in the dependentServiceCache.
type DependentServiceData struct {
	// Used for authorization
	APICache *urisearch.APICache
	// Used by the protomux to find the right service type.
	ServiceType common.ListenerType
}

// PortContext includes all the needed associations to refer to a service by port.
// For incoming connections the only available information is the IP/port
// pair of the original request and we use this to map the connection and
// request to a port. For network services we have additional state data
// such as the authorizers. Note that there is one PortContext for every
// service of every PU.
type PortContext struct {
	ID                 string
	Type               common.ListenerType
	Service            *policy.ApplicationService
	Authorizer         *auth.Processor
	PUContext          *pucontext.PUContext
	TargetPort         int
	ClientTrustedRoots *x509.CertPool
}

// Registry is a service registry. It maintains all the state information
// and provides a simple API to retrieve the data. The registry always
// locks and allows multi-threading.
type Registry struct {
	indexByName map[string]*ServiceContext
	indexByPort *servicecache.ServiceCache
	sync.Mutex
}

// NewServiceRegistry creates and initializes the registry.
func NewServiceRegistry() *Registry {
	return &Registry{
		indexByName: map[string]*ServiceContext{},
		indexByPort: servicecache.NewTable(),
	}
}

// Register registers a new service with the registry. If the service
// already exists it updates the service with the new information, otherwise
// it creates a new service.
func (r *Registry) Register(
	puID string,
	pu *policy.PUInfo,
	puContext *pucontext.PUContext,
	secrets secrets.Secrets,
) (*ServiceContext, error) {

	r.Lock()
	defer r.Unlock()

	sctx := &ServiceContext{
		PU:                    pu,
		PUContext:             puContext,
		dependentServiceCache: servicecache.NewTable(),
		RootCA:                [][]byte{},
	}

	// Delete all old references first. Since the registry is locked
	// nobody will be affected.
	r.indexByPort.DeleteByID(puID, true)
	r.indexByPort.DeleteByID(puID, false)

	if err := r.updateExposedServices(sctx, secrets); err != nil {
		return nil, err
	}

	r.indexByName[puID] = sctx

	return sctx, nil
}

// buildExposedServices builds the caches for the exposed services. It assumes that an authorization
func (r *Registry) updateExposedServices(sctx *ServiceContext, secrets secrets.Secrets) error {
	addresses, _ := net.InterfaceAddrs()
	netIPAddress := make([]*net.IPNet, len(addresses))
	var err error
	for index, addr := range addresses {
		ipnetaddr := addr.String()
		_, netIPAddress[index], err = net.ParseCIDR(ipnetaddr)
		if err != nil {
			zap.L().Error("Got Invalid Address", zap.String("CIDR", ipnetaddr))
		}
	}
	r.indexByPort.Add(&triremecommon.Service{
		Ports: &portspec.PortSpec{
			Min: 1,
			Max: 65535,
		},
		Protocol:  6,
		Addresses: []*net.IPNet{},
	}, sctx.PU.ContextID, &PortContext{
		ID: sctx.PU.ContextID,
		Service: &policy.ApplicationService{
			ID: sctx.PU.ContextID,
		},
		Type:      common.TCPNetwork,
		PUContext: sctx.PUContext,
	}, true)

	return nil
}

// Unregister unregisters a pu from the registry.
func (r *Registry) Unregister(puID string) error {
	r.Lock()
	defer r.Unlock()

	delete(r.indexByName, puID)
	r.indexByPort.DeleteByID(puID, true)
	r.indexByPort.DeleteByID(puID, false)
	return nil
}

// RetrieveExposedServiceContext retrieves a service by the provided IP and or port. This
// is called by the network side of processing to find the context.
func (r *Registry) RetrieveExposedServiceContext(ip net.IP, port int, host string) (*PortContext, error) {
	r.Lock()
	defer r.Unlock()

	data := r.indexByPort.Find(ip, port, host, true)
	if data == nil {
		return nil, fmt.Errorf("Service information not found: %s %d %s", ip.String(), port, host)
	}

	portContext, ok := data.(*PortContext)
	if !ok {
		return nil, fmt.Errorf("Internal server error")
	}

	return portContext, nil
}

// RetrieveServiceByID retrieves a service by the PU ID. Returns error if not found.
func (r *Registry) RetrieveServiceByID(id string) (*ServiceContext, error) {
	r.Lock()
	defer r.Unlock()

	svc, ok := r.indexByName[id]
	if !ok {
		return nil, fmt.Errorf("Service not found: %s", id)
	}

	return svc, nil
}

// RetrieveServiceDataByIDAndNetwork will return the service data that match the given
// PU and the given IP/port information.
func (r *Registry) RetrieveServiceDataByIDAndNetwork(id string, ip net.IP, port int, host string) (*ServiceContext, *DependentServiceData, error) {
	sctx, err := r.RetrieveServiceByID(id)
	if err != nil {
		return nil, nil, fmt.Errorf("Services for PU %s not found: %s", id, err)
	}
	data := sctx.dependentServiceCache.Find(ip, port, "", false)
	if data == nil {
		return nil, nil, fmt.Errorf("Service not found for this PU: %s", id)
	}
	serviceData, ok := data.(*DependentServiceData)
	if !ok {
		return nil, nil, fmt.Errorf("Internal server error - bad data types")
	}
	return sctx, serviceData, nil
}
