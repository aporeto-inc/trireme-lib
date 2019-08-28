// +build linux

package serviceregistry

import (
	"crypto/x509"
	"fmt"
	"net"
	"sync"

	"go.aporeto.io/tg/tglib"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/common"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/servicecache"
	"go.aporeto.io/trireme-lib/controller/pkg/auth"
	"go.aporeto.io/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/controller/pkg/urisearch"
	"go.aporeto.io/trireme-lib/policy"
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

	if err := r.updateDependentServices(sctx); err != nil {
		return nil, err
	}

	if err := r.updateExposedServices(sctx, secrets); err != nil {
		return nil, err
	}

	r.indexByName[puID] = sctx

	return sctx, nil
}

// buildExposedServices builds the caches for the exposed services. It assumes that an authorization
func (r *Registry) updateExposedServices(sctx *ServiceContext, secrets secrets.Secrets) error {

	for _, service := range sctx.PU.Policy.ExposedServices() {
		if service.Type != policy.ServiceHTTP && service.Type != policy.ServiceTCP {
			continue
		}
		if err := r.updateExposedPortAssociations(sctx, service, secrets); err != nil {
			return err
		}
	}

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

// updateExposedPortAssociations will insert the association between a port
// and a service in the global exposed service cache. This is  needed
// for all incoming connections, so that can determine both the type
// of proxy as well the correct policy for this connection. This
// association cannot have overlaps.
func (r *Registry) updateExposedPortAssociations(sctx *ServiceContext, service *policy.ApplicationService, secrets secrets.Secrets) error {

	// Do All the basic validations first.
	if service.PrivateNetworkInfo == nil {
		return fmt.Errorf("Private network is required for exposed services")
	}
	port, err := service.PrivateNetworkInfo.Ports.SinglePort()
	if err != nil {
		return fmt.Errorf("Multi-port is not supported for exposed services: %s", err)
	}
	if service.PublicNetworkInfo != nil {
		if _, err := service.PublicNetworkInfo.Ports.SinglePort(); err != nil {
			return fmt.Errorf("Multi-port is not supported for public network services: %s", err)
		}
	}

	// Find any existing state and get the authorizer. We do not want
	// to re-initialize the authorizer for every policy update.
	authProcessor, err := r.createOrUpdateAuthProcessor(sctx, service, secrets)
	if err != nil {
		return err
	}

	clientCAs := x509.NewCertPool()
	if (service.UserAuthorizationType == policy.UserAuthorizationMutualTLS || service.UserAuthorizationType == policy.UserAuthorizationJWT) &&
		len(service.MutualTLSTrustedRoots) > 0 {
		if !clientCAs.AppendCertsFromPEM(service.MutualTLSTrustedRoots) {
			return fmt.Errorf("Unable to process client CAs")
		}
	}

	// Add the new references.
	if err := r.indexByPort.Add(
		service.PrivateNetworkInfo,
		sctx.PU.ContextID,
		&PortContext{
			ID:                 sctx.PU.ContextID,
			Service:            service,
			TargetPort:         int(port),
			Type:               serviceTypeToNetworkListenerType(service.Type, false),
			Authorizer:         authProcessor,
			ClientTrustedRoots: clientCAs,
			PUContext:          sctx.PUContext,
		},
		true,
	); err != nil {
		return fmt.Errorf("Possible port overlap: %s", err)
	}

	if service.Type == policy.ServiceHTTP && service.PublicNetworkInfo != nil {
		if err := r.indexByPort.Add(
			service.PublicNetworkInfo,
			sctx.PU.ContextID,
			&PortContext{
				ID:                 sctx.PU.ContextID,
				Service:            service,
				TargetPort:         int(port),
				Type:               serviceTypeToNetworkListenerType(service.Type, service.PublicServiceNoTLS),
				Authorizer:         authProcessor,
				ClientTrustedRoots: clientCAs,
				PUContext:          sctx.PUContext,
			},
			true,
		); err != nil {
			return fmt.Errorf("Possible port overlap with public services: %s", err)
		}
	}

	return nil
}

// updateDependentServices will update all the information in the
// ServiceContext for the dependent services.
func (r *Registry) updateDependentServices(sctx *ServiceContext) error {

	for _, service := range sctx.PU.Policy.DependentServices() {

		if len(service.CACert) != 0 {
			sctx.RootCA = append(sctx.RootCA, service.CACert)
		}

		serviceData := &DependentServiceData{
			ServiceType: serviceTypeToApplicationListenerType(service.Type),
		}
		if service.Type == policy.ServiceHTTP {
			serviceData.APICache = urisearch.NewAPICache(service.HTTPRules, service.ID, service.External)
		}

		if err := sctx.dependentServiceCache.Add(
			service.NetworkInfo,
			sctx.PU.ContextID,
			serviceData,
			false,
		); err != nil {
			return fmt.Errorf("Possible overlap in dependent services: %s", err)
		}

	}

	return nil
}

func (r *Registry) createOrUpdateAuthProcessor(sctx *ServiceContext, service *policy.ApplicationService, secrets secrets.Secrets) (*auth.Processor, error) {

	var cert *x509.Certificate
	if len(service.FallbackJWTAuthorizationCert) > 0 {
		var err error
		cert, err = tglib.ParseCertificate([]byte(service.FallbackJWTAuthorizationCert))
		if err != nil {
			return nil, err
		}
	}

	portContext, _ := r.indexByPort.FindListeningServicesForPU(sctx.PU.ContextID)
	var authProcessor *auth.Processor
	if portContext != nil {
		existingPortCtx, ok := portContext.(*PortContext)
		if !ok {
			return nil, fmt.Errorf("Internal error - unusable data structure")
		}
		authProcessor = existingPortCtx.Authorizer
		authProcessor.UpdateSecrets(secrets, cert)
	} else {
		authProcessor = auth.NewProcessor(secrets, cert)
	}

	authProcessor.AddOrUpdateService(
		urisearch.NewAPICache(service.HTTPRules, service.ID, false),
		service.UserAuthorizationType,
		service.UserAuthorizationHandler,
		service.UserTokenToHTTPMappings,
	)

	return authProcessor, nil
}

func serviceTypeToNetworkListenerType(serviceType policy.ServiceType, noTLS bool) common.ListenerType {
	switch serviceType {
	case policy.ServiceHTTP:
		if noTLS {
			return common.HTTPNetwork
		}
		return common.HTTPSNetwork
	default:
		return common.TCPNetwork
	}
}

func serviceTypeToApplicationListenerType(serviceType policy.ServiceType) common.ListenerType {
	switch serviceType {
	case policy.ServiceHTTP:
		return common.HTTPApplication
	default:
		return common.TCPApplication
	}
}
