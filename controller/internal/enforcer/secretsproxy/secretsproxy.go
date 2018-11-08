package secretsproxy

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/aporeto-inc/oxy/forward"
	"github.com/shirou/gopsutil/process"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/controller/pkg/urisearch"
	"go.aporeto.io/trireme-lib/monitor/remoteapi/server"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/cache"
	"go.uber.org/zap"
)

// SecretsProxy holds all state information for applying policy
// in the secrets socket API.
type SecretsProxy struct {
	socketPath      string
	forwarder       *forward.Forwarder // nolint: structcheck
	apiCacheMapping cache.DataStore
	drivers         cache.DataStore
	cgroupCache     cache.DataStore
	policyCache     cache.DataStore

	server *http.Server
	sync.Mutex
}

// NewSecretsProxy creates a new secrets proxy.
func NewSecretsProxy() *SecretsProxy {

	return &SecretsProxy{
		socketPath:      constants.DefaultSecretsPath,
		drivers:         cache.NewCache("secrets driver cache"),
		apiCacheMapping: cache.NewCache("secrets api cache"),
		cgroupCache:     cache.NewCache("secrets pu cache"),
		policyCache:     cache.NewCache("policy cache"),
	}
}

// Run implements the run method of the CtrlInterface. It starts the proxy
// server and initializes the data structures.
func (s *SecretsProxy) Run(ctx context.Context) error {
	s.Lock()
	defer s.Unlock()

	var err error

	// Start a custom listener
	addr, _ := net.ResolveUnixAddr("unix", s.socketPath)
	nl, err := net.ListenUnix("unix", addr)
	if err != nil {
		return fmt.Errorf("Unable to start API server: %s", err)
	}

	s.server = &http.Server{
		Handler: http.HandlerFunc(s.apiProcessor),
	}

	go func() {
		<-ctx.Done()
		s.server.Close() // nolint errcheck
	}()

	go s.server.Serve(server.NewUIDListener(nl)) // nolint errcheck

	return nil
}

// Enforce implements the corresponding interface of enforcers.
func (s *SecretsProxy) Enforce(ctx context.Context, contextID string, puInfo *policy.PUInfo) error {
	return s.updateService(ctx, puInfo)
}

// Unenforce implements the corresponding interface of the enforcers.
func (s *SecretsProxy) Unenforce(contextID string) error {
	return s.deleteService(contextID)
}

// GetFilterQueue is a stub for TCP proxy
func (s *SecretsProxy) GetFilterQueue() *fqconfig.FilterQueue {
	return nil
}

// UpdateSecrets updates the secrets of running enforcers managed by trireme. Remote enforcers will
// get the secret updates with the next policy push.
func (s *SecretsProxy) UpdateSecrets(secret secrets.Secrets) error {
	return nil
}

// apiProcessor is called for every request. It processes the request
// and forwards to the originator of the secrets service after
// authenticating that the client can access the service.
func (s *SecretsProxy) apiProcessor(w http.ResponseWriter, r *http.Request) {
	zap.L().Info("Processing secrets call",
		zap.String("URI", r.RequestURI),
		zap.String("Host", r.Host),
		zap.String("Remote address", r.RemoteAddr),
	)

	// The remote address will contain the uid, gid and pid of the calling process.
	// This is because of the specific socket listener we are uing.
	parts := strings.Split(r.RemoteAddr, ":")
	if len(parts) != 3 {
		httpError(w, fmt.Errorf("Bad Remote Address"), "Unauthorized request", http.StatusUnauthorized)
		return
	}

	// We only care about the originating PID.
	pid := parts[2]
	cgroup, err := findParentCgroup(pid)
	if err != nil {
		httpError(w, err, "Unauthorized client - not the first process", http.StatusUnauthorized)
		return
	}

	data, err := s.apiCacheMapping.Get(cgroup)
	if err != nil {
		httpError(w, err, "Unauthorized client", http.StatusUnauthorized)
		return
	}

	// Find the corresponding API cache with the access permissions for
	// this particular client.
	apiCache, ok := data.(*urisearch.APICache)
	if !ok {
		httpError(w, fmt.Errorf("Invalid data types"), "Internal server error - invalid type", http.StatusInternalServerError)
		return
	}

	// Find the identity of the PU
	policyData, err := s.policyCache.Get(cgroup)
	if err != nil {
		httpError(w, err, "Unauthorized client", http.StatusUnauthorized)
		return
	}

	scopes, ok := policyData.([]string)
	if !ok {
		httpError(w, fmt.Errorf("Invalid data types"), "Internal server error - invalid type", http.StatusInternalServerError)
		return
	}

	// Search the API cache for matching rules.
	found, _ := apiCache.FindAndMatchScope(r.Method, r.RequestURI, scopes)
	if !found {
		httpError(w, fmt.Errorf("Unauthorized service"), "Unauthorized access", http.StatusUnauthorized)
		return
	}

	// Retrieve the secrets driver data and information.
	driverData, err := s.drivers.Get(cgroup)
	if err != nil {
		httpError(w, err, "No secrets driver for this client", http.StatusBadRequest)
		return
	}
	driver, ok := driverData.(SecretsDriver)
	if !ok {
		httpError(w, fmt.Errorf("driver not found"), "Bad driver", http.StatusInternalServerError)
		return
	}

	// Transfor the request based on the driver.
	if err := driver.Transform(r); err != nil {
		httpError(w, err, "Secrets driver error", http.StatusInternalServerError)
		return
	}

	// Forward the request. TODO .. we need to massage the return here.
	forwarder, err := forward.New(forward.RoundTripper(driver.Transport()))
	if err != nil {
		httpError(w, err, "Failed to configure forwarder", http.StatusInternalServerError)
		return
	}

	forwarder.ServeHTTP(w, r)
}

func (s *SecretsProxy) updateService(ctx context.Context, puInfo *policy.PUInfo) error {
	var cgroup string

	// Only supporting secrets for containers PUs at this time.
	if puInfo.Runtime.PUType() != common.ContainerPU {
		return nil
	}
	// First we need to determine the corresponding cgroup. We will look at the
	// cache since this might be an update event. If that fails, we will look
	// at the runtime. If it is not found we abort. If we find the cgroup
	// we add it to the cache for future reference.
	cgroupData, err := s.cgroupCache.Get(puInfo.ContextID)
	if err == nil {
		cgroup = cgroupData.(string)
	} else {
		if puInfo.Runtime == nil {
			return fmt.Errorf("Unable to find cgroup")
		}
		var found bool
		cgroup, found = puInfo.Policy.Annotations().Get("@sys:cgroupparent")
		if !found {
			// This is not Kubernetes. We will associate the cgroup with the enforcer.
			cgroup = puInfo.ContextID
		}
		s.cgroupCache.AddOrUpdate(puInfo.ContextID, cgroup)
	}

	scopes := append(puInfo.Policy.Identity().Copy().Tags, puInfo.Policy.Scopes()...)
	s.policyCache.AddOrUpdate(cgroup, scopes)

	// Scan through the dependent services for secrets distribution services.
	for _, service := range puInfo.Policy.DependentServices() {
		// Ignore all other services
		if service.Type != policy.ServiceSecretsProxy {
			continue
		}

		uriCache := urisearch.NewAPICache(service.HTTPRules, service.ID, true)
		s.apiCacheMapping.AddOrUpdate(cgroup, uriCache)
		// Parse the service definition and instantiate the transform driver.

		d, err := NewGenericSecretsDriver(service.CACert, service.AuthToken, service.NetworkInfo)
		if err != nil {
			return fmt.Errorf("Failed to create secrets driver: %s", err)
		}
		s.drivers.AddOrUpdate(cgroup, d)
	}
	return nil
}

func (s *SecretsProxy) deleteService(contextID string) error {

	cgroupData, err := s.cgroupCache.Get(contextID)
	if err != nil {
		// Returning nil here. Nothing anyone can do about it.
		zap.L().Debug("PU not found in secrets controller - unable to clean state")
		return nil
	}
	s.cgroupCache.Remove(contextID)               // nolint errcheck
	s.apiCacheMapping.Remove(cgroupData.(string)) // nolint errcheck
	s.drivers.Remove(cgroupData.(string))         // nolint errcheck
	s.policyCache.Remove(cgroupData.(string))     // nolint errcheck

	return nil
}

func httpError(w http.ResponseWriter, err error, msg string, number int) {
	zap.L().Error(msg, zap.Error(err))
	http.Error(w, msg, number)
}

// ValidateOriginProcess implements a strict validation of the origin process. We might add later.
func ValidateOriginProcess(pid string) (string, error) {

	pidNumber, err := strconv.Atoi(pid)
	if err != nil {
		return "", fmt.Errorf("Invalid PID %s", pid)
	}
	process, err := process.NewProcess(int32(pidNumber))
	if err != nil {
		return "", fmt.Errorf("Process not found: %s", err)
	}
	ppid, err := process.Ppid()
	if err != nil {
		return "", fmt.Errorf("Parent process not found: %s", err)
	}
	parentPidCgroup, err := processCgroups(strconv.Itoa(int(ppid)), "net_cls,net_prio")
	if err != nil {
		return "", fmt.Errorf("Parent cgroup not found: %s", err)
	}
	if parentPidCgroup != "/" {
		return "", fmt.Errorf("Parent is not root cgroup - authorization fail")
	}
	return findParentCgroup(pid)
}

func processCgroups(pid string, cgroupType string) (string, error) {
	path := fmt.Sprintf("/aporetoproc/%s/cgroup", pid)

	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close() // nolint

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", err
		}
		text := scanner.Text()
		if !strings.Contains(text, cgroupType) {
			continue
		}
		parts := strings.SplitN(text, ":", 3)
		if len(parts) < 3 {
			continue
		}
		return parts[2], nil
	}
	return "", fmt.Errorf("cgroup not found")
}

// findParentCgroup returns the parent cgroup of the process caller
func findParentCgroup(pid string) (string, error) {

	cgroup, err := processCgroups(pid, "net_cls,net_prio")
	if err != nil {
		return "", fmt.Errorf("Invalid cgroup: %s", err)
	}
	for i := len(cgroup) - 1; i > 0; i-- {
		if cgroup[i:i+1] == "/" {
			return cgroup[:i], nil
		}
	}
	if strings.HasPrefix(cgroup, "/docker/") && len(cgroup) > 8 {
		return cgroup[8:20], nil
	}
	return "", fmt.Errorf("Cannot find parent cgroup: %s", pid)
}
