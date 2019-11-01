package envoyproxy

// import (
// 	"crypto/tls"
// 	"crypto/x509"
// 	"fmt"
// 	"net/http"
// 	"sync"

// 	"go.aporeto.io/trireme-lib/collector"
// 	"go.aporeto.io/trireme-lib/common"
// 	"go.aporeto.io/trireme-lib/controller/internal/enforcer/apiauth"
// 	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/markedconn"
// 	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/serviceregistry"
// 	"go.aporeto.io/trireme-lib/controller/internal/enforcer/metadata"
// 	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
// )

// // Proxy maintains state for proxies connections from listen to backend.
// type Proxy struct {
// 	cert             *tls.Certificate
// 	ca               *x509.CertPool
// 	keyPEM           string
// 	certPEM          string
// 	secrets          secrets.Secrets
// 	collector        collector.EventCollector
// 	puContext        string
// 	localIPs         map[string]struct{}
// 	applicationProxy bool
// 	mark             int
// 	server           *http.Server
// 	registry         *serviceregistry.Registry

// 	tlsClientConfig *tls.Config
// 	auth            *apiauth.Processor
// 	metadata        *metadata.Client
// 	tokenIssuer     common.ServiceTokenIssuer
// 	//hooks           map[string]hookFunc
// 	sync.RWMutex
// }

// // NewEnvoyProxy creates a new instance of proxy
// func NewEnvoyProxy(
// 	c collector.EventCollector,
// 	puContext string,
// 	caPool *x509.CertPool,
// 	applicationProxy bool,
// 	mark int,
// 	secrets secrets.Secrets,
// 	registry *serviceregistry.Registry,
// 	tokenIssuer common.ServiceTokenIssuer,
// ) *Proxy {

// 	p := &Proxy{
// 		collector:        c,
// 		puContext:        puContext,
// 		ca:               caPool,
// 		applicationProxy: applicationProxy,
// 		mark:             mark,
// 		secrets:          secrets,
// 		localIPs:         markedconn.GetInterfaces(),
// 		registry:         registry,
// 		tlsClientConfig: &tls.Config{
// 			RootCAs: caPool,
// 		},
// 		auth:        apiauth.New(puContext, registry, secrets),
// 		metadata:    metadata.NewClient(puContext, registry, tokenIssuer),
// 		tokenIssuer: tokenIssuer,
// 	}

// 	fmt.Println("ABHI **** New envoy-proxy")

// 	return p
// }
