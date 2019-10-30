package envoyproxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"context"

	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/policy"
	"go.uber.org/zap"
	"google.golang.org/grpc"

	v2 "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/auth"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	sds "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v2"
	"github.com/gogo/protobuf/types"
	"google.golang.org/grpc/metadata"
	"istio.io/istio/security/pkg/nodeagent/model"
)

// for testing/POC purpose just add the manually created certificates.
var (
	sleepPEM = `
-----BEGIN CERTIFICATE-----
MIIBcDCCARegAwIBAgIQemVbvfpmCUzI7nbrImDe7DAKBggqhkjOPQQDAjAeMQ0w
CwYDVQQKEwRhY21lMQ0wCwYDVQQDEwRyb290MB4XDTE5MTAxOTAxMTgyM1oXDTI5
MDgyNzAxMTgyM1owIDENMAsGA1UEChMEYWNtZTEPMA0GA1UEAxMGY2xpZW50MFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJWdLEwANCfhWnhAcSJVeUXMCRj/xSh52
7Gxf7B8Rwo+g2M+0BE13ZClbeNbMu2x6RDUoObJgeSumM0GdHvgNqqM1MDMwDgYD
VR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAw
CgYIKoZIzj0EAwIDRwAwRAIgdAEzOqPsDF3+nrmCZZPaZSEzcuApDD/UoAOu96lb
EVICIF+utXDYgIeE7OqSmrtFXaif8fM+n/OgrIonF4RV8+jA
-----END CERTIFICATE-----`
	sleeepKey = `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJ496pypyXGSXHZEcMl8OiDR7hGl9xRWCodugRfscOm8oAoGCCqGSM49
AwEHoUQDQgAEJWdLEwANCfhWnhAcSJVeUXMCRj/xSh527Gxf7B8Rwo+g2M+0BE13
ZClbeNbMu2x6RDUoObJgeSumM0GdHvgNqg==
-----END EC PRIVATE KEY-----`
	serverPEM = `
-----BEGIN CERTIFICATE-----
MIIBcjCCARigAwIBAgIRALZyIRzfKP2tr0gjIUhJqOEwCgYIKoZIzj0EAwIwHjEN
MAsGA1UEChMEYWNtZTENMAsGA1UEAxMEcm9vdDAeFw0xOTEwMTkwMTIxMDdaFw0y
OTA4MjcwMTIxMDdaMCAxDTALBgNVBAoTBGFjbWUxDzANBgNVBAMTBnNlcnZlcjBZ
MBMGByqGSM49AgEGCCqGSM49AwEHA0IABB7qdtSzXWiof/nfzYclTKxQ+U0CRnro
Gc0cB7CEkaV/tsKacLegSxibtckDi1w8S0mBzUIotKBfnjTD5Ii1TmajNTAzMA4G
A1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAA
MAoGCCqGSM49BAMCA0gAMEUCIQCZidLIKKJY/R2EeGJNwCL9vYrtqPSPKJyxLrHY
Z4qe2AIgbARCHGwv53KKKElLy7tnBMnTpd4vo8BWcAOnppwXHSs=
-----END CERTIFICATE-----`
	serverKEY = `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBs8xKuuJ7SKVnr4QWmVmC1kJ6uIcdJ5DESr8zmZz6FQoAoGCCqGSM49
AwEHoUQDQgAEHup21LNdaKh/+d/NhyVMrFD5TQJGeugZzRwHsISRpX+2wppwt6BL
GJu1yQOLXDxLSYHNQii0oF+eNMPkiLVOZg==
-----END EC PRIVATE KEY-----`
	rootPEM = `
-----BEGIN CERTIFICATE-----
MIIBXjCCAQOgAwIBAgIQKd8Ypc10ti3tUZWpdYVzqTAKBggqhkjOPQQDAjAeMQ0w
CwYDVQQKEwRhY21lMQ0wCwYDVQQDEwRyb290MB4XDTE5MTAxOTAxMTc0MloXDTI5
MDgyNzAxMTc0MlowHjENMAsGA1UEChMEYWNtZTENMAsGA1UEAxMEcm9vdDBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABPujmM2L3DqDMlWkQIVASZS3kZA9harmnWNS
f7ji9wGmmd1hTAicja2YQxGWoy42M1Tc9Wrl+h0Lrxhyjk0dm3qjIzAhMA4GA1Ud
DwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0kAMEYCIQCt
ot79SkWd5wfxh/e0mlEVS+wNxRGm/5gC59h2UDRvRAIhAOtrClKkPqjxgBkHlzmU
94wdniSd6HoIEcRVlaLx1fM4
-----END CERTIFICATE-----`

	rootPEM2 = `
-----BEGIN CERTIFICATE-----
MIIEBDCCAuygAwIBAgIDAjppMA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNVBAYTAlVT
MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i
YWwgQ0EwHhcNMTMwNDA1MTUxNTU1WhcNMTUwNDA0MTUxNTU1WjBJMQswCQYDVQQG
EwJVUzETMBEGA1UEChMKR29vZ2xlIEluYzElMCMGA1UEAxMcR29vZ2xlIEludGVy
bmV0IEF1dGhvcml0eSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AJwqBHdc2FCROgajguDYUEi8iT/xGXAaiEZ+4I/F8YnOIe5a/mENtzJEiaB0C1NP
VaTOgmKV7utZX8bhBYASxF6UP7xbSDj0U/ck5vuR6RXEz/RTDfRK/J9U3n2+oGtv
h8DQUB8oMANA2ghzUWx//zo8pzcGjr1LEQTrfSTe5vn8MXH7lNVg8y5Kr0LSy+rE
ahqyzFPdFUuLH8gZYR/Nnag+YyuENWllhMgZxUYi+FOVvuOAShDGKuy6lyARxzmZ
EASg8GF6lSWMTlJ14rbtCMoU/M4iarNOz0YDl5cDfsCx3nuvRTPPuj5xt970JSXC
DTWJnZ37DhF5iR43xa+OcmkCAwEAAaOB+zCB+DAfBgNVHSMEGDAWgBTAephojYn7
qwVkDBF9qn1luMrMTjAdBgNVHQ4EFgQUSt0GFhu89mi1dvWBtrtiGrpagS8wEgYD
VR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwOgYDVR0fBDMwMTAvoC2g
K4YpaHR0cDovL2NybC5nZW90cnVzdC5jb20vY3Jscy9ndGdsb2JhbC5jcmwwPQYI
KwYBBQUHAQEEMTAvMC0GCCsGAQUFBzABhiFodHRwOi8vZ3RnbG9iYWwtb2NzcC5n
ZW90cnVzdC5jb20wFwYDVR0gBBAwDjAMBgorBgEEAdZ5AgUBMA0GCSqGSIb3DQEB
BQUAA4IBAQA21waAESetKhSbOHezI6B1WLuxfoNCunLaHtiONgaX4PCVOzf9G0JY
/iLIa704XtE7JW4S615ndkZAkNoUyHgN7ZVm2o6Gb4ChulYylYbc3GrKBIxbf/a/
zG+FA1jDaFETzf3I93k9mTXwVqO94FntT0QJo544evZG0R0SnU++0ED8Vf4GXjza
HFa9llF7b1cq26KqltyMdMKVvvBulRP/F/A8rLIQjcxz++iPAsbw+zOzlTvjwsto
WHPbqCRiOwY1nQ2pM714A5AuTHhdUDqB1O6gyHA43LL5Z/qHQF1hwFGPa4NrzQU6
yuGnBXj8ytqU0CwIPX4WecigUCAkVDNx
-----END CERTIFICATE-----`

	counter uint64
)

const (
	// SdsSocketpath is the socket path on which the envoy will talk to the remoteEnforcer.
	//SdsSocketpath = "@aporeto_envoy_sds"
	//SdsSocketpath = "127.0.0.1:2999"
	SdsSocketpath = "/var/run/sds/uds_path"
)

// Options to create a SDS server to task to envoy
type Options struct {
	SocketPath string
}

// SecretDiscoveryStream is the same as the sds.SecretDiscoveryService_StreamSecretsServer
type SecretDiscoveryStream interface {
	Send(*v2.DiscoveryResponse) error
	Recv() (*v2.DiscoveryRequest, error)
	grpc.ServerStream
}

// SdsServer to talk with envoy for sds.
type SdsServer struct {
	sdsGrpcServer   *grpc.Server
	sdsGrpcListener net.Listener

	errCh   chan error
	puInfo  *policy.PUInfo
	cert    *tls.Certificate
	ca      *x509.CertPool
	keyPEM  string
	certPEM string
	secrets secrets.Secrets
	sync.RWMutex
	// secretcache is a cache of the secrets, here the key is the connectionID and val is the secret.
	secretcache *kvcache
	connMap     map[string]bool
}

// clientConn is ID for the connection between client and SDS server.
type clientConn struct {
	clientID string
	// the TLS cert information cached for this particular connection
	secret *model.SecretItem

	mutex sync.RWMutex

	// connectionID is the ID for each new request, make it a combo of nodeID+counter.
	connectionID string
}

// NewSdsServer creates a instance of a server.
func NewSdsServer(contextID string, puInfo *policy.PUInfo, caPool *x509.CertPool, secrets secrets.Secrets) (*SdsServer, error) {
	if puInfo == nil {
		fmt.Println("\n\n puInfo NIL ")
		return nil, fmt.Errorf("the puinfo cannot be nil")
	}
	fmt.Println("New sds server for : ", puInfo.Policy.Annotations(), " puID is : ", contextID)
	//return nil, nil
	sdsOptions := &Options{SocketPath: SdsSocketpath}
	sdsServer := &SdsServer{
		puInfo:      puInfo,
		ca:          caPool,
		errCh:       make(chan error),
		secrets:     secrets,
		secretcache: newkvCache(),
		connMap:     make(map[string]bool),
	}
	if err := sdsServer.CreateSdsService(sdsOptions); err != nil {
		fmt.Println("Error while starting the envoy sds server.")
		return nil, err
	}
	fmt.Println("SDS start success for :", puInfo.ContextID)
	return sdsServer, nil
}

// CreateSdsService does the following
// 1. create grpc server.
// 2. create a listener on the Unix Domain Socket.
// 3.
func (s *SdsServer) CreateSdsService(options *Options) error { //nolint: unparam
	fmt.Println("ABHI, envoy-trireme create  SDS server")
	s.sdsGrpcServer = grpc.NewServer()
	s.register(s.sdsGrpcServer)
	if err := os.Remove(options.SocketPath); err != nil && !os.IsNotExist(err) {
		fmt.Println("ABHI, envoy-reireme, failed to remove the udspath", err)
		return err
	}
	fmt.Println("Start listening on UDS path: ", options.SocketPath)
	addr, _ := net.ResolveUnixAddr("unix", options.SocketPath)

	sdsGrpcListener, err := net.ListenUnix("unix", addr)
	if err != nil {
		fmt.Println("cannot listen on the socketpath", err)
		return err
	}
	//make sure the socket path can be accessed.
	if _, err := os.Stat(options.SocketPath); err != nil {
		fmt.Println("SDS uds file doesn't exist", options.SocketPath)
		return fmt.Errorf("sds uds file %q doesn't exist", options.SocketPath)
	}
	if err := os.Chmod(options.SocketPath, 0666); err != nil {
		fmt.Println("Failed to update permission", options.SocketPath)
		return fmt.Errorf("failed to update %q permission", options.SocketPath)
	}
	//var err error
	s.sdsGrpcListener = sdsGrpcListener

	fmt.Println("run the grpc server at: ", s.sdsGrpcListener.Addr())
	s.Run()
	return nil
}

// Run starts the sdsGrpcServer to serve
func (s *SdsServer) Run() {
	go func() {
		if s.sdsGrpcListener != nil {
			if err := s.sdsGrpcServer.Serve(s.sdsGrpcListener); err != nil {
				fmt.Println("got error after serve", err)
				s.errCh <- err
			}
		}
		fmt.Println("the listener is nil, cannot start the SDS server for: ", s.puInfo.ContextID)
	}()
}

// Stop stops all the listeners and the grpc servers.
func (s *SdsServer) Stop() {
	if s.sdsGrpcListener != nil {
		s.sdsGrpcListener.Close()
	}
	if s.sdsGrpcServer != nil {
		s.sdsGrpcServer.Stop()
	}
}

// GracefulStop calls the function with the same name on the backing gRPC server
func (s *SdsServer) GracefulStop() {
	s.sdsGrpcServer.GracefulStop()
}

// register adds the SDS handle to the grpc server
func (s *SdsServer) register(sdsGrpcServer *grpc.Server) {
	fmt.Println("\n\n ** Abhi envoy-trireme registering the secret discovery")
	sds.RegisterSecretDiscoveryServiceServer(sdsGrpcServer, s)
}

// now implement the interfaces of the SDS grpc server.
// type SecretDiscoveryServiceServer interface {
// 	DeltaSecrets(SecretDiscoveryService_DeltaSecretsServer) error
// 	StreamSecrets(SecretDiscoveryService_StreamSecretsServer) error
// 	FetchSecrets(context.Context, *v2.DiscoveryRequest) (*v2.DiscoveryResponse, error)
// }

// DeltaSecrets checks for the delta and sends the changes.
func (s *SdsServer) DeltaSecrets(stream sds.SecretDiscoveryService_DeltaSecretsServer) error {
	return nil
}

func startStreaming(stream SecretDiscoveryStream, discoveryReqCh chan *v2.DiscoveryRequest) {
	fmt.Println("In start streaming")
	defer close(discoveryReqCh)
	for {
		//fmt.Println("\n wait for the stream to be received")
		req, err := stream.Recv()
		if err != nil {
			fmt.Println("Connection terminated with err: ", err)
			return
		}
		//fmt.Println("\n\n **** $$$$$ received the msg, now send it the main function", req.Node.Id)
		discoveryReqCh <- req
	}
}

// StreamSecrets is the function invoked by the envoy in-order to pull the certs, this also sends the response back to the envoy.
// It does the following:
// 1. create a receiver thread to stream the requests.
// 2. parse the discovery request.
// 3. track the request.
// 4. call the Aporeto api to generate the secret
func (s *SdsServer) StreamSecrets(stream sds.SecretDiscoveryService_StreamSecretsServer) error {
	fmt.Println("IN stream secret")
	ctx := stream.Context()
	token := ""
	metadata, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return fmt.Errorf("unable to get metadata from incoming context")
	}
	if h, ok := metadata["authorization"]; ok {
		if len(h) != 1 {
			return fmt.Errorf("credential token from %q must have 1 value in gRPC metadata but got %d", "authorization", len(h))
		}
		token = h[0]
	}
	fmt.Println("IN stream secrets, token: ", token, len(token))

	// create new connection
	conn := &clientConn{}

	discoveryReqCh := make(chan *v2.DiscoveryRequest, 1)
	go startStreaming(stream, discoveryReqCh)

	for {
		// wait for the receiver thread to stream the request and send it to us over here.
		select {
		case req, ok := <-discoveryReqCh:
			fmt.Println("got the req to be processed by start streaming", req)
			if req.ErrorDetail != nil {
				fmt.Println("ERROR from envoy for processing the resource: ", req.ResourceNames, " with error: ", req.ErrorDetail.GoString())
				continue
			}
			// Now check the following:
			// 1. Return if stream is closed.
			// 2. Return if its invalid request.
			if !ok {
				//fmt.Println("Receiver channel closed, which means the Receiver stream is closed")
				return fmt.Errorf("Receiver closed the channel")
			}
			// if req.Node == nil {
			// 	fmt.Println("unknow/invalid request from the envoy")
			// 	return fmt.Errorf("unknow/invalid request from the envoy")
			// }
			// the node will be present only only in the 1st message according to the xds protocol
			if req.Node != nil {
				//fmt.Println("the 1st request came from envoy: ", req.Node.Id, req.Node.Cluster)
			}
			// now according to the Istio pilot SDS secret config we have 2 configs, this configs are pushed to envoy through Istio.
			// 1. SDSDefaultResourceName is the default name in sdsconfig, used for fetching normal key/cert.
			// 2. SDSRootResourceName is the sdsconfig name for root CA, used for fetching root cert.
			// therefore from the above we receive 2 requests, 1 for default and 2 for the ROOTCA

			// now check for the resourcename, it should atleast have one, else continue and stream the next request.
			// according to the defination this could be empty.
			if len(req.ResourceNames) == 0 || len(req.ResourceNames) > 1 {
				continue
			}
			//resourceName := req.ResourceNames[0]
			//fmt.Println("ABHI, envoy-trireme the req resource name is: ", req.ResourceNames)
			conn.clientID = req.Node.GetId()
			if len(conn.connectionID) == 0 {
				conn.connectionID = createConnID(conn.clientID)
			}
			// if this is not the 1st request and if the secret is already present then dont proceed as this is a ACK according to the XDS protocol.
			if req.VersionInfo != "" || s.checkSecretPresent(conn.connectionID, req, token) {
				fmt.Println("Received SDS ACK from %q, connectionID %q, resourceName %q, versionInfo %q\n", req.Node.Id, conn.connectionID, req.ResourceNames[0], req.VersionInfo)
				continue
			}

			secret := s.generateSecret(req, token)
			if secret == nil {
				fmt.Println("\n the Certs cannot be served so return nil")
				return fmt.Errorf("the aporeto SDS server cannot generate server, the certs are nil")
			}
			s.secretcache.store(conn.connectionID, secret)
			// TODO: now call the metadata-lib function to fetch the secrets.
			// TODO: once the secret is fetched create a discovery Response depending on the secret.

			resp := &v2.DiscoveryResponse{
				TypeUrl:     "type.googleapis.com/envoy.api.v2.auth.Secret",
				VersionInfo: secret.Version,
				Nonce:       secret.Version,
			}
			retSecret := &auth.Secret{
				Name: secret.ResourceName,
			}
			if secret.RootCert != nil {
				//fmt.Println("*** ABHI: send the root cert")
				retSecret.Type = getRootCert(secret)
			} else {
				retSecret.Type = getTLScerts(secret)
			}
			endSecret, err := types.MarshalAny(retSecret)
			if err != nil {
				fmt.Println("Cannot marshall the secret")
				continue
			}
			resp.Resources = append(resp.Resources, endSecret)
			if err = stream.Send(resp); err != nil {
				fmt.Println("Failed to send the resp cert")
				return err
			}
			if secret.RootCert != nil {
				fmt.Println("\n\n ** Successfully sent root cert: ", string(secret.RootCert))
			} else {
				fmt.Println("Successfully sent default cert: ", string(secret.CertificateChain))
			}
		}
	}

}

func (s *SdsServer) checkSecretPresent(connID string, req *v2.DiscoveryRequest, token string) bool {
	val, ok := s.secretcache.load(connID)
	if !ok {
		return false
	}
	e := val.(*model.SecretItem)
	return e.ResourceName == req.ResourceNames[0] && e.Token == token && e.Version == req.VersionInfo
}
func createConnID(clientID string) string {
	fmt.Println("generated a unique ID:", clientID+string(atomic.AddUint64(&counter, 1)))
	return clientID + string(atomic.AddUint64(&counter, 1))
}

// UpdateSecrets updates the secrets
// Whenever the Envoy makes a request for certificate, the certs and keys are fetched from
// the Proxy.
func (s *SdsServer) UpdateSecrets(cert *tls.Certificate, caPool *x509.CertPool, secrets secrets.Secrets, certPEM, keyPEM string) {
	s.Lock()
	defer s.Unlock()

	s.cert = cert
	s.ca = caPool
	s.secrets = secrets
	s.certPEM = certPEM
	s.keyPEM = keyPEM
	//s.tlsClientConfig.RootCAs = caPool
	//s.metadata.UpdateSecrets([]byte(certPEM), []byte(keyPEM))
}

// FetchSecrets gets the discovery request and call the Aporeto backend to fetch the certs.
// 1. parse the discovery request.
// 2. track the request.
// 3. call the Aporeto api to generate the secret
func (s *SdsServer) FetchSecrets(ctx context.Context, req *v2.DiscoveryRequest) (*v2.DiscoveryResponse, error) {
	fmt.Println("ABHI, envoy-trireme the req resource name is: ", req.ResourceNames)
	token := ""
	metadata, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("unable to get metadata from incoming context")
	}
	if h, ok := metadata["authorization"]; ok {
		if len(h) != 1 {
			return nil, fmt.Errorf("credential token from %q must have 1 value in gRPC metadata but got %d", "authorization", len(h))
		}
		token = h[0]
	}
	fmt.Println("IN stream secrets, token: ", token, len(token))
	secret := s.generateSecret(req, token)

	// TODO: now call the metadata-lib function to fetch the secrets.
	// TODO: once the secret is fetched create a discovery Response depending on the secret.

	resp := &v2.DiscoveryResponse{
		TypeUrl: "type.googleapis.com/envoy.api.v2.auth.Secret",
	}
	retSecret := &auth.Secret{
		Name: secret.ResourceName,
	}
	if secret.RootCert != nil {
		//fmt.Println("*** ABHI: send the root cert")
		retSecret.Type = getRootCert(secret)
	} else {
		retSecret.Type = getTLScerts(secret)
	}
	endSecret, err := types.MarshalAny(retSecret)
	if err != nil {
		fmt.Println("Cannot marshall the secret")
		return nil, err
	}
	resp.Resources = append(resp.Resources, endSecret)

	if secret.RootCert != nil {
		fmt.Println("\n\n ** Successfully sent root cert: ", string(secret.RootCert))
	} else {
		fmt.Println("Successfully sent default cert: ", string(secret.CertificateChain))
	}
	return resp, nil
}

// generateSecret is the call which talks to the metadata API to fetch the certs.
func (s *SdsServer) generateSecret(req *v2.DiscoveryRequest, token string) *model.SecretItem {
	t := time.Now()
	expTime := time.Time{}
	var err error
	pemCert := []byte{}
	//keyPEM := []byte{}
	if s.puInfo.Policy == nil {
		fmt.Println("\n\n *** The policy is nil, cannot be nil.")
	}
	//fmt.Println("\n\n *** GENERATE cert in SDS, policy ptr: ", s.puInfo.Policy)
	// now fetch the certificates for the PU/Service.
	certPEM, keyPEM, _ := s.puInfo.Policy.ServiceCertificates()
	if certPEM == "" || keyPEM == "" {
		fmt.Println("SDS server the certs are empty")
		return nil
	}

	caPEM := s.secrets.PublicSecrets().CertAuthority()
	//fmt.Println("\n\n the CA returned is: ", caPEM, " and cert pem is :", certPEM)
	if req.ResourceNames[0] == "default" {
		// if strings.Contains(req.Node.Id, "httpbin") {
		// 	expTime, err = getExpTimeFromCert([]byte(serverPEM))
		// 	pemCert = []byte(serverPEM)
		// 	keyPEM = []byte(serverKEY)
		// }
		// if strings.Contains(req.Node.Id, "sleep") {
		expTime, err = getExpTimeFromCert([]byte(certPEM))
		pemCert, err = buildCertChain([]byte(certPEM), caPEM)
		if err != nil {
			fmt.Println("\n\n Cannot build the cert chain")
		}
		//pemCert = []byte(certPEM)
		//keyPEM = []byte(keyPEM)
		//}
	} else {
		expTime, err = getExpTimeFromCert([]byte(caPEM))
		//pemCert = []byte(caPEM)
		pemCert, err = getTopRootCa(caPEM)
		//fmt.Println(string(pemCert))
		if err != nil {
			fmt.Println("\n\n Cannot build the Root cert chain")
		}
		//keyPEM = []byte()
	}
	if err != nil {
		fmt.Println("cannot get exp time", err)
		return nil
	}
	if req.ResourceNames[0] == "default" {
		return &model.SecretItem{
			CertificateChain: pemCert,
			PrivateKey:       []byte(keyPEM),
			ResourceName:     req.ResourceNames[0],
			Token:            token,
			CreatedTime:      t,
			ExpireTime:       expTime,
			Version:          t.String(),
		}
	}

	return &model.SecretItem{
		RootCert:     pemCert,
		ResourceName: req.ResourceNames[0],
		Token:        token,
		CreatedTime:  t,
		ExpireTime:   expTime,
		Version:      t.String(),
	}

}

func buildCertChain(certPEM, caPEM []byte) ([]byte, error) {
	fmt.Println("\n\n BEFORE in buildCertChain \n\n ", "certPEM: ", string(certPEM), "\n\n", "caPEM: ", string(caPEM))
	certChain := []*x509.Certificate{}
	//certPEMBlock := caPEM
	clientPEMBlock := certPEM
	derBlock, _ := pem.Decode(clientPEMBlock)
	if derBlock != nil {
		if derBlock.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(derBlock.Bytes)
			if err != nil {
				return nil, err
			}
			certChain = append(certChain, cert)
		} else {
			return nil, fmt.Errorf("invalid pem block type: %s", derBlock.Type)
		}
	}
	var certDERBlock *pem.Block
	for {
		certDERBlock, caPEM = pem.Decode(caPEM)
		if certDERBlock == nil {
			break
		}
		//fmt.Println("\n cert: ", string(certDERBlock.Type))
		if certDERBlock.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(certDERBlock.Bytes)
			if err != nil {
				return nil, err
			}
			certChain = append(certChain, cert)
		} else {
			return nil, fmt.Errorf("invalid pem block type: %s", certDERBlock.Type)
		}
	}
	fmt.Println("After building the cert chain: ", certChain, "\n\n ")
	by, _ := x509CertChainToPem(certChain)
	fmt.Println("\n\n AFTER in buildCertChain \n\n ", "certPEM: ", string(by))
	return x509CertChainToPem(certChain)
}

func x509CertToPem(cert *x509.Certificate) ([]byte, error) {
	var pemBytes bytes.Buffer
	if err := pem.Encode(&pemBytes, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		return nil, err
	}
	return pemBytes.Bytes(), nil
}
func x509CertChainToPem(certChain []*x509.Certificate) ([]byte, error) {
	var pemBytes bytes.Buffer
	for _, cert := range certChain {
		//fmt.Println("\n\n Cert subj: ", cert.)
		if err := pem.Encode(&pemBytes, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return nil, err
		}
	}
	return pemBytes.Bytes(), nil
}

//var pemStart = []byte("\n-----BEGIN ")

//-----BEGIN
// getTopRootCa get the top root CA
func getTopRootCa(certPEMBlock []byte) ([]byte, error) {
	fmt.Println("BEFORE root cert is :", string(certPEMBlock))
	//rootCert := []*x509.Certificate{}
	var certChain tls.Certificate
	//certPEMBlock := []byte(rootcaBundle)
	var certDERBlock *pem.Block
	for {
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}
		//fmt.Println("\n cert: ", string(certDERBlock.Type))
		if certDERBlock.Type == "CERTIFICATE" {
			certChain.Certificate = append(certChain.Certificate, certDERBlock.Bytes)
		}
	}
	fmt.Println(" the root ca is:", certChain.Certificate[len(certChain.Certificate)-1])
	x509Cert, err := x509.ParseCertificate(certChain.Certificate[len(certChain.Certificate)-1])
	if err != nil {
		panic(err)
	}
	fmt.Println("\n\n *** root cert serial number: ***", x509Cert.SerialNumber)
	//
	by, _ := x509CertToPem(x509Cert)
	fmt.Println("AFTER the root cert: ", string(by))
	return x509CertToPem(x509Cert)
}

// getExpTimeFromCert gets the exp time from the cert, assumning the cert is in pem encoded.
func getExpTimeFromCert(cert []byte) (time.Time, error) {
	block, _ := pem.Decode(cert)
	if block == nil {
		zap.L().Error("getExpTimeFromCert: error while pem decode")
		return time.Time{}, fmt.Errorf("Cannot decode the pem certs")
	}
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		zap.L().Error("failed to parse the certs", zap.Error(err))
		return time.Time{}, err
	}
	return x509Cert.NotAfter, nil
}

func getRootCert(secret *model.SecretItem) *auth.Secret_ValidationContext {
	return &auth.Secret_ValidationContext{
		ValidationContext: &auth.CertificateValidationContext{
			TrustedCa: &core.DataSource{
				Specifier: &core.DataSource_InlineBytes{
					InlineBytes: secret.RootCert,
				},
			},
		},
	}
}

func getTLScerts(secret *model.SecretItem) *auth.Secret_TlsCertificate {
	return &auth.Secret_TlsCertificate{
		TlsCertificate: &auth.TlsCertificate{
			CertificateChain: &core.DataSource{
				Specifier: &core.DataSource_InlineBytes{
					InlineBytes: secret.CertificateChain,
				},
			},
			PrivateKey: &core.DataSource{
				Specifier: &core.DataSource_InlineBytes{
					InlineBytes: secret.PrivateKey,
				},
			},
		},
	}
}
