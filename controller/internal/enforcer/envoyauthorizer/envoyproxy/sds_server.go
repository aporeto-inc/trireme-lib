package envoyproxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"time"

	"context"

	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/cache"
	"go.uber.org/zap"
	"google.golang.org/grpc"

	v2 "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	envoy_api_v2_auth "github.com/envoyproxy/go-control-plane/envoy/api/v2/auth"
	envoy_api_v2_core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	sds "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v2"
	"github.com/ericrpowers/go-deadlock"

	"github.com/golang/protobuf/ptypes"
	//"github.com/gogo/protobuf/types"
	"google.golang.org/grpc/metadata"
)

const (
	// SdsSocketpath is the socket path on which the envoy will talk to the remoteEnforcer.
	//SdsSocketpath = "@aporeto_envoy_sds"
	SdsSocketpath = "127.0.0.1:2999"
	//SdsSocketpath = "/var/run/sds/uds_path"
	typeCertificate = "CERTIFICATE"
)

// Options to create a SDS server to task to envoy
type Options struct {
	SocketPath string
}

// sdsCerts is the structure will pass the upstream certs downwards.
type sdsCerts struct {
	key    string
	cert   string
	caPool *x509.CertPool
}

// SdsDiscoveryStream is the same as the sds.SecretDiscoveryService_StreamSecretsServer
type SdsDiscoveryStream interface {
	Send(*v2.DiscoveryResponse) error
	Recv() (*v2.DiscoveryRequest, error)
	grpc.ServerStream
}

var _ sds.SecretDiscoveryServiceServer = &SdsServer{}

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
	deadlock.RWMutex
	// conncache is a cache of the sdsConnection, here the key is the connectionID and val is the secret.
	conncache cache.DataStore
	// updCertsChannel is used whenever there is a cert-update/Enfore
	updCertsChannel chan sdsCerts
	connMap         map[string]bool
}

type secretItem struct {
	CertificateChain []byte
	PrivateKey       []byte

	RootCert []byte

	// RootCertOwnedByCompoundSecret is true if this SecretItem was created by a
	// K8S secret having both server cert/key and client ca and should be deleted
	// with the secret.
	RootCertOwnedByCompoundSecret bool

	// ResourceName passed from envoy SDS discovery request.
	// "ROOTCA" for root cert request, "default" for key/cert request.
	ResourceName string

	// Credential token passed from envoy, caClient uses this token to send
	// CSR to CA to sign certificate.
	Token string

	// Version is used(together with token and ResourceName) to identify discovery request from
	// envoy which is used only for confirm purpose.
	Version string

	CreatedTime time.Time

	ExpireTime time.Time
}

// clientConn is ID for the connection between client and SDS server.
type clientConn struct {
	clientID string
	// the TLS cert information cached for this particular connection
	secret *secretItem

	// connectionID is the ID for each new request, make it a combo of nodeID+counter.
	connectionID string
	stream       SdsDiscoveryStream
}

// NewSdsServer creates a instance of a server.
func NewSdsServer(contextID string, puInfo *policy.PUInfo, caPool *x509.CertPool, secrets secrets.Secrets) (*SdsServer, error) {
	if puInfo == nil {
		zap.L().Error("SDS Server: puInfo NIL ")
		return nil, fmt.Errorf("the puinfo cannot be nil")
	}

	sdsOptions := &Options{SocketPath: SdsSocketpath}
	sdsServer := &SdsServer{
		puInfo:          puInfo,
		ca:              caPool,
		errCh:           make(chan error),
		secrets:         secrets,
		conncache:       cache.NewCache("servers"),
		updCertsChannel: make(chan sdsCerts),
		connMap:         make(map[string]bool),
	}
	if err := sdsServer.CreateSdsService(sdsOptions); err != nil {
		zap.L().Error("SDS Server:Error while starting the envoy sds server.")
		return nil, err
	}
	zap.L().Debug("SDS Server: SDS start success for :", zap.String("pu: ", puInfo.ContextID))
	return sdsServer, nil
}

// CreateSdsService does the following
// 1. create grpc server.
// 2. create a listener on the Unix Domain Socket.
// 3.
func (s *SdsServer) CreateSdsService(options *Options) error { //nolint: unparam
	s.sdsGrpcServer = grpc.NewServer()
	s.register(s.sdsGrpcServer)

	addr, err := net.ResolveTCPAddr("tcp", options.SocketPath)
	if err != nil {
		return err
	}
	nl, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}
	// if err := os.Remove(options.SocketPath); err != nil && !os.IsNotExist(err) {
	// 	zap.L().Error("SDS Server: envoy-reireme, failed to remove the udspath", zap.Error(err))
	// 	return err
	// }
	// zap.L().Debug("SDS Server: Start listening on UDS path: ", zap.Any("socketPath: ", options.SocketPath))
	// addr, _ := net.ResolveUnixAddr("unix", options.SocketPath)

	// sdsGrpcListener, err := net.ListenUnix("unix", addr)
	// if err != nil {
	// 	zap.L().Error("SDS Server:cannot listen on the socketpath", zap.Error(err))
	// 	return err
	// }
	// //make sure the socket path can be accessed.
	// if _, err := os.Stat(options.SocketPath); err != nil {
	// 	zap.L().Error("SDS Server: SDS uds file doesn't exist", zap.String("socketPath:", options.SocketPath))
	// 	return fmt.Errorf("sds uds file %q doesn't exist", options.SocketPath)
	// }
	// if err := os.Chmod(options.SocketPath, 0666); err != nil {
	// 	zap.L().Error("SDS Server: Failed to update permission", zap.String("socketPath:", options.SocketPath))
	// 	return fmt.Errorf("failed to update %q permission", options.SocketPath)
	// }
	s.sdsGrpcListener = nl

	zap.L().Debug("SDS Server: run the grpc server at: ", zap.Any("addr: ", s.sdsGrpcListener.Addr()))
	s.Run()
	return nil
}

// Run starts the sdsGrpcServer to serve
func (s *SdsServer) Run() {
	go func() {
		if s.sdsGrpcListener != nil {
			if err := s.sdsGrpcServer.Serve(s.sdsGrpcListener); err != nil {
				zap.L().Error("SDS Server: Error while serve", zap.Error(err))
				s.errCh <- err
			}
		}
		zap.L().Error("SDS Server: the listener is nil, cannot start the SDS server for: ", zap.String("puID: ", s.puInfo.ContextID))
	}()
}

// Stop stops all the listeners and the grpc servers.
func (s *SdsServer) Stop() {
	if s.sdsGrpcListener != nil {
		s.sdsGrpcListener.Close() //nolint
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
	zap.L().Debug("SDS Server:  envoy-trireme registering the secret discovery")
	sds.RegisterSecretDiscoveryServiceServer(sdsGrpcServer, s)
}

// UpdateSecrets updates the secrets
// Whenever the Envoy makes a request for certificate, the certs and keys are fetched from
// the Proxy.
func (s *SdsServer) UpdateSecrets(cert *tls.Certificate, caPool *x509.CertPool, secrets secrets.Secrets, certPEM, keyPEM string) {
	s.Lock()
	defer s.Unlock()

	s.cert = cert
	s.ca = caPool
	//s.secrets = secrets
	s.certPEM = certPEM
	s.keyPEM = keyPEM
	s.updCertsChannel <- sdsCerts{key: keyPEM, cert: certPEM, caPool: caPool}
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

func startStreaming(stream SdsDiscoveryStream, discoveryReqCh chan *v2.DiscoveryRequest) {
	defer close(discoveryReqCh)
	for {
		req, err := stream.Recv()
		if err != nil {
			zap.L().Error("SDS Server: Connection terminated with err: ", zap.Error(err))
			return
		}
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
	zap.L().Debug("SDS Server: IN stream secrets, token: ", zap.String("token: ", token))

	// create new connection
	conn := &clientConn{}
	conn.stream = stream
	discoveryReqCh := make(chan *v2.DiscoveryRequest, 1)
	go startStreaming(stream, discoveryReqCh)

	for {
		// wait for the receiver thread to stream the request and send it to us over here.
		select {
		case req, ok := <-discoveryReqCh:
			// if req == nil {
			// 	zap.L().Warn("SDS Server: The request is nil")
			// 	continue
			// }
			// Now check the following:
			// 1. Return if stream is closed.
			// 2. Return if its invalid request.
			if !ok {
				zap.L().Error("SDS Server: Receiver channel closed, which means the Receiver stream is closed")
				return fmt.Errorf("Receiver closed the channel")
			}
			// then check for the req.Node
			if req.Node == nil {
				zap.L().Error("Invalid discovery request with no node")
				return fmt.Errorf("invalid discovery request with no node")
			}
			if req.ErrorDetail != nil {
				zap.L().Error("SDS Server: ERROR from envoy for processing the resource: ", zap.String("error: ", req.GetErrorDetail().String()))
				continue
			}

			// now according to the Istio pilot SDS secret config we have 2 configs, this configs are pushed to envoy through Istio.
			// 1. SDSDefaultResourceName is the default name in sdsconfig, used for fetching normal key/cert.
			// 2. SDSRootResourceName is the sdsconfig name for root CA, used for fetching root cert.
			// therefore from the above we receive 2 requests, 1 for default and 2 for the ROOTCA

			// now check for the resourcename, it should atleast have one, else continue and stream the next request.
			// according to the definition this could be empty.
			if len(req.ResourceNames) == 0 {
				continue
			}
			if len(req.ResourceNames) > 1 {
				return fmt.Errorf("SDS Server: invalid resourceNames, greater than one")
			}
			resourceName := req.ResourceNames[0]
			conn.clientID = req.Node.GetId()
			//if len(conn.connectionID) == 0 {
			conn.connectionID = createConnID(conn.clientID, resourceName)

			// if this is not the 1st request and if the secret is already present then dont proceed as this is a ACK according to the XDS protocol.
			if req.VersionInfo != "" && s.checkSecretPresent(conn.connectionID, req, token) {
				zap.L().Warn("SDS Server: got a ACK from envoy ", zap.String("connectionID", conn.connectionID), zap.String("resourceName: ", resourceName), zap.String("version", req.VersionInfo))
				continue
			}
			secret := s.generateSecret(req, token)
			if secret == nil {
				zap.L().Error("SDS Server: the Certs cannot be served so return nil")
				return fmt.Errorf("the aporeto SDS server cannot generate server, the certs are nil")
			}
			conn.secret = secret
			s.conncache.AddOrUpdate(conn.connectionID, conn)

			resp := &v2.DiscoveryResponse{
				TypeUrl:     "type.googleapis.com/envoy.api.v2.auth.Secret",
				VersionInfo: secret.Version,
				Nonce:       secret.Version,
			}
			retSecret := &envoy_api_v2_auth.Secret{
				Name: secret.ResourceName,
			}
			if secret.RootCert != nil {
				retSecret.Type = getRootCert(secret)
			} else {
				retSecret.Type = getTLScerts(secret)
			}
			endSecret, err := ptypes.MarshalAny(retSecret)
			if err != nil {
				zap.L().Error("SDS Server: Cannot marshall the secret", zap.Error(err))
				continue
			}
			resp.Resources = append(resp.Resources, endSecret)
			if err = stream.Send(resp); err != nil {
				zap.L().Error("SDS Server: Failed to send the resp cert", zap.Error(err))
				return err
			}
			if secret.RootCert != nil {
				zap.L().Debug("SDS Server: Successfully sent root cert: ", zap.String("rootCA: ", string(secret.RootCert)))
			} else {
				zap.L().Debug("SDS Server: Successfully sent default cert: ", zap.String("default cert: ", string(secret.CertificateChain)))
			}
		case updateCerts := <-s.updCertsChannel:
			// 1st check if the connection is present

			_, err := s.conncache.Get(conn.connectionID)
			if err != nil {
				zap.L().Warn("SDS server: updCertsChannel, no connID found in cache,", zap.String("connID", conn.connectionID))
				continue
			}
			fmt.Println("connID found now send certs")
			if updateCerts.key != "" && updateCerts.cert != "" {
				if err := s.sendUpdatedCerts(updateCerts, conn); err != nil {
					zap.L().Error("SDS Server: send updated certs failed", zap.Error(err))
				}
			}
		}
	}

}

func (s *SdsServer) sendUpdatedCerts(apoSecret sdsCerts, conn *clientConn) error {
	var err error
	pemCert := []byte{} //nolint
	t := time.Now()

	if apoSecret.key != "" && apoSecret.cert != "" {
		caPEM := s.secrets.PublicSecrets().CertAuthority()

		pemCert, err = buildCertChain([]byte(apoSecret.cert), caPEM)
		if err != nil {
			zap.L().Error("SDS Server: Cannot build the cert chain")
			return fmt.Errorf("SDS Server: Cannot build the cert chain")
		}

		resp := &v2.DiscoveryResponse{
			TypeUrl:     "type.googleapis.com/envoy.api.v2.auth.Secret",
			VersionInfo: t.String(),
			Nonce:       t.String(),
		}
		retSecret := &envoy_api_v2_auth.Secret{
			Name: "default",
		}

		retSecret.Type = &envoy_api_v2_auth.Secret_TlsCertificate{
			TlsCertificate: &envoy_api_v2_auth.TlsCertificate{
				CertificateChain: &envoy_api_v2_core.DataSource{
					Specifier: &envoy_api_v2_core.DataSource_InlineBytes{
						InlineBytes: pemCert,
					},
				},
				PrivateKey: &envoy_api_v2_core.DataSource{
					Specifier: &envoy_api_v2_core.DataSource_InlineBytes{
						InlineBytes: []byte(apoSecret.key),
					},
				},
			},
		}

		endSecret, err := ptypes.MarshalAny(retSecret)
		if err != nil {
			zap.L().Error("SDS Server: Cannot marshall the secret")
			return fmt.Errorf("SDS Server: Cannot marshall the secret")
		}

		resp.Resources = append(resp.Resources, endSecret)
		if err = conn.stream.Send(resp); err != nil {
			zap.L().Error("SDS Server: Failed to send the resp cert")
			return err
		}

	}
	return nil
}

func (s *SdsServer) checkSecretPresent(connID string, req *v2.DiscoveryRequest, token string) bool {
	val, err := s.conncache.Get(connID)
	if err != nil {
		return false
	}
	e := val.(*clientConn)
	return e.secret.ResourceName == req.ResourceNames[0] && e.secret.Token == token && e.secret.Version == req.VersionInfo
}

func createConnID(clientID, resourceName string) string {
	temp := clientID + resourceName
	zap.L().Debug("SDS Server: generated a unique ID:", zap.String("connID: ", temp), zap.String("resource: ", resourceName))
	return temp
}

// FetchSecrets gets the discovery request and call the Aporeto backend to fetch the certs.
// 1. parse the discovery request.
// 2. track the request.
// 3. call the Aporeto api to generate the secret
func (s *SdsServer) FetchSecrets(ctx context.Context, req *v2.DiscoveryRequest) (*v2.DiscoveryResponse, error) {
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
	zap.L().Info("SDS Server: IN stream secrets, token: ", zap.String("token: ", token))
	secret := s.generateSecret(req, token)

	resp := &v2.DiscoveryResponse{
		TypeUrl: "type.googleapis.com/envoy.api.v2.auth.Secret",
	}
	retSecret := &envoy_api_v2_auth.Secret{
		Name: secret.ResourceName,
	}
	if secret.RootCert != nil {
		retSecret.Type = getRootCert(secret)
	} else {
		retSecret.Type = getTLScerts(secret)
	}
	endSecret, err := ptypes.MarshalAny(retSecret)
	if err != nil {
		zap.L().Error("SDS Server: Cannot marshall the secret")
		return nil, err
	}
	resp.Resources = append(resp.Resources, endSecret)

	if secret.RootCert != nil {
		zap.L().Debug("SDS Server:  Successfully sent root cert: ", zap.Any("rootCA: ", string(secret.RootCert)))
	} else {
		zap.L().Debug("SDS Server: Successfully sent default cert: ", zap.Any("default cert: ", string(secret.CertificateChain)))
	}
	return resp, nil
}

// generateSecret is the call which talks to the metadata API to fetch the certs.
func (s *SdsServer) generateSecret(req *v2.DiscoveryRequest, token string) *secretItem {

	var err error
	var pemCert []byte
	t := time.Now()
	var expTime time.Time

	if s.puInfo.Policy == nil {
		zap.L().Error("SDS Server:  The policy is nil, Policy cannot be nil.")
	}
	// now fetch the certificates for the PU/Service.
	certPEM, keyPEM, _ := s.puInfo.Policy.ServiceCertificates()
	if certPEM == "" || keyPEM == "" {
		zap.L().Error("SDS Server:  the certs are empty")
		return nil
	}

	caPEM := s.secrets.PublicSecrets().CertAuthority()
	if req.ResourceNames[0] == "default" {

		expTime, _ = getExpTimeFromCert([]byte(certPEM))
		pemCert, _ = buildCertChain([]byte(certPEM), caPEM)
		if err != nil {
			zap.L().Error("SDS Server: Cannot build the cert chain")
			return nil
		}

	} else {

		expTime, _ = getExpTimeFromCert(caPEM)
		pemCert, err = getTopRootCa(caPEM)
		if err != nil {
			zap.L().Error("SDS Server:  Cannot build the Root cert chain")
		}
	}
	if err != nil {
		zap.L().Error("SDS Server: cannot get exp time", zap.Error(err))
		return nil
	}
	if req.ResourceNames[0] == "default" {
		return &secretItem{
			CertificateChain: pemCert,
			PrivateKey:       []byte(keyPEM),
			//PrivateKey:   []byte(keyPEMdebug),
			ResourceName: req.ResourceNames[0],
			Token:        token,
			CreatedTime:  t,
			ExpireTime:   expTime,
			Version:      t.String(),
		}
	}

	return &secretItem{
		RootCert:     pemCert,
		ResourceName: req.ResourceNames[0],
		Token:        token,
		CreatedTime:  t,
		ExpireTime:   expTime,
		Version:      t.String(),
	}

}

func buildCertChain(certPEM, caPEM []byte) ([]byte, error) {
	zap.L().Debug("SDS Server:  BEFORE in buildCertChain certPEM: ", zap.String("certPEM:", string(certPEM)), zap.String("caPEM: ", string(caPEM)))
	certChain := []*x509.Certificate{}
	//certPEMBlock := caPEM
	clientPEMBlock := certPEM
	derBlock, _ := pem.Decode(clientPEMBlock)
	if derBlock != nil {
		if derBlock.Type == typeCertificate {
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
		if certDERBlock.Type == typeCertificate {
			cert, err := x509.ParseCertificate(certDERBlock.Bytes)
			if err != nil {
				return nil, err
			}
			certChain = append(certChain, cert)
		} else {
			return nil, fmt.Errorf("invalid pem block type: %s", certDERBlock.Type)
		}
	}
	by, _ := x509CertChainToPem(certChain)
	zap.L().Debug("SDS Server: After building the cert chain: ", zap.String("certChain: ", string(by)))
	return x509CertChainToPem(certChain)
}

// x509CertToPem converts x509 to byte.
func x509CertToPem(cert *x509.Certificate) ([]byte, error) {
	var pemBytes bytes.Buffer
	if err := pem.Encode(&pemBytes, &pem.Block{Type: typeCertificate, Bytes: cert.Raw}); err != nil {
		return nil, err
	}
	return pemBytes.Bytes(), nil
}

// x509CertChainToPem converts chain of x509 certs to byte.
func x509CertChainToPem(certChain []*x509.Certificate) ([]byte, error) {
	var pemBytes bytes.Buffer
	for _, cert := range certChain {
		if err := pem.Encode(&pemBytes, &pem.Block{Type: typeCertificate, Bytes: cert.Raw}); err != nil {
			return nil, err
		}
	}
	return pemBytes.Bytes(), nil
}

// getTopRootCa get the top root CA
func getTopRootCa(certPEMBlock []byte) ([]byte, error) {
	zap.L().Debug("SDS Server: BEFORE root cert is :", zap.String("root_cert: ", string(certPEMBlock)))
	//rootCert := []*x509.Certificate{}
	var certChain tls.Certificate
	//certPEMBlock := []byte(rootcaBundle)
	var certDERBlock *pem.Block
	for {
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == typeCertificate {
			certChain.Certificate = append(certChain.Certificate, certDERBlock.Bytes)
		}
	}
	zap.L().Debug("SDS Server: the root ca is:", zap.String("cert: ", string(certChain.Certificate[len(certChain.Certificate)-1])))
	x509Cert, err := x509.ParseCertificate(certChain.Certificate[len(certChain.Certificate)-1])
	if err != nil {
		panic(err)
	}
	by, _ := x509CertToPem(x509Cert)
	zap.L().Debug("SDS Server: After building the cert chain: ", zap.String("rootCert: ", string(by)))
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

func getRootCert(secret *secretItem) *envoy_api_v2_auth.Secret_ValidationContext {
	return &envoy_api_v2_auth.Secret_ValidationContext{
		ValidationContext: &envoy_api_v2_auth.CertificateValidationContext{
			TrustedCa: &envoy_api_v2_core.DataSource{
				Specifier: &envoy_api_v2_core.DataSource_InlineBytes{
					InlineBytes: secret.RootCert,
				},
			},
		},
	}
}

func getTLScerts(secret *secretItem) *envoy_api_v2_auth.Secret_TlsCertificate {
	return &envoy_api_v2_auth.Secret_TlsCertificate{
		TlsCertificate: &envoy_api_v2_auth.TlsCertificate{
			CertificateChain: &envoy_api_v2_core.DataSource{
				Specifier: &envoy_api_v2_core.DataSource_InlineBytes{
					InlineBytes: secret.CertificateChain,
				},
			},
			PrivateKey: &envoy_api_v2_core.DataSource{
				Specifier: &envoy_api_v2_core.DataSource_InlineBytes{
					InlineBytes: secret.PrivateKey,
				},
			},
		},
	}
}
