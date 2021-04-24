package sds

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"time"

	"context"

	"go.uber.org/zap"
	"google.golang.org/grpc"

	v2 "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/auth"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	sds "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v2"
	"github.com/gogo/protobuf/types"
	"istio.io/istio/security/pkg/nodeagent/model"
)

// for testing/POC purpose just add the manually created certificates.
var (
	defaultPEM = `
-----BEGIN CERTIFICATE-----
MIIBcjCCARigAwIBAgIRANdSVgeGQ1MmZNBLBAsTPbswCgYIKoZIzj0EAwIwHjEN
MAsGA1UEChMEYWNtZTENMAsGA1UEAxMEcm9vdDAeFw0xOTA5MTcwMDM4MDdaFw0y
OTA3MjYwMDM4MDdaMCAxDTALBgNVBAoTBGFjbWUxDzANBgNVBAMTBnNlcnZlcjBZ
MBMGByqGSM49AgEGCCqGSM49AwEHA0IABMssoKX7OnfBXttYTf3TtFE7uJwveyED
xDrZzffzXCXvgkhEA8Llri32e+uJk0OKEzFrS0gsH5tNPwYkSa0zaJ6jNTAzMA4G
A1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAA
MAoGCCqGSM49BAMCA0gAMEUCIQCPWNVRhmfHsctDfbRrRz9kcwr2jpPSm68A4P9P
0AMlSAIgOmoxQS3EVJGkYgUap6aHM+82u1RBrRXgzu9jMuWdsMo=
-----END CERTIFICATE-----`
	defaultKey = `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBe4TlWfJnq3VWLy+uHLg4zd1EsdRTJkOVCI4Mf8EwdyoAoGCCqGSM49
AwEHoUQDQgAEyyygpfs6d8Fe21hN/dO0UTu4nC97IQPEOtnN9/NcJe+CSEQDwuWu
LfZ764mTQ4oTMWtLSCwfm00/BiRJrTNong==
-----END EC PRIVATE KEY-----`
	rootPEM = `
-----BEGIN CERTIFICATE-----
MIIBXTCCAQSgAwIBAgIRANHUhGwjacv0a/34X5D9cJEwCgYIKoZIzj0EAwIwHjEN
MAsGA1UEChMEYWNtZTENMAsGA1UEAxMEcm9vdDAeFw0xOTA5MTYxODQzMDFaFw0y
OTA3MjUxODQzMDFaMB4xDTALBgNVBAoTBGFjbWUxDTALBgNVBAMTBHJvb3QwWTAT
BgcqhkjOPQIBBggqhkjOPQMBBwNCAARJI8STC0WVw5sQ/Ija0nrYKIBZO43iifs0
tsk7coRZwaYM7MEEr1qIOk+LmtR3DIGQTWva19u/56inYCTwDA7UoyMwITAOBgNV
HQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiBO
DMNgviNbjkZPE4RcldmEEBfHpPgMDir4jJhRGS624QIgMojinDUARNuyzQA4/B98
pnICnBfAt0aiZojITEqCDDc=
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

// Server to talk with envoy.
type Server struct {
	sdsGrpcServer   *grpc.Server
	sdsGrpcListener net.Listener

	errCh chan error
}

// NewServer creates a instance of a server.
func NewServer() Server {
	return Server{errCh: make(chan error)}
}

// CreateSdsService does the following
// 1. create grpc server.
// 2. create a listener on the Unix Domain Socket.
// 3.
func (s Server) CreateSdsService(options *Options) error { //nolint: unparam
	fmt.Println("ABHI, envoy-trireme create  SDS server")
	s.sdsGrpcServer = grpc.NewServer()
	s.register(s.sdsGrpcServer)
	if err := os.Remove(options.SocketPath); err != nil && !os.IsNotExist(err) {
		fmt.Println("ABHI, envoy-reireme, failed to remove the udspath", err)
		return err
	}
	fmt.Println("Start listening on UDS path: ", options.SocketPath)
	sdsGrpcListener, err := net.Listen("unix", options.SocketPath)
	if err != nil {
		fmt.Println("cannot listen on the socketpath", err)
		return err
	}
	// make sure the socket path can be accessed.
	if _, err := os.Stat(options.SocketPath); err != nil {
		fmt.Println("SDS uds file %q doesn't exist", options.SocketPath)
		return fmt.Errorf("sds uds file %q doesn't exist", options.SocketPath)
	}
	if err := os.Chmod(options.SocketPath, 0666); err != nil {
		fmt.Println("Failed to update %q permission", options.SocketPath)
		return fmt.Errorf("failed to update %q permission", options.SocketPath)
	}
	//var err error
	s.sdsGrpcListener = sdsGrpcListener

	fmt.Println("run the grpc server")
	s.Run()
	return nil
}

// Run starts the sdsGrpcServer to serve
func (s Server) Run() {
	go func() {
		if s.sdsGrpcListener != nil {
			if err := s.sdsGrpcServer.Serve(s.sdsGrpcListener); err != nil {
				fmt.Println("got error after serve", err)
				s.errCh <- err
			}
		}
		fmt.Println("the listener is nil, cannot start the server")
	}()
}

// Stop stops all the listeners and the grpc servers.
func (s Server) Stop() {
	if s.sdsGrpcListener != nil {
		s.sdsGrpcListener.Close()
	}
	if s.sdsGrpcServer != nil {
		s.sdsGrpcServer.Stop()
	}
}

// register adds the SDS handle to the grpc server
func (s Server) register(sdsGrpcServer *grpc.Server) {
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
func (s Server) DeltaSecrets(stream sds.SecretDiscoveryService_DeltaSecretsServer) error {
	return nil
}

func startStreaming(stream SecretDiscoveryStream, discoveryReqCh chan *v2.DiscoveryRequest) {
	fmt.Println("In start streaming")
	defer close(discoveryReqCh)
	for {
		fmt.Println("\n wait for the stream to be received")
		req, err := stream.Recv()
		if err != nil {
			fmt.Println("Connection terminated with err: ", err)
			return
		}
		fmt.Println("\n\n **** $$$$$ received the msg, now send it the main function", req.Node.Id)
		discoveryReqCh <- req
	}
}

// StreamSecrets is the function invoked by the envoy in-order to pull the certs, this also sends the response back to the envoy.
// It does the following:
// 1. create a receiver thread to stream the requests.
// 2. parse the discovery request.
// 3. track the request.
// 4. call the Aporeto api to generate the secret
func (s Server) StreamSecrets(stream sds.SecretDiscoveryService_StreamSecretsServer) error {
	fmt.Println("IN stream secret")
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
				fmt.Println("Receiver channel closed, which means the Receiver stream is closed")
				return fmt.Errorf("Receiver closed the channel")
			}
			// if req.Node == nil {
			// 	fmt.Println("unknow/invalid request from the envoy")
			// 	return fmt.Errorf("unknow/invalid request from the envoy")
			// }
			// the node will be present only only in the 1st message according to the xds protocol
			if req.Node != nil {
				fmt.Println("the 1st request came from envoy: ", req.Node.Id, req.Node.Cluster)
			}
			// now according to the Istio pilot SDS secret config we have 2 configs, this configs are pushed to envoy through Istio.
			// 1. SDSDefaultResourceName is the default name in sdsconfig, used for fetching normal key/cert.
			// 2. SDSRootResourceName is the sdsconfig name for root CA, used for fetching root cert.
			// therefore from the above we receive 2 requests, 1 for default and 2 for the ROOTCA

			// now check for the resourcename, it should atleast have one, else continue and stream the next request.
			// according to the defination this could be empty.
			if len(req.ResourceNames) == 0 {
				continue
			}
			fmt.Println("ABHI, envoy-trireme the req resource name is: ", req.ResourceNames)

			secret := generateSecret(req)

			// TODO: now call the metadata-lib function to fetch the secrets.
			// TODO: once the secret is fetched create a discovery Response depending on the secret.

			resp := &v2.DiscoveryResponse{
				TypeUrl: "type.googleapis.com/envoy.api.v2.auth.Secret",
			}
			retSecret := &auth.Secret{
				Name: secret.ResourceName,
			}
			if secret.RootCert != nil {
				fmt.Println("*** ABHI: send the root cert")
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

// FetchSecrets gets the discovery request and call the Aporeto backend to fetch the certs.
// 1. parse the discovery request.
// 2. track the request.
// 3. call the Aporeto api to generate the secret
func (s Server) FetchSecrets(ctx context.Context, discReq *v2.DiscoveryRequest) (*v2.DiscoveryResponse, error) {
	return nil, nil
}

// generateSecret is the call which talks to the metadata API to fetch the certs.
func generateSecret(req *v2.DiscoveryRequest) *model.SecretItem {
	t := time.Now()
	expTime := time.Time{}
	var err error
	pemCert := []byte{}
	if req.ResourceNames[0] == "default" {
		expTime, err = getExpTimeFromCert([]byte(defaultPEM))
		pemCert = []byte(defaultPEM)
	} else {
		expTime, err = getExpTimeFromCert([]byte(rootPEM))
		pemCert = []byte(rootPEM)
	}
	if err != nil {
		fmt.Println("cannot get exp time", err)
		return nil
	}
	if req.ResourceNames[0] == "default" {
		return &model.SecretItem{
			CertificateChain: pemCert,
			PrivateKey:       []byte(defaultKey),
			ResourceName:     req.ResourceNames[0],
			Token:            "",
			CreatedTime:      t,
			ExpireTime:       expTime,
			Version:          t.String(),
		}
	}

	return &model.SecretItem{
		RootCert:     pemCert,
		ResourceName: req.ResourceNames[0],
		Token:        "",
		CreatedTime:  t,
		ExpireTime:   expTime,
		Version:      t.String(),
	}

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
