package secretsproxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"go.aporeto.io/trireme-lib/common"
)

// SecretsDriver is a generic interface that the secrets driver must implement.
type SecretsDriver interface {
	Transport() http.RoundTripper
	Transform(r *http.Request) error
}

// GenericSecretsDriver holds the configuration information for the driver and implements
// the SecretsDriver interface.
type GenericSecretsDriver struct {
	transport *http.Transport
	token     string
	targetURL *url.URL
}

// NewGenericSecretsDriver creates a new Kubernetes Secrets Driver. It
// always uses the incluster config to automatically derive all the
// necessary values.
func NewGenericSecretsDriver(ca []byte, token string, network *common.Service) (SecretsDriver, error) {

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("No valid CA provided")
	}

	targetAddress := ""
	if len(network.FQDNs) > 0 {
		targetAddress = network.FQDNs[0]
	} else if len(network.Addresses) > 0 {
		targetAddress = network.Addresses[0].IP.String()
	} else {
		return nil, fmt.Errorf("No valid target")
	}

	if network.Ports.Min == 0 {
		return nil, fmt.Errorf("Invalid port specification")
	}

	targetURL, err := url.Parse("https://" + targetAddress + ":" + strconv.Itoa(int(network.Ports.Min)))
	if err != nil {
		return nil, fmt.Errorf("Invalid URL for secrets service")
	}

	return &GenericSecretsDriver{
		transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caPool,
			},
		},
		token:     token,
		targetURL: targetURL,
	}, nil
}

// Transport implements the transport interface of the SecretsDriver.
func (k *GenericSecretsDriver) Transport() http.RoundTripper {
	return k.transport
}

// Transform transforms the request of the SecretsDriver
func (k *GenericSecretsDriver) Transform(r *http.Request) error {

	r.Host = k.targetURL.Host
	r.URL = k.targetURL
	r.Header.Add("Authorization", "Bearer "+k.token)

	return nil
}
