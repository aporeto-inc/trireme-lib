package metadata

import (
	"context"
	"encoding/json"
	"time"

	"github.com/sasha-s/go-deadlock"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/apiauth"

	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/serviceregistry"
	"go.aporeto.io/trireme-lib/policy"
)

// Client is a metadata client.
type Client struct {
	puContext   string
	registry    *serviceregistry.Registry
	tokenIssuer common.ServiceTokenIssuer
	certPEM     []byte
	keyPEM      []byte

	deadlock.RWMutex
}

// NewClient returns a new metadata client
func NewClient(puContext string, r *serviceregistry.Registry, t common.ServiceTokenIssuer) *Client {
	return &Client{
		puContext:   puContext,
		registry:    r,
		tokenIssuer: t,
	}
}

// UpdateSecrets updates the secrets of the client.
func (c *Client) UpdateSecrets(cert, key []byte) {
	c.Lock()
	defer c.Unlock()

	c.certPEM = cert
	c.keyPEM = key
}

// GetCertificate returns back the certificate.
func (c *Client) GetCertificate() []byte {
	c.RLock()
	defer c.RUnlock()

	return c.certPEM
}

// GetPrivateKey returns the private key associated with this service.
func (c *Client) GetPrivateKey() []byte {
	c.RLock()
	defer c.RUnlock()

	return c.keyPEM
}

// GetCurrentPolicy returns the current policy of the datapath. It returns
// the marshalled policy as well as the original object for any farther processing.
func (c *Client) GetCurrentPolicy() ([]byte, *policy.PUPolicyPublic, error) {

	sctx, err := c.registry.RetrieveServiceByID(c.puContext)
	if err != nil {
		return nil, nil, err
	}

	plc := sctx.PU.Policy.ToPublicPolicy()
	plc.ServicesCertificate = ""
	plc.ServicesPrivateKey = ""
	data, err := json.MarshalIndent(plc, "  ", "  ")
	if err != nil {
		data = []byte("Internal Server Error")
	}

	return data, plc, nil
}

// IssueToken issues an OAUTH token for this PU for the desired audience
// and validity. The request will use the token issuer to contact the OIDC
// provider and issue the token.
func (c *Client) IssueToken(ctx context.Context, stype common.ServiceTokenType, audience string, validity time.Duration) (string, error) {
	return c.tokenIssuer.Issue(ctx, c.puContext, stype, audience, validity)
}

// Authorize request will use the enforcerd databases and context to authorize
// an http request given the provided credentials.
func (c *Client) Authorize(request *apiauth.Request) error {

	// TODO
	return nil
}
