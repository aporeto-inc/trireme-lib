package tokenissuer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"time"

	"go.aporeto.io/trireme-lib/v11/common"
	"go.aporeto.io/trireme-lib/v11/controller/constants"
	"go.aporeto.io/trireme-lib/v11/controller/internal/enforcer/utils/rpcwrapper"
	"go.uber.org/zap"
)

// TokenClient interface provides a start function. the client is used to
// request tokens.
type TokenClient interface {
	Run(ctx context.Context) error
	Issue(ctx context.Context, contextID string, stype common.ServiceTokenType, audience string, validity time.Duration) (string, error)
}

const (
	tokenIssuerContextID = "UNUSED"
	retrieveTokenCommand = "ProxyRPCServer.RetrieveToken"
)

// Client represents the remote API client.
type Client struct {
	rpchdl     rpcwrapper.RPCClient
	secret     string
	socketPath string
	stop       chan bool
}

// NewClient returns a remote API client that can be used for
// issuing API calls to the master enforcer.
func NewClient() (*Client, error) {
	c := &Client{
		rpchdl:     rpcwrapper.NewRPCWrapper(),
		secret:     os.Getenv(constants.EnvStatsSecret),
		socketPath: os.Getenv(constants.EnvStatsChannel),
		stop:       make(chan bool),
	}
	if c.socketPath == "" {
		return nil, errors.New("no path to socket provided")
	}
	if c.secret == "" {
		return nil, errors.New("no secret provided for  channel")
	}

	return c, nil
}

// RetrieveToken will issue a token request to the main over the RPC channnel.
func (c *Client) RetrieveToken(contextID string, stype common.ServiceTokenType, audience string, validity time.Duration) (string, error) {

	request := &rpcwrapper.Request{
		Payload: &rpcwrapper.TokenRequestPayload{
			ContextID:        contextID,
			Audience:         audience,
			Validity:         validity,
			ServiceTokenType: stype,
		},
	}

	response := &rpcwrapper.Response{}

	if err := c.rpchdl.RemoteCall(tokenIssuerContextID, retrieveTokenCommand, request, response); err != nil {
		return "", err
	}

	payload, ok := response.Payload.(rpcwrapper.TokenResponsePayload)
	if !ok {
		return "", fmt.Errorf("unrecognized response payload. Received payload is %s", reflect.TypeOf(response.Payload))
	}

	return payload.Token, nil
}

// Issue implements the ServiceTokenIssuer interface.
func (c *Client) Issue(ctx context.Context, contextID string, stype common.ServiceTokenType, audience string, validity time.Duration) (string, error) {
	return c.RetrieveToken(contextID, stype, audience, validity)
}

// Run will initialize the client.
func (c *Client) Run(ctx context.Context) error {
	if err := c.rpchdl.NewRPCClient(tokenIssuerContextID, c.socketPath, c.secret); err != nil {
		zap.L().Error("CounterClient RPC client cannot connect", zap.Error(err))
		return err
	}
	return nil
}
