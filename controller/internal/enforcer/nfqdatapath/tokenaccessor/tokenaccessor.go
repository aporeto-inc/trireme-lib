package tokenaccessor

import (
	"bytes"
	"errors"
	"sync"
	"time"

	"go.aporeto.io/trireme-lib/controller/internal/enforcer/constants"
	"go.aporeto.io/trireme-lib/controller/pkg/connection"
	"go.aporeto.io/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/controller/pkg/tokens"
)

// tokenAccessor is a wrapper around tokenEngine to provide locks for accessing
type tokenAccessor struct {
	sync.RWMutex
	tokens   tokens.TokenEngine
	serverID string
	validity time.Duration
}

// New creates a new instance of TokenAccessor interface
func New(serverID string, validity time.Duration, secret secrets.Secrets) (TokenAccessor, error) {

	tokenEngine, err := tokens.NewJWT(validity, serverID, secret)
	if err != nil {
		return nil, err
	}

	return &tokenAccessor{
		tokens:   tokenEngine,
		serverID: serverID,
		validity: validity,
	}, nil
}

func (t *tokenAccessor) getToken() tokens.TokenEngine {

	t.Lock()
	defer t.Unlock()

	return t.tokens
}

// SetToken updates sthe stored token in the struct
func (t *tokenAccessor) SetToken(serverID string, validity time.Duration, secret secrets.Secrets) error {

	t.Lock()
	defer t.Unlock()
	tokenEngine, err := tokens.NewJWT(validity, serverID, secret)
	if err != nil {
		return err
	}
	t.tokens = tokenEngine
	return nil
}

// GetTokenValidity returns the duration the token is valid for
func (t *tokenAccessor) GetTokenValidity() time.Duration {
	return t.validity
}

// GetTokenServerID returns the server ID which is used the generate the token.
func (t *tokenAccessor) GetTokenServerID() string {
	return t.serverID
}

// CreateAckPacketToken creates the authentication token
func (t *tokenAccessor) CreateAckPacketToken(context *pucontext.PUContext, auth *connection.AuthInfo) ([]byte, error) {

	claims := &tokens.ConnectionClaims{
		LCL: auth.LocalContext,
		RMT: auth.RemoteContext,
	}

	token, err := t.getToken().CreateAndSign(true, claims, auth.LocalContext)
	if err != nil {
		return []byte{}, err
	}

	return token, nil
}

// createSynPacketToken creates the authentication token
func (t *tokenAccessor) CreateSynPacketToken(context *pucontext.PUContext, auth *connection.AuthInfo) (token []byte, err error) {

	token, serviceContext, err := context.GetCachedTokenAndServiceContext()
	if err == nil && bytes.Equal(auth.LocalServiceContext, serviceContext) {
		// Randomize the nonce and send it
		err = t.getToken().Randomize(token, auth.LocalContext)
		if err == nil {
			return token, nil
		}
		// If there is an error, let's try to create a new one
	}

	claims := &tokens.ConnectionClaims{
		T:  context.Identity(),
		EK: auth.LocalServiceContext,
	}

	if token, err = t.getToken().CreateAndSign(false, claims, auth.LocalContext); err != nil {
		return []byte{}, nil
	}

	context.UpdateCachedTokenAndServiceContext(token, auth.LocalServiceContext)

	return token, nil
}

// createSynAckPacketToken  creates the authentication token for SynAck packets
// We need to sign the received token. No caching possible here
func (t *tokenAccessor) CreateSynAckPacketToken(context *pucontext.PUContext, auth *connection.AuthInfo) (token []byte, err error) {

	claims := &tokens.ConnectionClaims{
		T:   context.Identity(),
		RMT: auth.RemoteContext,
		EK:  auth.LocalServiceContext,
	}

	if token, err = t.getToken().CreateAndSign(false, claims, auth.LocalContext); err != nil {
		return []byte{}, nil
	}

	return token, nil
}

// parsePacketToken parses the packet token and populates the right state.
// Returns an error if the token cannot be parsed or the signature fails
func (t *tokenAccessor) ParsePacketToken(auth *connection.AuthInfo, data []byte) (*tokens.ConnectionClaims, error) {

	// Validate the certificate and parse the token
	claims, nonce, cert, err := t.getToken().Decode(false, data, auth.RemotePublicKey)
	if err != nil {
		return nil, err
	}

	// We always a need a valid remote context ID
	if claims.T == nil {
		return nil, errors.New("no claims found")
	}
	remoteContextID, ok := claims.T.Get(enforcerconstants.TransmitterLabel)
	if !ok {
		return nil, errors.New("no transmitter label")
	}

	auth.RemotePublicKey = cert
	auth.RemoteContext = nonce
	auth.RemoteContextID = remoteContextID
	auth.RemoteServiceContext = claims.EK

	return claims, nil
}

// parseAckToken parses the tokens in Ack packets. They don't carry all the state context
// and it needs to be recovered
func (t *tokenAccessor) ParseAckToken(auth *connection.AuthInfo, data []byte) (*tokens.ConnectionClaims, error) {

	gt := t.getToken()
	if gt == nil {
		return nil, errors.New("token is nil")
	}
	if auth == nil {
		return nil, errors.New("auth is nil")
	}
	// Validate the certificate and parse the token
	claims, _, _, err := t.getToken().Decode(true, data, auth.RemotePublicKey)
	if err != nil {
		return nil, err
	}

	// Compare the incoming random context with the stored context
	matchLocal := bytes.Compare(claims.RMT, auth.LocalContext)
	matchRemote := bytes.Compare(claims.LCL, auth.RemoteContext)
	if matchLocal != 0 || matchRemote != 0 {
		return nil, errors.New("failed to match context in ack packet")
	}

	return claims, nil
}
