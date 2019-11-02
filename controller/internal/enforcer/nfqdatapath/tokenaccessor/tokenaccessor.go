package tokenaccessor

import (
	"bytes"
	"errors"
	"sync"
	"time"

	enforcerconstants "go.aporeto.io/trireme-lib/v11/controller/internal/enforcer/constants"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/claimsheader"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/connection"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/tokens"
	"go.uber.org/zap"
)

// tokenAccessor is a wrapper around tokenEngine to provide locks for accessing
type tokenAccessor struct {
	sync.RWMutex
	tokens   tokens.TokenEngine
	serverID string
	validity time.Duration
	binary   bool
}

// New creates a new instance of TokenAccessor interface
func New(serverID string, validity time.Duration, secret secrets.Secrets, binary bool) (TokenAccessor, error) {

	var tokenEngine tokens.TokenEngine
	var err error

	if binary {
		zap.L().Info("Enabling Trireme Datapath v2.0")
		tokenEngine, err = tokens.NewBinaryJWT(validity, serverID, secret)
	} else {
		zap.L().Info("Enabling Trireme Datapath v1.0")
		tokenEngine, err = tokens.NewJWT(validity, serverID, secret)
	}
	if err != nil {
		return nil, err
	}

	return &tokenAccessor{
		tokens:   tokenEngine,
		serverID: serverID,
		validity: validity,
		binary:   binary,
	}, nil
}

func (t *tokenAccessor) getToken() tokens.TokenEngine {

	t.Lock()
	defer t.Unlock()

	return t.tokens
}

// SetToken updates the stored token in the struct
func (t *tokenAccessor) SetToken(serverID string, validity time.Duration, secret secrets.Secrets) error {

	t.Lock()
	defer t.Unlock()

	var tokenEngine tokens.TokenEngine
	var err error

	if t.binary {
		tokenEngine, err = tokens.NewBinaryJWT(validity, serverID, secret)
	} else {
		tokenEngine, err = tokens.NewJWT(validity, serverID, secret)
	}

	if err != nil {
		panic("unable to update token engine")
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
		ID:       context.ManagementID(),
		RMT:      auth.RemoteContext,
		RemoteID: auth.RemoteContextID,
	}

	token, err := t.getToken().CreateAndSign(true, claims, auth.LocalContext, claimsheader.NewClaimsHeader())
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
		// FIX:we do nothing on error !!!
		err = t.getToken().Randomize(token, auth.LocalContext)
		if err == nil {
			return token, nil
		}
		// If there is an error, let's try to create a new one
	}

	claims := &tokens.ConnectionClaims{
		LCL: auth.LocalContext,
		EK:  auth.LocalServiceContext,
		T:   context.Identity(),
		CT:  context.CompressedTags(),
		ID:  context.ManagementID(),
	}

	if token, err = t.getToken().CreateAndSign(false, claims, auth.LocalContext, claimsheader.NewClaimsHeader()); err != nil {
		return []byte{}, nil
	}

	context.UpdateCachedTokenAndServiceContext(token, auth.LocalServiceContext)

	return token, nil
}

// createSynAckPacketToken  creates the authentication token for SynAck packets
// We need to sign the received token. No caching possible here
func (t *tokenAccessor) CreateSynAckPacketToken(context *pucontext.PUContext, auth *connection.AuthInfo, claimsHeader *claimsheader.ClaimsHeader) (token []byte, err error) {

	claims := &tokens.ConnectionClaims{
		T:        context.Identity(),
		CT:       context.CompressedTags(),
		LCL:      auth.LocalContext,
		RMT:      auth.RemoteContext,
		EK:       auth.LocalServiceContext,
		ID:       context.ManagementID(),
		RemoteID: auth.RemoteContextID,
	}

	if token, err = t.getToken().CreateAndSign(false, claims, auth.LocalContext, claimsHeader); err != nil {
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

	if !bytes.Equal(claims.RMT, auth.LocalContext) {
		return nil, errors.New("failed to match context in ack packet")
	}

	return claims, nil
}
