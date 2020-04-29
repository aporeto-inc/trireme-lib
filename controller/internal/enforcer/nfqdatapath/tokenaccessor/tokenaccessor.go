package tokenaccessor

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	enforcerconstants "go.aporeto.io/trireme-lib/controller/internal/enforcer/constants"
	"go.aporeto.io/trireme-lib/controller/pkg/claimsheader"
	"go.aporeto.io/trireme-lib/controller/pkg/connection"
	"go.aporeto.io/trireme-lib/controller/pkg/pkiverifier"
	"go.aporeto.io/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/controller/pkg/tokens"
	"go.uber.org/zap"
)

// tokenAccessor is a wrapper around tokenEngine to provide locks for accessing
type tokenAccessor struct {
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
		tokenEngine, err = tokens.NewBinaryJWT(validity, serverID)
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

// GetTokenValidity returns the duration the token is valid for
func (t *tokenAccessor) GetTokenValidity() time.Duration {
	return t.validity
}

// GetTokenServerID returns the server ID which is used the generate the token.
func (t *tokenAccessor) GetTokenServerID() string {
	return t.serverID
}

// CreateAckPacketToken creates the authentication token
func (t *tokenAccessor) CreateAckPacketToken(context *pucontext.PUContext, auth *connection.AuthInfo, secrets secrets.Secrets) ([]byte, error) {

	claims := &tokens.ConnectionClaims{
		ID:       context.ManagementID(),
		RMT:      auth.RemoteContext,
		RemoteID: auth.RemoteContextID,
	}

	token, err := t.tokens.CreateAndSign(true, claims, auth.LocalContext, claimsheader.NewClaimsHeader(), secrets)
	if err != nil {
		return nil, fmt.Errorf("unable to create ack token: %v", err)
	}

	return token, nil
}

// createSynPacketToken creates the authentication token
func (t *tokenAccessor) CreateSynPacketToken(context *pucontext.PUContext, auth *connection.AuthInfo, claimsHeader *claimsheader.ClaimsHeader, secrets secrets.Secrets) ([]byte, error) {

	token, serviceContext, err := context.GetCachedTokenAndServiceContext()
	if err == nil && bytes.Equal(auth.LocalServiceContext, serviceContext) {
		// Randomize the nonce and send it
		// FIX:we do nothing on error !!!
		err = t.tokens.Randomize(token, auth.LocalContext)
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

	token, err = t.tokens.CreateAndSign(false, claims, auth.LocalContext, claimsHeader, secrets)
	if err != nil {
		return nil, fmt.Errorf("unable to create syn token: %v", err)
	}

	context.UpdateCachedTokenAndServiceContext(token, auth.LocalServiceContext)

	return token, nil
}

// createSynAckPacketToken  creates the authentication token for SynAck packets
// We need to sign the received token. No caching possible here
func (t *tokenAccessor) CreateSynAckPacketToken(context *pucontext.PUContext, auth *connection.AuthInfo, claimsHeader *claimsheader.ClaimsHeader, secrets secrets.Secrets) ([]byte, error) {

	claims := &tokens.ConnectionClaims{
		T:        context.Identity(),
		CT:       context.CompressedTags(),
		LCL:      auth.LocalContext,
		RMT:      auth.RemoteContext,
		EK:       auth.LocalServiceContext,
		ID:       context.ManagementID(),
		RemoteID: auth.RemoteContextID,
	}

	token, err := t.tokens.CreateAndSign(false, claims, auth.LocalContext, claimsHeader, secrets)
	if err != nil {
		return nil, fmt.Errorf("unable to create synack token: %v", err)
	}

	return token, nil
}

// parsePacketToken parses the packet token and populates the right state.
// Returns an error if the token cannot be parsed or the signature fails
func (t *tokenAccessor) ParsePacketToken(auth *connection.AuthInfo, data []byte, secrets secrets.Secrets) (*tokens.ConnectionClaims, *pkiverifier.PKIControllerInfo, error) {

	// Validate the certificate and parse the token
	claims, nonce, cert, controller, err := t.tokens.Decode(false, data, auth.RemotePublicKey, secrets)
	if err != nil {
		return nil, nil, err
	}

	// We always a need a valid remote context ID
	if claims.T == nil {
		return nil, nil, errors.New("no claims found")
	}
	remoteContextID, ok := claims.T.Get(enforcerconstants.TransmitterLabel)
	if !ok {
		return nil, nil, errors.New("no transmitter label")
	}

	auth.RemotePublicKey = cert
	auth.RemoteContext = nonce
	auth.RemoteContextID = remoteContextID
	auth.RemoteServiceContext = claims.EK

	return claims, controller, nil
}

// parseAckToken parses the tokens in Ack packets. They don't carry all the state context
// and it needs to be recovered
func (t *tokenAccessor) ParseAckToken(auth *connection.AuthInfo, data []byte, secrets secrets.Secrets) (*tokens.ConnectionClaims, *pkiverifier.PKIControllerInfo, error) {

	if secrets == nil {
		return nil, nil, errors.New("secrets is nil")
	}
	if auth == nil {
		return nil, nil, errors.New("auth is nil")
	}
	// Validate the certificate and parse the token
	claims, _, _, controller, err := t.tokens.Decode(true, data, auth.RemotePublicKey, secrets)
	if err != nil {
		return nil, nil, err
	}

	if !bytes.Equal(claims.RMT, auth.LocalContext) {
		return nil, nil, errors.New("failed to match context in ack packet")
	}

	return claims, controller, nil
}
