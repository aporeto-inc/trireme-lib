package tokenaccessor

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"time"

	enforcerconstants "go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/constants"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/utils/ephemeralkeys"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/claimsheader"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/pkiverifier"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/tokens"
)

// tokenAccessor is a wrapper around tokenEngine to provide locks for accessing
type tokenAccessor struct {
	tokens   tokens.TokenEngine
	serverID string
	validity time.Duration
}

// New creates a new instance of TokenAccessor interface
func New(serverID string, validity time.Duration, secret secrets.Secrets) (TokenAccessor, error) {

	var tokenEngine tokens.TokenEngine
	var err error

	tokenEngine, err = tokens.NewBinaryJWT(validity, serverID)
	if err != nil {
		return nil, err
	}

	return &tokenAccessor{
		tokens:   tokenEngine,
		serverID: serverID,
		validity: validity,
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
func (t *tokenAccessor) CreateAckPacketToken(proto314 bool, secretKey []byte, claims *tokens.ConnectionClaims, encodedBuf []byte) ([]byte, error) {

	token, err := t.tokens.CreateAckToken(proto314, secretKey, claims, encodedBuf, claimsheader.NewClaimsHeader())
	if err != nil {
		return nil, fmt.Errorf("unable to create ack token: %v", err)
	}

	return token, nil
}

func (t *tokenAccessor) Randomize(token []byte, nonce []byte) error {
	return t.tokens.Randomize(token, nonce)
}

func (t *tokenAccessor) Sign(buf []byte, key *ecdsa.PrivateKey) ([]byte, error) {
	return t.tokens.Sign(buf, key)
}

// createSynPacketToken creates the authentication token
func (t *tokenAccessor) CreateSynPacketToken(claims *tokens.ConnectionClaims, encodedBuf []byte, nonce []byte, claimsHeader *claimsheader.ClaimsHeader, secrets secrets.Secrets) ([]byte, error) {
	token, err := t.tokens.CreateSynToken(claims, encodedBuf, nonce, claimsHeader, secrets)
	if err != nil {
		return nil, fmt.Errorf("unable to create syn token: %v", err)
	}

	return token, nil
}

// createSynAckPacketToken  creates the authentication token for SynAck packets
// We need to sign the received token. No caching possible here
func (t *tokenAccessor) CreateSynAckPacketToken(proto314 bool, claims *tokens.ConnectionClaims, encodedBuf []byte, nonce []byte, claimsHeader *claimsheader.ClaimsHeader, secrets secrets.Secrets, secretKey []byte) ([]byte, error) {
	token, err := t.tokens.CreateSynAckToken(proto314, claims, encodedBuf, nonce, claimsHeader, secrets, secretKey)
	if err != nil {
		return nil, fmt.Errorf("unable to create synack token: %v", err)
	}

	return token, nil
}

// parsePacketToken parses the packet token and populates the right state.
// Returns an error if the token cannot be parsed or the signature fails
func (t *tokenAccessor) ParsePacketToken(privateKey *ephemeralkeys.PrivateKey, data []byte, secrets secrets.Secrets, claims *tokens.ConnectionClaims, isSynAck bool) ([]byte, *claimsheader.ClaimsHeader, *pkiverifier.PKIControllerInfo, []byte, string, bool, error) {

	// Validate the certificate and parse the token
	secretKey, header, nonce, controller, proto314, err := t.tokens.DecodeSyn(isSynAck, data, privateKey, secrets, claims)
	if err != nil {
		return nil, nil, nil, nil, "", false, err
	}

	// We always a need a valid remote context ID
	if claims.T == nil {
		return nil, nil, nil, nil, "", false, errors.New("no claims found")
	}

	remoteContextID, ok := claims.T.Get(enforcerconstants.TransmitterLabel)
	if !ok {
		return nil, nil, nil, nil, "", false, errors.New("no transmitter label")
	}

	return secretKey, header, controller, nonce, remoteContextID, proto314, nil
}

// parseAckToken parses the tokens in Ack packets. They don't carry all the state context
// and it needs to be recovered
func (t *tokenAccessor) ParseAckToken(proto314 bool, secretKey []byte, nonce []byte, data []byte, connClaims *tokens.ConnectionClaims) error {

	// Validate the certificate and parse the token
	if err := t.tokens.DecodeAck(proto314, secretKey, data, connClaims); err != nil {
		return err
	}

	if !bytes.Equal(connClaims.RMT, nonce) {
		return errors.New("failed to match context in ack packet")
	}

	return nil
}
