package tokenprocessor

import (
	"bytes"
	"fmt"
	"time"

	"github.com/aporeto-inc/trireme-lib/enforcer/connection"
	"github.com/aporeto-inc/trireme-lib/enforcer/constants"
	"github.com/aporeto-inc/trireme-lib/enforcer/pucontext"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/tokens"
)

type tokenProcessor struct {
	tokenEngine tokens.TokenEngine
}

// New provides a token processor capable of parsing and creating tokens for various types of packets
func New(t tokens.TokenEngine) TokenProcessor {
	return &tokenProcessor{
		tokenEngine: t,
	}
}

// createacketToken creates the authentication token
func (d *tokenProcessor) CreateAckPacketToken(context *pucontext.PUContext, auth *connection.AuthInfo) ([]byte, error) {

	claims := &tokens.ConnectionClaims{
		LCL: auth.LocalContext,
		RMT: auth.RemoteContext,
	}

	token, _, err := d.tokenEngine.CreateAndSign(true, claims)
	if err != nil {
		return []byte{}, err
	}

	return token, nil
}

// createSynPacketToken creates the authentication token
func (d *tokenProcessor) CreateSynPacketToken(context *pucontext.PUContext, auth *connection.AuthInfo) (token []byte, err error) {

	if context.SynExpiration.After(time.Now()) && len(context.SynToken) > 0 {
		// Randomize the nonce and send it
		auth.LocalContext, err = d.tokenEngine.Randomize(context.SynToken)
		if err == nil {
			return context.SynToken, nil
		}
		// If there is an error, let's try to create a new one
	}

	claims := &tokens.ConnectionClaims{
		T: context.Identity,
	}

	if context.SynToken, auth.LocalContext, err = d.tokenEngine.CreateAndSign(false, claims); err != nil {
		return []byte{}, nil
	}

	context.SynExpiration = time.Now().Add(time.Millisecond * 500)

	return context.SynToken, nil
}

// createSynAckPacketToken  creates the authentication token for SynAck packets
// We need to sign the received token. No caching possible here
func (d *tokenProcessor) CreateSynAckPacketToken(context *pucontext.PUContext, auth *connection.AuthInfo) (token []byte, err error) {

	claims := &tokens.ConnectionClaims{
		T:   context.Identity,
		RMT: auth.RemoteContext,
	}

	if context.SynToken, auth.LocalContext, err = d.tokenEngine.CreateAndSign(false, claims); err != nil {
		return []byte{}, nil
	}

	return context.SynToken, nil

}

// parsePacketToken parses the packet token and populates the right state.
// Returns an error if the token cannot be parsed or the signature fails
func (d *tokenProcessor) ParsePacketToken(auth *connection.AuthInfo, data []byte) (*tokens.ConnectionClaims, error) {

	// Validate the certificate and parse the token
	claims, nonce, cert, err := d.tokenEngine.Decode(false, data, auth.RemotePublicKey)
	if err != nil {
		return nil, err
	}

	// We always a need a valid remote context ID
	remoteContextID, ok := claims.T.Get(enforcerconstants.TransmitterLabel)
	if !ok {
		return nil, fmt.Errorf("No Transmitter Label ")
	}

	auth.RemotePublicKey = cert
	auth.RemoteContext = nonce
	auth.RemoteContextID = remoteContextID

	return claims, nil
}

// parseAckToken parses the tokens in Ack packets. They don't carry all the state context
// and it needs to be recovered
func (d *tokenProcessor) ParseAckToken(auth *connection.AuthInfo, data []byte) (*tokens.ConnectionClaims, error) {

	// Validate the certificate and parse the token
	claims, _, _, err := d.tokenEngine.Decode(true, data, auth.RemotePublicKey)
	if err != nil {
		return nil, err
	}

	// Compare the incoming random context with the stored context
	matchLocal := bytes.Compare(claims.RMT, auth.LocalContext)
	matchRemote := bytes.Compare(claims.LCL, auth.RemoteContext)
	if matchLocal != 0 || matchRemote != 0 {
		return nil, fmt.Errorf("Failed to match context in ACK packet")
	}

	return claims, nil
}
