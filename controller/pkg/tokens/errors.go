package tokens

import (
	"errors"

	"go.uber.org/zap"
)

var (
	ErrTokenTooSmall           = errors.New("randomize: token is small")
	ErrTokenEncodeFailed       = errors.New("unable to encode token")
	ErrTokenHashFailed         = errors.New("unable to hash token")
	ErrTokenSignFailed         = errors.New("unable to sign token")
	ErrSharedSecretMissing     = errors.New("secret not found")
	ErrInvalidSecret           = errors.New("invalid secret")
	ErrInvalidTokenLength      = errors.New("not enough data")
	ErrMissingSignature        = errors.New("signature is missing")
	ErrInvalidSignature        = errors.New("invalid signature")
	ErrCompressedTagMismatch   = errors.New("Compressed tag mismatch")
	ErrDatapathVersionMismatch = errors.New("Datapath version mismatch")
	ErrTokenDecodeFailed       = errors.New("unable to decode token")
	ErrTokenExpired            = errors.New("token expired")
	ErrSignatureMismatch       = errors.New("signature mismatch")
	ErrSharedKeyHashFailed     = errors.New("unable to hash shared key")
	ErrPublicKeyFailed         = errors.New("unable to verify public key")
)

// logError is a convinience function which logs the err:msg and returns the error.
func logError(err error, msg string) error {

	zap.L().Debug(err.Error(), zap.String("error", msg))

	return err
}
