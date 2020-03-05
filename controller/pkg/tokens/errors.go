package tokens

import (
	"errors"
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
