package nfqdatapath

import (
	"go.aporeto.io/trireme-lib/controller/pkg/counters"
	"go.aporeto.io/trireme-lib/controller/pkg/tokens"
)

func appSynCounterFromError(err error) counters.CounterType {

	switch err {
	case tokens.ErrTokenEncodeFailed:
		return counters.ErrSynTokenEncodeFailed
	case tokens.ErrTokenHashFailed:
		return counters.ErrSynTokenHashFailed
	case tokens.ErrTokenSignFailed:
		return counters.ErrSynTokenSignFailed
	case tokens.ErrSharedSecretMissing:
		return counters.ErrSynSharedSecretMissing
	case tokens.ErrInvalidSecret:
		return counters.ErrSynInvalidSecret
	case tokens.ErrInvalidSignature:
		return counters.ErrSynInvalidSignature
	default:
		return counters.ErrSynTokenFailed
	}
}

func appSynAckCounterFromError(err error) counters.CounterType {

	switch err {
	case tokens.ErrTokenEncodeFailed:
		return counters.ErrSynAckTokenEncodeFailed
	case tokens.ErrTokenHashFailed:
		return counters.ErrSynAckTokenHashFailed
	case tokens.ErrTokenSignFailed:
		return counters.ErrSynAckTokenSignFailed
	case tokens.ErrSharedSecretMissing:
		return counters.ErrSynAckSharedSecretMissing
	case tokens.ErrInvalidSecret:
		return counters.ErrSynAckInvalidSecret
	case tokens.ErrInvalidSignature:
		return counters.ErrSynAckInvalidSignature
	default:
		return counters.ErrSynAckTokenFailed
	}
}

func appAckCounterFromError(err error) counters.CounterType {

	switch err {
	case tokens.ErrTokenEncodeFailed:
		return counters.ErrAckTokenEncodeFailed
	case tokens.ErrTokenHashFailed:
		return counters.ErrAckTokenHashFailed
	case tokens.ErrInvalidSecret:
		return counters.ErrAckInvalidSecret
	case tokens.ErrSharedSecretMissing:
		return counters.ErrAckSharedSecretMissing
	default:
		return counters.ErrAckTokenFailed
	}
}

func netSynCounterFromError(err error) counters.CounterType {

	switch err {
	case tokens.ErrInvalidTokenLength:
		return counters.ErrSynInvalidTokenLength
	case tokens.ErrMissingSignature:
		return counters.ErrSynMissingSignature
	case tokens.ErrCompressedTagMismatch:
		return counters.ErrSynCompressedTagMismatch
	case tokens.ErrDatapathVersionMismatch:
		return counters.ErrSynDatapathVersionMismatch
	case tokens.ErrTokenDecodeFailed:
		return counters.ErrSynTokenDecodeFailed
	case tokens.ErrTokenExpired:
		return counters.ErrSynTokenExpired
	case tokens.ErrPublicKeyFailed:
		return counters.ErrSynPublicKeyFailed
	case tokens.ErrSharedKeyHashFailed:
		return counters.ErrSynSharedKeyHashFailed
	default:
		return counters.ErrSynDroppedInvalidToken
	}
}

func netSynAckCounterFromError(err error) counters.CounterType {

	switch err {
	case tokens.ErrInvalidTokenLength:
		return counters.ErrSynAckInvalidTokenLength
	case tokens.ErrMissingSignature:
		return counters.ErrSynAckMissingSignature
	case tokens.ErrCompressedTagMismatch:
		return counters.ErrSynAckCompressedTagMismatch
	case tokens.ErrDatapathVersionMismatch:
		return counters.ErrSynAckDatapathVersionMismatch
	case tokens.ErrTokenDecodeFailed:
		return counters.ErrSynAckTokenDecodeFailed
	case tokens.ErrTokenExpired:
		return counters.ErrSynAckTokenExpired
	case tokens.ErrPublicKeyFailed:
		return counters.ErrSynAckPublicKeyFailed
	case tokens.ErrSharedKeyHashFailed:
		return counters.ErrSynAckSharedKeyHashFailed
	default:
		return counters.ErrSynAckInvalidToken
	}
}

func netAckCounterFromError(err error) counters.CounterType {
	switch err {
	case tokens.ErrInvalidTokenLength:
		return counters.ErrAckInvalidTokenLength
	case tokens.ErrMissingSignature:
		return counters.ErrAckMissingSignature
	case tokens.ErrCompressedTagMismatch:
		return counters.ErrAckCompressedTagMismatch
	case tokens.ErrDatapathVersionMismatch:
		return counters.ErrAckDatapathVersionMismatch
	case tokens.ErrTokenDecodeFailed:
		return counters.ErrAckTokenDecodeFailed
	case tokens.ErrTokenExpired:
		return counters.ErrAckTokenExpired
	case tokens.ErrSharedSecretMissing:
		return counters.ErrAckSharedSecretMissing
	case tokens.ErrTokenHashFailed:
		return counters.ErrAckTokenHashFailed
	case tokens.ErrSignatureMismatch:
		return counters.ErrAckSignatureMismatch
	default:
		return counters.ErrAckInvalidToken
	}
}

func appUDPSynCounterFromError(err error) counters.CounterType {

	switch err {
	case tokens.ErrTokenEncodeFailed:
		return counters.ErrUDPSynTokenEncodeFailed
	case tokens.ErrTokenHashFailed:
		return counters.ErrUDPSynTokenHashFailed
	case tokens.ErrTokenSignFailed:
		return counters.ErrUDPSynTokenSignFailed
	case tokens.ErrSharedSecretMissing:
		return counters.ErrUDPSynSharedSecretMissing
	case tokens.ErrInvalidSecret:
		return counters.ErrUDPSynInvalidSecret
	case tokens.ErrInvalidSignature:
		return counters.ErrUDPSynInvalidSignature
	default:
		return counters.ErrUDPSynTokenFailed
	}
}

func appUDPSynAckCounterFromError(err error) counters.CounterType {

	switch err {
	case tokens.ErrTokenEncodeFailed:
		return counters.ErrUDPSynAckTokenEncodeFailed
	case tokens.ErrTokenHashFailed:
		return counters.ErrUDPSynAckTokenHashFailed
	case tokens.ErrTokenSignFailed:
		return counters.ErrUDPSynAckTokenSignFailed
	case tokens.ErrSharedSecretMissing:
		return counters.ErrUDPSynAckSharedSecretMissing
	case tokens.ErrInvalidSecret:
		return counters.ErrUDPSynAckInvalidSecret
	case tokens.ErrInvalidSignature:
		return counters.ErrUDPSynAckInvalidSignature
	default:
		return counters.ErrUDPSynAckTokenFailed
	}
}

func appUDPAckCounterFromError(err error) counters.CounterType {

	switch err {
	case tokens.ErrTokenEncodeFailed:
		return counters.ErrUDPAckTokenEncodeFailed
	case tokens.ErrTokenHashFailed:
		return counters.ErrUDPAckTokenHashFailed
	case tokens.ErrInvalidSecret:
		return counters.ErrUDPAckInvalidSecret
	case tokens.ErrSharedSecretMissing:
		return counters.ErrUDPAckSharedSecretMissing
	default:
		return counters.ErrUDPAckTokenFailed
	}
}

func netUDPSynCounterFromError(err error) counters.CounterType {

	switch err {
	case tokens.ErrInvalidTokenLength:
		return counters.ErrUDPSynInvalidTokenLength
	case tokens.ErrMissingSignature:
		return counters.ErrUDPSynMissingSignature
	case tokens.ErrCompressedTagMismatch:
		return counters.ErrUDPSynCompressedTagMismatch
	case tokens.ErrDatapathVersionMismatch:
		return counters.ErrUDPSynDatapathVersionMismatch
	case tokens.ErrTokenDecodeFailed:
		return counters.ErrUDPSynTokenDecodeFailed
	case tokens.ErrTokenExpired:
		return counters.ErrUDPSynTokenExpired
	case tokens.ErrPublicKeyFailed:
		return counters.ErrUDPSynPublicKeyFailed
	case tokens.ErrSharedKeyHashFailed:
		return counters.ErrUDPSynSharedKeyHashFailed
	default:
		return counters.ErrUDPSynDroppedInvalidToken
	}
}

func netUDPSynAckCounterFromError(err error) counters.CounterType {

	switch err {
	case tokens.ErrInvalidTokenLength:
		return counters.ErrUDPSynAckInvalidTokenLength
	case tokens.ErrMissingSignature:
		return counters.ErrUDPSynAckMissingSignature
	case tokens.ErrCompressedTagMismatch:
		return counters.ErrUDPSynAckCompressedTagMismatch
	case tokens.ErrDatapathVersionMismatch:
		return counters.ErrUDPSynAckDatapathVersionMismatch
	case tokens.ErrTokenDecodeFailed:
		return counters.ErrUDPSynAckTokenDecodeFailed
	case tokens.ErrTokenExpired:
		return counters.ErrUDPSynAckTokenExpired
	case tokens.ErrPublicKeyFailed:
		return counters.ErrUDPSynAckPublicKeyFailed
	case tokens.ErrSharedKeyHashFailed:
		return counters.ErrUDPSynAckSharedKeyHashFailed
	default:
		return counters.ErrUDPSynAckInvalidToken
	}
}

func netUDPAckCounterFromError(err error) counters.CounterType {
	switch err {
	case tokens.ErrInvalidTokenLength:
		return counters.ErrUDPAckInvalidTokenLength
	case tokens.ErrMissingSignature:
		return counters.ErrUDPAckMissingSignature
	case tokens.ErrCompressedTagMismatch:
		return counters.ErrUDPAckCompressedTagMismatch
	case tokens.ErrDatapathVersionMismatch:
		return counters.ErrUDPAckDatapathVersionMismatch
	case tokens.ErrTokenDecodeFailed:
		return counters.ErrUDPAckTokenDecodeFailed
	case tokens.ErrTokenExpired:
		return counters.ErrUDPAckTokenExpired
	case tokens.ErrSharedSecretMissing:
		return counters.ErrUDPAckSharedSecretMissing
	case tokens.ErrTokenHashFailed:
		return counters.ErrUDPAckTokenHashFailed
	case tokens.ErrSignatureMismatch:
		return counters.ErrUDPAckSignatureMismatch
	default:
		return counters.ErrUDPAckInvalidToken
	}
}
