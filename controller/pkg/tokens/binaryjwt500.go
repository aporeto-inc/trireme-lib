package tokens

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"fmt"

	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/utils/ephemeralkeys"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/pkiverifier"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/secrets"
	"go.uber.org/zap"
)

func (c *BinaryJWTConfig) process500Protocol(isSynAck bool, token []byte, privateKey *ephemeralkeys.PrivateKey, secrets secrets.Secrets, connClaims *ConnectionClaims, binaryClaims *BinaryJWTClaims, sig []byte) ([]byte, *pkiverifier.PKIControllerInfo, error) {

	publicKey, publicKeyClaims, _, controller, err := secrets.KeyAndClaims(binaryClaims.SignerKey)
	if err != nil || publicKey == nil {
		return nil, nil, ErrPublicKeyFailed
	}

	var remotePublicKeyString, remotePublicKeySig string
	var isV1Proto bool

	// Since we know that the signature is valid, we check if the token is already in
	// the cache and accept it. We do that after the verification, in case the
	// public key has expired and we still have it in the cache. This is true for syn only
	if !isSynAck {
		if cachedClaims, cerr := c.tokenCache.Get(string(token)); cerr == nil {
			*connClaims = *cachedClaims.(*ConnectionClaims)
			if len(connClaims.DEKV2) == 0 {
				remotePublicKeyString = string(connClaims.DEKV1)
				isV1Proto = true
			} else {
				remotePublicKeyString = string(connClaims.DEKV2)
				isV1Proto = false
			}

			secretKey, err := c.getSecretKey(privateKey, remotePublicKeyString, isV1Proto)
			if err != nil {
				return nil, nil, err
			}
			return secretKey, controller, nil
		}
	}

	// Uncommpress the tags and add the public key claims to the tags that
	// we return.
	uncompressTags(binaryClaims, publicKeyClaims)
	CopyToConnectionClaims(binaryClaims, connClaims)

	if len(connClaims.DEKV2) == 0 {
		remotePublicKeyString = string(connClaims.DEKV1)
		remotePublicKeySig = string(connClaims.SDEKV1)
		isV1Proto = true
	} else {
		remotePublicKeyString = string(connClaims.DEKV2)
		remotePublicKeySig = string(connClaims.SDEKV2)
		isV1Proto = false
	}

	// We haven't seen this token again, so we will validate it with the
	// public key and cache it for future calls.

	// First we check if we know RMT attribute is set. This will indicate
	// that this is SynAck packet that carries the remote nonce, and we
	// can use the shared key approach. In the protocol we mandate
	// that RMT in the SynAck is populated since it carries the nonce
	// of the remote.
	if isSynAck {
		binaryClaims.RMT = nil

		// We don't need to verify the ephemeral key if we have done it already.
		if _, cerr := c.tokenCache.Get(remotePublicKeyString); cerr != nil {
			if err := c.verify([]byte(remotePublicKeyString), []byte(remotePublicKeySig), publicKey.(*ecdsa.PublicKey)); err != nil {
				zap.L().Error("Ephemeral key can not be verified", zap.Error(err))
				return nil, nil, err
			}

			c.tokenCache.AddOrUpdate(remotePublicKeyString, "")
		}
	} else {
		// If the token is not in the cache, we validate the token with the
		// provided and validated public key. We will then add it in the
		// cache for future reference.

		if err := c.verify(token, sig, publicKey.(*ecdsa.PublicKey)); err != nil {
			return nil, nil, err
		}
	}

	secretKey, err := c.getSecretKey(privateKey, remotePublicKeyString, isV1Proto)
	if err != nil {
		return nil, nil, err
	}

	// create a copy of the connClaims as this conn claims belongs to the original Connection.
	// It would have been fine to store the connclaims in the cache here, but the gc will not be able to
	// reclaim memory of the entire connection.
	if !isSynAck {
		connClaimsCopy := new(ConnectionClaims)
		*connClaimsCopy = *connClaims
		c.tokenCache.AddOrUpdate(string(token), connClaimsCopy)
	}

	return secretKey, controller, nil
}

func hash500(buf []byte, key []byte) ([]byte, error) {

	newBuf := make([]byte, 0, len(buf)+len(key))
	newBuf = append(newBuf, buf...)
	newBuf = append(newBuf, key...)

	hasher := crypto.SHA256.New()
	if _, err := hasher.Write(newBuf); err != nil {
		return nil, fmt.Errorf("unable to hash data structure: %s", err)
	}

	return hasher.Sum(nil), nil
}

func (c *BinaryJWTConfig) verifyWithSharedKey500(buf []byte, key []byte, sig []byte) error {

	ps, err := hash500(buf, key)
	if err != nil {
		return logError(ErrTokenHashFailed, err.Error())
	}

	if !bytes.Equal(ps, sig) {
		return logError(ErrSignatureMismatch, fmt.Sprintf("unable to verify token with shared secret: they don't match %d %d ", len(ps), len(sig)))
	}

	return nil
}
