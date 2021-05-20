package tokens

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"fmt"

	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/pkiverifier"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/secrets"
	localcrypto "go.aporeto.io/enforcerd/trireme-lib/utils/crypto"
)

func (c *BinaryJWTConfig) getSharedKey314(pub interface{}, priv interface{}) ([]byte, error) {

	publicKey := pub.(*ecdsa.PublicKey)
	privateKey := priv.(*ecdsa.PrivateKey)

	hashKey := string(localcrypto.EncodePublicKeyV2(publicKey)) + string(localcrypto.EncodePrivateKey(privateKey))

	secretKey := c.sharedKeys.Get(hashKey)
	if secretKey != nil {
		return secretKey, nil
	}

	secretKey, err := symmetricKey(privateKey, publicKey)
	if err != nil {
		return nil, logError(ErrSharedKeyHashFailed, err.Error())
	}

	// Add it in the cache
	c.sharedKeys.Put(hashKey, secretKey)

	return secretKey, nil
}

func hash314(buf []byte, key []byte) ([]byte, error) {

	hasher := crypto.SHA256.New()
	if _, err := hasher.Write(buf); err != nil {
		return nil, fmt.Errorf("unable to hash data structure: %s", err)
	}

	return hasher.Sum(key), nil
}

func (c *BinaryJWTConfig) verifyWithSharedKey314(buf []byte, key []byte, sig []byte) error {

	ps, err := hash314(buf, key)
	if err != nil {
		return logError(ErrTokenHashFailed, err.Error())
	}

	if !bytes.Equal(ps, sig) {
		return logError(ErrSignatureMismatch, fmt.Sprintf("unable to verify token with shared secret: they don't match %d %d ", len(ps), len(sig)))
	}

	return nil
}

func (c *BinaryJWTConfig) process314Protocol(isSynAck bool, token []byte, secrets secrets.Secrets, connClaims *ConnectionClaims, binaryClaims *BinaryJWTClaims, sig []byte) ([]byte, *pkiverifier.PKIControllerInfo, error) {

	var secretKey []byte
	publicKey, publicKeyClaims, _, controller, err := secrets.KeyAndClaims(binaryClaims.SignerKey)
	if err != nil || publicKey == nil {
		return nil, nil, ErrPublicKeyFailed
	}

	// Since we know that the signature is valid, we check if the token is already in
	// the cache and accept it. We do that after the verification, in case the
	// public key has expired and we still have it in the cache. This is true for syn only
	if !isSynAck {
		if cachedClaims, cerr := c.tokenCache.Get(string(token)); cerr == nil {
			*connClaims = *cachedClaims.(*ConnectionClaims)

			secretKey, err = c.getSharedKey314(publicKey, secrets.EncodingKey())
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

	if isSynAck {
		binaryClaims.RMT = nil
		secretKey, err = c.getSharedKey314(publicKey, secrets.EncodingKey())
		if err != nil {
			return nil, nil, err
		}

		if err := c.verifyWithSharedKey314(token, secretKey, sig); err != nil {
			return nil, nil, err
		}

	} else {
		// If the token is not in the cache, we validate the token with the
		// provided and validated public key. We will then add it in the
		// cache for future reference.

		if err := c.verify(token, sig, publicKey.(*ecdsa.PublicKey)); err != nil {
			return nil, nil, err
		}

		secretKey, err = c.getSharedKey314(publicKey, secrets.EncodingKey())
		if err != nil {
			return nil, nil, err
		}
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
