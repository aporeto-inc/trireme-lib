package ephemeralkeys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"sync"
	"time"

	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/enforcerd/trireme-lib/utils/crypto"
)

//PrivateKey struct holds the ecdsa private key and its encoded string
type PrivateKey struct {
	*ecdsa.PrivateKey
	PrivateKeyString string
}

type ephemeralKey struct {
	privateKey  *PrivateKey
	publicKeyV1 []byte
	publicKeyV2 []byte
	sync.RWMutex
}

const keyInterval = 5 * time.Minute

// New creates a new key accessor
func New() (KeyAccessor, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	publicKeyBytesV1 := crypto.EncodePublicKeyV1(&privateKey.PublicKey)
	publicKeyBytesV2 := crypto.EncodePublicKeyV2(&privateKey.PublicKey)
	pvtKeyBytes := crypto.EncodePrivateKey(privateKey)

	keys := &ephemeralKey{
		privateKey:  &PrivateKey{privateKey, string(pvtKeyBytes)},
		publicKeyV1: publicKeyBytesV1,
		publicKeyV2: publicKeyBytesV2,
	}

	return keys, nil
}

// NewWithRenewal creates a new key accessor and renews it every keyInterval
func NewWithRenewal() (KeyAccessor, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	publicKeyBytesV1 := crypto.EncodePublicKeyV1(&privateKey.PublicKey)
	publicKeyBytesV2 := crypto.EncodePublicKeyV2(&privateKey.PublicKey)
	pvtKeyBytes := crypto.EncodePrivateKey(privateKey)

	keys := &ephemeralKey{
		privateKey:  &PrivateKey{privateKey, string(pvtKeyBytes)},
		publicKeyV1: publicKeyBytesV1,
		publicKeyV2: publicKeyBytesV2,
	}

	go func() {
		for {
			<-time.After(keyInterval)
			for i := 0; i < 5; i++ {
				privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					continue
				}
				publicKeyBytesV1 := crypto.EncodePublicKeyV1(&privateKey.PublicKey)
				publicKeyBytesV2 := crypto.EncodePublicKeyV2(&privateKey.PublicKey)
				pvtKeyBytes := crypto.EncodePrivateKey(privateKey)

				keys.Lock()
				keys.privateKey = &PrivateKey{privateKey, string(pvtKeyBytes)}
				keys.publicKeyV1 = publicKeyBytesV1
				keys.publicKeyV2 = publicKeyBytesV2
				keys.Unlock()
				break
			}
		}
	}()

	return keys, nil
}

// PrivateKey return the private key of the keypair
func (k *ephemeralKey) PrivateKey() *PrivateKey {
	k.RLock()
	defer k.RUnlock()
	return k.privateKey
}

func (k *ephemeralKey) DecodingKeyV1() []byte {
	k.RLock()
	defer k.RUnlock()
	return k.publicKeyV1
}

func (k *ephemeralKey) DecodingKeyV2() []byte {
	k.RLock()
	defer k.RUnlock()
	return k.publicKeyV2
}

var secret secrets.Secrets
var lock sync.RWMutex

//GetDatapathSecret returns the secrets
func GetDatapathSecret() secrets.Secrets {
	lock.RLock()
	defer lock.RUnlock()
	return secret
}

//UpdateDatapathSecrets updates the secrets
func UpdateDatapathSecrets(s secrets.Secrets) {
	lock.Lock()
	secret = s
	lock.Unlock()
}
