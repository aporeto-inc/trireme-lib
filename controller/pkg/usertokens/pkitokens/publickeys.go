package pkitokens

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// parsePublicKeysFromPEM reads all public keys from PEMs that are either
// in a "PUBLIC KEY", "RSA PUBLIC KEY" or "CERTIFICATE" type PEM and
// returns them in an array. Only RSA and ECDSA keys are taken into account.
// NOTE: pay attention to the special return logic!
//
// The return logic is as follows:
// if no keys could be found or parsed: nil, err
// if no errors were found at all: keys, nil
// if some keys could be parsed, but others failed: keys, err
//
func parsePublicKeysFromPEM(bytesPEM []byte) ([]crypto.PublicKey, error) {
	keys := make([]crypto.PublicKey, 0, 1)
	rest := bytesPEM
	var errs []error
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if !isSupportedPublicKeyType(cert.PublicKey) {
				errs = append(errs, fmt.Errorf("unsupported key type %T", cert.PublicKey))
				continue
			}
			keys = append(keys, cert.PublicKey)
		case "PUBLIC KEY":
			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if !isSupportedPublicKeyType(pub) {
				errs = append(errs, fmt.Errorf("unsupported key type %T", pub))
				continue
			}
			keys = append(keys, pub)
		case "RSA PUBLIC KEY":
			pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if !isSupportedPublicKeyType(pub) {
				errs = append(errs, fmt.Errorf("unsupported key type %T", pub))
				continue
			}
			keys = append(keys, pub)
		default:
			// invalid type, read the next entry
			errs = append(errs, fmt.Errorf("unsupported PEM type %s", block.Type))
			continue
		}
	}

	// create detailed error
	var detailedErrors string
	for i, err := range errs {
		detailedErrors += err.Error()
		if i+1 < len(errs) {
			detailedErrors += "; "
		}
	}

	// if no keys at all were found, be specific about this
	if len(keys) == 0 {
		return nil, fmt.Errorf("no valid certificates or public keys found (errors: [%s])", detailedErrors)
	}

	// if some errors were encountered, but we have some keys, return both
	if len(keys) > 0 && len(errs) > 0 {
		return keys, fmt.Errorf("[%s]", detailedErrors)
	}

	// if all went well, return keys, but no error
	return keys, nil
}

// isSupportedPublicKeyType returns true if `key` is an RSA or ECDSA public key
func isSupportedPublicKeyType(key crypto.PublicKey) bool {
	return isRSAPublicKey(key) || isECDSAPublicKey(key)
}

func isRSAPublicKey(key crypto.PublicKey) bool {
	_, ok := key.(*rsa.PublicKey)
	return ok
}

func isECDSAPublicKey(key crypto.PublicKey) bool {
	_, ok := key.(*ecdsa.PublicKey)
	return ok
}
