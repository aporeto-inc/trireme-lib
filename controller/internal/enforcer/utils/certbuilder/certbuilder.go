package certbuilder

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"go.uber.org/zap"
)

const (
	// TypeCertificate type certificate
	TypeCertificate = "CERTIFICATE"
)

// BuildCertChain builds the cert chain from the root to the leaf cert
func BuildCertChain(certPEM, caPEM []byte) ([]byte, error) {
	zap.L().Debug("SDS Server:  BEFORE in buildCertChain certPEM: ", zap.String("certPEM:", string(certPEM)), zap.String("caPEM: ", string(caPEM)))
	certChain := []*x509.Certificate{}
	//certPEMBlock := caPEM
	clientPEMBlock := certPEM
	derBlock, _ := pem.Decode(clientPEMBlock)
	if derBlock != nil {
		if derBlock.Type == TypeCertificate {
			cert, err := x509.ParseCertificate(derBlock.Bytes)
			if err != nil {
				return nil, err
			}
			certChain = append(certChain, cert)
		} else {
			return nil, fmt.Errorf("invalid pem block type: %s", derBlock.Type)
		}
	}
	var certDERBlock *pem.Block
	for {
		certDERBlock, caPEM = pem.Decode(caPEM)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == TypeCertificate {
			cert, err := x509.ParseCertificate(certDERBlock.Bytes)
			if err != nil {
				return nil, err
			}
			certChain = append(certChain, cert)
		} else {
			return nil, fmt.Errorf("invalid pem block type: %s", certDERBlock.Type)
		}
	}
	by, _ := x509CertChainToPem(certChain)
	zap.L().Debug("SDS Server: After building the cert chain: ", zap.String("certChain: ", string(by)))
	return x509CertChainToPem(certChain)
}

// x509CertToPem converts x509 to byte.
func x509CertToPem(cert *x509.Certificate) ([]byte, error) {
	var pemBytes bytes.Buffer
	if err := pem.Encode(&pemBytes, &pem.Block{Type: TypeCertificate, Bytes: cert.Raw}); err != nil {
		return nil, err
	}
	return pemBytes.Bytes(), nil
}

// x509CertChainToPem converts chain of x509 certs to byte.
func x509CertChainToPem(certChain []*x509.Certificate) ([]byte, error) {
	var pemBytes bytes.Buffer
	for _, cert := range certChain {
		if err := pem.Encode(&pemBytes, &pem.Block{Type: TypeCertificate, Bytes: cert.Raw}); err != nil {
			return nil, err
		}
	}
	return pemBytes.Bytes(), nil
}

// GetTopRootCa get the top root CA
func GetTopRootCa(certPEMBlock []byte) ([]byte, error) {
	zap.L().Debug("SDS Server: BEFORE root cert is :", zap.String("root_cert: ", string(certPEMBlock)))
	//rootCert := []*x509.Certificate{}
	var certChain tls.Certificate
	//certPEMBlock := []byte(rootcaBundle)
	var certDERBlock *pem.Block
	for {
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == TypeCertificate {
			certChain.Certificate = append(certChain.Certificate, certDERBlock.Bytes)
		}
	}
	zap.L().Debug("SDS Server: the root ca is:", zap.String("cert: ", string(certChain.Certificate[len(certChain.Certificate)-1])))
	x509Cert, err := x509.ParseCertificate(certChain.Certificate[len(certChain.Certificate)-1])
	if err != nil {
		panic(err)
	}
	by, _ := x509CertToPem(x509Cert)
	zap.L().Debug("SDS Server: After building the cert chain: ", zap.String("rootCert: ", string(by)))
	return by, nil
}

// GetExpTimeFromCert gets the exp time from the cert, assumning the cert is in pem encoded.
func GetExpTimeFromCert(cert []byte) (time.Time, error) {
	block, _ := pem.Decode(cert)
	if block == nil {
		zap.L().Error("getExpTimeFromCert: error while pem decode")
		return time.Time{}, fmt.Errorf("Cannot decode the pem certs")
	}
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		zap.L().Error("failed to parse the certs", zap.Error(err))
		return time.Time{}, err
	}
	return x509Cert.NotAfter, nil
}

// X509CertChainToPem converts certChain to pem format
func X509CertChainToPem(certChain []*x509.Certificate) ([]byte, error) {
	return x509CertChainToPem(certChain)
}

// X509CertToPem converts a single cert to pem format
func X509CertToPem(cert *x509.Certificate) ([]byte, error) {
	return x509CertToPem(cert)
}
