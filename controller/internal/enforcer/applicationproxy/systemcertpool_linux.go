// +build linux

package applicationproxy

import (
	"crypto/x509"

	"go.uber.org/zap"
)

func GetSystemCertPool() (*x509.CertPool, error) {
	zap.L().Error("LInux Code")
	return x509.SystemCertPool()

}
