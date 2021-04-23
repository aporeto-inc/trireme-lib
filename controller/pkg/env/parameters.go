package env

import (
	"os"
	"strconv"

	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/claimsheader"
)

// RemoteParameters holds all configuration objects that must be passed
// during the initialization of the monitor.
type RemoteParameters struct {
	LogWithID      bool
	LogLevel       string
	LogFormat      string
	CompressedTags claimsheader.CompressionType
}

// GetParameters retrieves log parameters for Remote Enforcer.
func GetParameters() (string, string, string, claimsheader.CompressionType, int) {

	var logID, logLevel, logFormat string
	var compressedTagsVersion claimsheader.CompressionType
	var numQueues int

	logLevel = os.Getenv(constants.EnvLogLevel)
	if logLevel == "" {
		logLevel = "info"
	}
	logFormat = os.Getenv(constants.EnvLogFormat)
	if logLevel == "" {
		logFormat = "json"
	}

	logID = os.Getenv(constants.EnvLogID)
	compressedTagsVersion = claimsheader.CompressionTypeV1

	if num, err := strconv.Atoi(os.Getenv(constants.EnvEnforcerdNFQueues)); err == nil {
		numQueues = num
	} else {
		numQueues = 4
	}

	return logID, logLevel, logFormat, compressedTagsVersion, numQueues
}
