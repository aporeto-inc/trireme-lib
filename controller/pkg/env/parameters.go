package env

import (
	"os"

	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/pkg/claimsheader"
)

// RemoteParameters holds all configuration objects that must be passed
// during the initialization of the monitor.
type RemoteParameters struct {
	LogToConsole   bool
	LogWithID      bool
	LogLevel       string
	LogFormat      string
	CompressedTags claimsheader.CompressionType
}

// GetParameters retrieves log parameters for Remote Enforcer.
func GetParameters() (logToConsole bool, logID string, logLevel string, logFormat string, compressedTagsVersion claimsheader.CompressionType) {

	logLevel = os.Getenv(constants.EnvLogLevel)
	if logLevel == "" {
		logLevel = "info"
	}

	logFormat = os.Getenv(constants.EnvLogFormat)
	if logLevel == "" {
		logFormat = "json"
	}

	if console := os.Getenv(constants.EnvLogToConsole); console == constants.EnvLogToConsoleEnable {
		logToConsole = true
	}

	logID = os.Getenv(constants.EnvLogID)

	compressedTagsVersion = claimsheader.CompressionTypeNone
	if console := os.Getenv(constants.EnvCompressedTags); console != string(claimsheader.CompressionTypeNone) {
		if console == string(claimsheader.CompressionTypeV1) {
			compressedTagsVersion = claimsheader.CompressionTypeV1
		} else if console == string(claimsheader.CompressionTypeV2) {
			compressedTagsVersion = claimsheader.CompressionTypeV2
		}
	}

	return
}
