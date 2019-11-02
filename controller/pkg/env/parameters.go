package env

import (
	"os"
	"strconv"

	"go.aporeto.io/trireme-lib/v11/controller/constants"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/claimsheader"
)

// RemoteParameters holds all configuration objects that must be passed
// during the initialization of the monitor.
type RemoteParameters struct {
	LogToConsole    bool
	LogWithID       bool
	LogLevel        string
	LogFormat       string
	CompressedTags  claimsheader.CompressionType
	DisableLogWrite bool
}

// GetParameters retrieves log parameters for Remote Enforcer.
func GetParameters() (logToConsole bool, logID string, logLevel string, logFormat string, compressedTagsVersion claimsheader.CompressionType, DisableLogWrite bool) {

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
	// here we skip the error handling because the env is passed from the main enforcerd, so it has to be either true or false.
	DisableLogWrite, _ = strconv.ParseBool(os.Getenv(constants.EnvDisableLogWrite))
	return
}
