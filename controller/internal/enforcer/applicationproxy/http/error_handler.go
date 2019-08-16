package httpproxy

import (
	"context"
	"io"
	"net"
	"net/http"
)

const (
	// TriremeBadGatewayText is the message to send when downstream fails.
	TriremeBadGatewayText = ":The downstream port cannot be accessed. Please validate your service ports and address/hosts configuration"

	// TriremeGatewayTimeout is the message to send when downstream times-out.
	TriremeGatewayTimeout = ":The downstream node timed-out."

	// StatusClientClosedRequest non-standard HTTP status code for client disconnection
	StatusClientClosedRequest = 499

	// StatusClientClosedRequestText non-standard HTTP status for client disconnection
	StatusClientClosedRequestText = "Client Closed Request"
)

// TriremeHTTPErrHandler Standard error handler
type TriremeHTTPErrHandler struct{}

func (e TriremeHTTPErrHandler) ServeHTTP(w http.ResponseWriter, req *http.Request, err error) {
	statusCode := http.StatusInternalServerError

	if e, ok := err.(net.Error); ok {
		if e.Timeout() {
			statusCode = http.StatusGatewayTimeout
		} else {
			statusCode = http.StatusBadGateway
		}
	} else if err == io.EOF {
		statusCode = http.StatusBadGateway
	} else if err == context.Canceled {
		statusCode = StatusClientClosedRequest
	}

	w.WriteHeader(statusCode)
	w.Write([]byte(statusText(statusCode))) // nolint errcheck
}

func statusText(statusCode int) string {

	prefix := http.StatusText(statusCode)

	switch statusCode {
	case http.StatusGatewayTimeout:
		return prefix + TriremeGatewayTimeout
	case http.StatusBadGateway:
		return prefix + TriremeBadGatewayText
	case StatusClientClosedRequest:
		return StatusClientClosedRequestText
	}
	return prefix
}
