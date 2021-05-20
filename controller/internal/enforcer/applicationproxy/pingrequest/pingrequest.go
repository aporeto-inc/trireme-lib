package pingrequest

import (
	"bufio"
	"bytes"
	"errors"
	"net/http"

	"github.com/vmihailenco/msgpack"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
)

// PingHeaderKey holds the value for aporeto ping.
const PingHeaderKey = "X-APORETO-PING"

// CreateRaw is same as 'Create' but will return raw bytes of
// the request (wire format) returned by 'Create'.
func CreateRaw(host string, pingPayload *policy.PingPayload) ([]byte, error) {

	req, err := Create(host, pingPayload)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := req.Write(&buf); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// ExtractRaw is same as 'Extract' but will parse the raw
// bytes of the request passed and calls 'Validate'.
func ExtractRaw(rawReq []byte) (*policy.PingPayload, error) {

	buf := bytes.NewBuffer(rawReq)
	req, err := http.ReadRequest(bufio.NewReader(buf))
	if err != nil {
		return nil, err
	}

	return Extract(req)
}

// Create creates a new http request with the given host.
// It encodes the pingPayload passed with msgpack encoding and
// adds the data bytes to the header with key 'X-APORETO-PING'.
// It also returns the request.
func Create(host string, pingPayload *policy.PingPayload) (*http.Request, error) {

	req, err := http.NewRequest("GET", host, nil)
	if err != nil {
		return nil, err
	}

	payload, err := encode(pingPayload)
	if err != nil {
		return nil, err
	}

	req.Header.Add(PingHeaderKey, string(payload))

	return req, nil
}

// Extract verifies If the given request has the header
// 'X-APORETO-PING'. If it doesn't returns error, If it did have
// the header, it will try to decode the data using msgpack
// encoding and will return the ping payload.
func Extract(req *http.Request) (*policy.PingPayload, error) {

	payload := req.Header.Get(PingHeaderKey)
	if payload == "" {
		return nil, errors.New("missing ping payload in header")
	}

	pingPayload, err := decode([]byte(payload))
	if err != nil {
		return nil, err
	}

	return pingPayload, nil
}

func encode(pingPayload *policy.PingPayload) ([]byte, error) {
	return msgpack.Marshal(pingPayload)
}

func decode(data []byte) (*policy.PingPayload, error) {

	pingPayload := &policy.PingPayload{}

	if err := msgpack.Unmarshal(data, pingPayload); err != nil {
		return nil, err
	}

	return pingPayload, nil
}
