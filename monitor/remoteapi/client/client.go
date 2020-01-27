package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"go.aporeto.io/trireme-lib/v11/common"
)

type dialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

// SendRequest sends a request to the remote.
// TODO: Add retries
func (c *Client) SendRequest(event *common.EventInfo) error {

	httpc := http.Client{
		Transport: &http.Transport{
			DialContext:     c.getDialContext(),
			MaxIdleConns:    10,
			IdleConnTimeout: 10 * time.Second,
		},
	}

	b := new(bytes.Buffer)
	if err := json.NewEncoder(b).Encode(event); err != nil {
		return fmt.Errorf("Unable to encode message: %s", err)
	}

	resp, err := httpc.Post("http://unix", "application/json", b)
	if err != nil {
		return err
	}
	defer resp.Body.Close() // nolint

	if resp.StatusCode == http.StatusAccepted {
		return nil
	}

	errorBuffer, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("Invalid request: %s", err)
	}

	return fmt.Errorf("Invalid request : %s", string(errorBuffer))
}
