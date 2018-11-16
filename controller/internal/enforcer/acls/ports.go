package acls

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"go.aporeto.io/trireme-lib/policy"
)

// ErrNoMatch is error returned when no match is found.
var ErrNoMatch = errors.New("No Match")

// portAction captures the minimum and maximum ports for an action
type portAction struct {
	min    uint16
	max    uint16
	policy *policy.FlowPolicy
}

// portActionList is a list of Port Actions
type portActionList []*portAction

// newPortAction parses a port spec and creates the action
func newPortAction(tcpport string, policy *policy.FlowPolicy) (*portAction, error) {

	p := &portAction{}
	if strings.Contains(tcpport, ":") {
		parts := strings.Split(tcpport, ":")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid port: %s", tcpport)
		}

		port, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil, err
		}
		p.min = uint16(port)

		port, err = strconv.Atoi(parts[1])
		if err != nil {
			return nil, err
		}
		p.max = uint16(port)

	} else {
		port, err := strconv.Atoi(tcpport)
		if err != nil {
			return nil, err
		}

		p.min = uint16(port)
		p.max = p.min
	}

	if p.min > p.max {
		return nil, errors.New("min port is greater than max port")
	}

	p.policy = policy

	return p, nil
}

func (p *portActionList) lookup(port uint16, preReported *policy.FlowPolicy) (report *policy.FlowPolicy, packet *policy.FlowPolicy, err error) {

	report = preReported

	// Scan the ports - TODO: better algorithm needed here
	for _, pa := range *p {
		if port >= pa.min && port <= pa.max {

			// Check observed policies.
			if pa.policy.ObserveAction.Observed() {
				if report == nil {
					report = pa.policy
				}
				if pa.policy.ObserveAction.ObserveContinue() {
					continue
				}
				packet = pa.policy
				return report, packet, nil
			}

			packet = pa.policy
			if report == nil {
				report = packet
			}
			return report, packet, nil
		}
	}

	return report, packet, ErrNoMatch
}
