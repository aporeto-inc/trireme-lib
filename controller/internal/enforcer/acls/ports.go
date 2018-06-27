package acls

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"go.aporeto.io/trireme-lib/policy"
)

// portAction captures the minimum and maximum ports for an action
type portAction struct {
	min    uint16
	max    uint16
	policy *policy.FlowPolicy
}

// portActionList is a list of Port Actions
type portActionList []*portAction

// newPortAction parses a port spec and creates the action
func newPortAction(rule policy.IPRule) (*portAction, error) {

	p := &portAction{}
	if strings.Contains(rule.Port, ":") {
		parts := strings.Split(rule.Port, ":")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid port: %s", rule.Port)
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
		port, err := strconv.Atoi(rule.Port)
		if err != nil {
			return nil, err
		}

		p.min = uint16(port)
		p.max = p.min
	}

	if p.min > p.max {
		return nil, errors.New("min port is greater than max port")
	}

	p.policy = rule.Policy

	return p, nil
}

func (p *portActionList) lookup(port uint16, preReported *policy.FlowPolicy) (report *policy.FlowPolicy, packet *policy.FlowPolicy, err error) {

	report = preReported

	// Scan the ports - TODO: better algorithm needed here
	for _, pa := range *p {
		if port >= pa.min && port <= pa.max {

			// Check observed policies.
			if pa.policy.ObserveAction.Observed() {
				if report != nil {
					continue
				}
				report = pa.policy
				if pa.policy.ObserveAction.ObserveContinue() {
					continue
				}
				packet = report
				return report, packet, nil
			}

			packet = pa.policy
			if report == nil {
				report = packet
			}
			return report, packet, nil
		}
	}

	return report, packet, errors.New("No match")
}
