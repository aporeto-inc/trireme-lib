// +build windows

package controller

import (
	"go.aporeto.io/trireme-lib/v11/controller/internal/supervisor"
)

func (t *trireme) setupEnvoyAuthorizer() error {
	return nil
}

func (t *trireme) setupEnvoySupervisor(sup supervisor.Supervisor) error {
	return nil
}
