// +build !windows

package controller

import (
	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/supervisor"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
)

func (t *trireme) setupEnvoyAuthorizer() error {

	var err error
	t.enforcers[constants.LocalEnvoyAuthorizer], err = enforcer.New(
		t.config.mutualAuth,
		t.config.fq,
		t.config.collector,
		t.config.secret,
		t.config.serverID,
		t.config.validity,
		constants.LocalEnvoyAuthorizer,
		t.config.procMountPoint,
		t.config.externalIPcacheTimeout,
		t.config.packetLogs,
		t.config.runtimeCfg,
		t.config.tokenIssuer,
		t.config.isBPFEnabled,
		t.config.agentVersion,
		policy.None,
	)
	return err
}

func (t *trireme) setupEnvoySupervisor(sup supervisor.Supervisor) error {

	t.supervisors[constants.LocalEnvoyAuthorizer] = sup
	return nil
}
