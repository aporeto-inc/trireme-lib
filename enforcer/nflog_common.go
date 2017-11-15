package enforcer

import (
	"github.com/aporeto-inc/trireme-lib/policy"
)

type nfLogger interface {
	start()
	stop()
}

type puInfoFunc func(string) (string, *policy.TagStore)
