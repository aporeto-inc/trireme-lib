package enforcer

import (
	"github.com/aporeto-inc/trireme/policy"
)

type nfLogger interface {
	start()
}

type puInfoFunc func(string) (string, *policy.TagStore)
