package nfqdatapath

// ContextProcessor is an interface to provide context checks
type ContextProcessor interface {
	DoesContextExist(contextID string) bool
	IsContextServer(contextID string, backendip string) bool
}

// RuleProcessor is an interface to access rules
type RuleProcessor interface {
	CheckRejectRecvRules(contextID string) (int, bool)
	CheckAcceptRecvRules(contextID string) (int, bool)
	CheckRejectTxRules(contextID string) (int, bool)
	CheckAcceptTxRules(contextID string) (int, bool)
}

// Accessor is an interface for datapth to access contexts/rules/tokens
type Accessor interface {
	ContextProcessor
	RuleProcessor
}
