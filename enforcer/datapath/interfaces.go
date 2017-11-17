package datapath

// ContextProcessor is an interface to provide context checks
type ContextProcessor interface {
	DoesContextExist(contextID string) bool
	IsContextServer(contextID string, backendip string) bool
}

// TokenProcessor is an interface to process tokens
type TokenProcessor interface {
	CreateSynToken(contextID string, payload []byte)
	CreateSynAckToken(contextID string, payload []byte)
	ParsePacketToken(auth ProxyAuthInfo, data []byte)
	CreateAckToken(contextID string, payload []byte)
	ParseAckToken(contextID string, data []byte)
}

// RuleProcessor is an interface to access rules
type RuleProcessor interface {
	CheckRejectRecvRules(contextID string) (int, bool)
	CheckAcceptRecvRules(contextID string) (int, bool)
	CheckRejectTxRules(contextID string) (int, bool)
	CheckAcceptTxRules(contextID string) (int, bool)
}

// DatapathAccessor is an interface for datapth to access contexts/rules/tokens
type DatapathAccessor interface {
	ContextProcessor
	TokenProcessor
	RuleProcessor
}
