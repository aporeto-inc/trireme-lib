package datapathproxy

type ContextProcessor interface {
	DoesContextExist(contextID string) bool
	IsContextServer(contextID string, backendip string) bool
}

type TokenProcessor interface {
	CreateSynToken(contextID string, payload []byte)
	CreateSynAckToken(contextID string, payload []byte)
	ParsePacketToken(auth ProxyAuthInfo, data []byte)
	CreateAckToken(contextID string, payload []byte)
	ParseAckToken(contextID string, data []byte)
}

type RuleProcessor interface {
	CheckRejectRecvRules(contextID string) (int, bool)
	CheckAcceptRecvRules(contextID string) (int, bool)
	CheckRejectTxRules(contextID string) (int, bool)
	CheckAcceptTxRules(contextID string) (int, bool)
}
type DatapathAccessor interface {
	ContextProcessor
	TokenProcessor
	RuleProcessor
}
