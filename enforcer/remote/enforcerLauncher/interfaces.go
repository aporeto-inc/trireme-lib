package enforcerLauncher

type keyPEM interface {
	AuthPEM() []byte
	TransmittedPEM() []byte
	EncodingPEM() []byte
}

type RemotePolicyEnforcer interface {
	PushConfig(contextID string)
}
