package remenforcer

//keyPEM is a private interface required by the enforcerlauncher to expose method not exposed by the
//PolicyEnforcer interface
type keyPEM interface {
	AuthPEM() []byte
	TransmittedPEM() []byte
	EncodingPEM() []byte
}
