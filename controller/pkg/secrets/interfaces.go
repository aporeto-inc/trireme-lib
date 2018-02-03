package secrets

// PublicKeyAdder register a publicKey for a Node.
type PublicKeyAdder interface {

	// PublicKeyAdd adds the given cert for the given host.
	PublicKeyAdd(host string, cert []byte) error
}
