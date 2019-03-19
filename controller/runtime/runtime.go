package runtime

// Configuration is configuration parameters that can be safely updated
// for the controller after it is started
type Configuration struct {
	// TCPTargetNetworks is the set of networks that host Trireme.
	TCPTargetNetworks []string
	// UDPTargetNetworks is the set of UDP networks that host Trireme.
	UDPTargetNetworks []string
	// ExcludedNetworks is the list of networks that must be excxluded from any enforcement.
	ExcludedNetworks []string
}

// DeepCopy copies the configuration and avoids locking issues.
func (c *Configuration) DeepCopy() *Configuration {
	return &Configuration{
		TCPTargetNetworks: append([]string{}, c.TCPTargetNetworks...),
		UDPTargetNetworks: append([]string{}, c.UDPTargetNetworks...),
		ExcludedNetworks:  append([]string{}, c.ExcludedNetworks...),
	}
}
