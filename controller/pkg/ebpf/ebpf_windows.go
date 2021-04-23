package ebpf

// IsEBPFSupported returns false for Windows.
func IsEBPFSupported() bool {
	return false
}

// LoadBPF is not supported on Windows.
func LoadBPF() BPFModule {
	return nil
}
