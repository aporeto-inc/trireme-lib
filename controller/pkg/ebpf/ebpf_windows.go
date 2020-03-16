package ebpf

// ISeBPFSupported returns false for Windows.
func ISeBPFSupported() bool {
	return false
}

//LoadBPF is not supported on Windows.
func LoadBPF() BPFModule {
	return nil
}
