// +build !rhel6

package buildflags

// Distro constants
const (
	Rhel6 = ""
	Rhel5 = ""
)

// IsRHEL6 returns true if the build flag was set for rhel6
func IsRHEL6() bool {
	return false
}

// IsRHEL5 returns true if the build flag was set for rhel5
func IsRHEL5() bool {
	return false
}

// IsLegacyKernel returns true if the build flag was set for rhel5/rhel6
func IsLegacyKernel() bool {
	return false
}
