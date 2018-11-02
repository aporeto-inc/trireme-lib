package buildflags

// Distro constants
const (
	Rhel6 = "rhel6"
	Rhel5 = "rhel5"
)

// Distro is a variable set during the build which allows different behaviors
var Distro string

// IsRHEL6 returns true if the build flag was set for rhel6
func IsRHEL6() bool {
	return Distro == Rhel6
}

// IsRHEL5 returns true if the build flag was set for rhel5
func IsRHEL5() bool {
	return Distro == Rhel5
}
