package buildflags

// Distro constants
const (
	Rhel6 = "rhel6"
	Rhel5 = "rhel5"
	None  = ""
)

// Distro is a variable set during the build which allows different behaviors
var Distro string
