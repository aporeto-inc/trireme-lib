package tundatapath

const (
	// tunIPAddressSubnet the last byte is per device. This allows us to create upto 256 devices
	tunIPAddressSubnetIn  = "169.1.2."
	tunIPAddressSubnetOut = "169.1.3."
	tunStartIdentifier    = 1
	baseTunDeviceName     = "tun"
	baseTunDeviceInput    = "-in"
	baseTunDeviceOutput   = "-out"
	// maxNumQueues
	maxNumQueues = 255

	numTunDevicesPerDirection = 1
)
