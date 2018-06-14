package tundatapath

const (
	// tunIPAddressSubnet the last byte is per device. This allows us to create upto 256 devices
	tunIPAddressSubnetIn  = "169.1.2."
	tunIPAddressSubnetOut = "169.1.3."
	//tunStartIdentifier    = 1
	baseTunDeviceName   = "tun"
	baseTunDeviceInput  = "-in"
	baseTunDeviceOutput = "-out"
	// maxNumQueues
	maxNumQueues = 256

	numTunDevicesPerDirection = 1

	// NetworkRuleTable route table pointed to by Rule trapping incoming marked packets
	NetworkRuleTable = 10
	// ApplicationRuleTable route table pointed to by Rule trapping outgoing marked packets
	ApplicationRuleTable = 11
	// RulePriority is the priority of the rule in the rule table.(Lower number means higher prio)
	RulePriority = 0
	// RuleMarkBit is the bit which is set in 32 bit mark TODO: needs to move to a higher package
	RuleMarkBit = 16
	// RuleMask mask for low  16 bits of the mark
	RuleMask = 0xffff
)
