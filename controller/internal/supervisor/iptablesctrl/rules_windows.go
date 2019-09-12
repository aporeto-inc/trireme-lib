// +build windows

package iptablesctrl

var triremChains = `
-t INPUT -N GlobalRules-INPUT
-t OUTPUT -N GlobalRules-OUTPUT 
`
var globalRules = `
-t  GlobalRules-INPUT -m set  --match-set {{.ExclusionsSet}} src -j ACCEPT
-t  GlobalRules-OUTPUT -m set  --match-set {{.ExclusionsSet}} dst -j ACCEPT

`

// cgroupCaptureTemplate are the list of iptables commands that will hook traffic and send it to a PU specific
// chain. The hook method depends on the type of PU.
var cgroupCaptureTemplate = ``

// containerChainTemplate will hook traffic towards the container specific chains.
var containerChainTemplate = ``

var uidChainTemplate = ``

var acls = ``

// packetCaptureTemplate are the rules that trap traffic towards the user space.
var packetCaptureTemplate = ``

var proxyChainTemplate = ``

var deleteChains = ``

var globalHooks = ``

var legacyProxyRules = ``
