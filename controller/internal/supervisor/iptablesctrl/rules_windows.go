// +build windows

package iptablesctrl

var triremChains = `
-t OUTPUT  -N GlobalRules-OUTPUT
-t INPUT   -N GlobalRules-INPUT
-t OUTPUT  -N HostSvcRules-OUTPUT
-t INPUT   -N HostSvcRules-INPUT
-t OUTPUT  -N HostPU-OUTPUT
-t INPUT   -N HostPU-INPUT
`
var globalRules = `
-A  GlobalRules-INPUT -m set  --match-set {{.ExclusionsSet}} srcIP -j ACCEPT
-A  GlobalRules-OUTPUT -m set  --match-set {{.ExclusionsSet}} dstIP -j ACCEPT
`

// cgroupCaptureTemplate are the list of iptables commands that will hook traffic and send it to a PU specific
// chain. The hook method depends on the type of PU.
var cgroupCaptureTemplate = `
{{if isHostPU}}
-A HostPU-OUTPUT -p tcp -m set --match-set {{.TargetTCPNetSet}} dstIP -m set --match-set {{.DestIPSet}} dstIP,dstPort -j REDIRECT  --to-ports {{.ProxyPort}}
-A HostPU-OUTPUT -p tcp -m set --match-set {{.TargetTCPNetSet}} dstIP -j NFQUEUE -j MARK {{.Mark}}
-A HostPU-OUTPUT -p udp -m set --match-set {{.TargetUDPNetSet}} dstIP -j NFQUEUE -j MARK {{.Mark}}
-A HostPU-INPUT -p tcp -m set --match-set {{.SrvIPSet}} dstPort -j REDIRECT --to-ports {{.ProxyPort}}
-A HostPU-INPUT -p tcp -m set --match-set {{.TargetTCPNetSet}} srcIP -j NFQUEUE -j MARK {{.Mark}}
-A HostPU-INPUT -p udp -m set --match-set {{.TargetUDPNetSet}} srcIP -m string --string {{.UDPSignature}} --offset 2 -j NFQUEUE -j MARK {{.Mark}}
{{else}}
-A HostSvcRules-INPUT -p tcp -m set --match-set {{.SrvIPSet}} dstPort -j REDIRECT --to-ports {{.ProxyPort}}
-A HostSvcRules-INPUT -p tcp --dports {{.TCPPorts}} -j NFQUEUE -j MARK {{.Mark}}
-A HostSvcRules-INPUT -p udp --dports {{.UDPPorts}} -m string --string {{.UDPSignature}} --offset 2 -j NFQUEUE -j MARK {{.Mark}}
-A HostSvcRules-OUTPUT -p tcp --sports {{.TCPPorts}} -j NFQUEUE -j MARK {{.Mark}}
-A HostSvcRules-OUTPUT -p udp --sports {{.UDPPorts}} -j NFQUEUE -j MARK {{.Mark}}
{{end}}
`

// containerChainTemplate will hook traffic towards the container specific chains.
var containerChainTemplate = ``

var uidChainTemplate = ``

var acls = `
{{range .RejectObserveContinue}}
{{joinRule .}}
{{end}}

{{range .RejectNotObserved}}
{{joinRule .}}
{{end}}

{{range .RejectObserveApply}}
{{joinRule .}}
{{end}}

{{range .AcceptObserveContinue}}
{{joinRule .}}
{{end}}

{{range .AcceptNotObserved}}
{{joinRule .}}
{{end}}

{{range .AcceptObserveApply}}
{{joinRule .}}
{{end}}

{{range .ReverseRules}}
{{joinRule .}}
{{end}}
`

// packetCaptureTemplate are the rules that trap traffic towards the user space.
// windows uses it as a final deny-all.
var packetCaptureTemplate = `
{{if isHostPU}}
-A HostPU-OUTPUT -m set --match-set {{.IpsetPrefix}}WindowsAllIPs dstIP -j DROP -j NFLOG --nflog-group 10 --nflog-prefix {{.DefaultNFLOGDropPrefix}}
-A HostPU-INPUT -m set --match-set {{.IpsetPrefix}}WindowsAllIPs srcIP -j DROP -j NFLOG --nflog-group 11 --nflog-prefix {{.DefaultNFLOGDropPrefix}}
{{end}}
`

var proxyChainTemplate = ``

var deleteChains = ``

var globalHooks = ``

var legacyProxyRules = ``
