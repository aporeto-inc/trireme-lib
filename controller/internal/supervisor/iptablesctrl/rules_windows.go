// +build windows

package iptablesctrl

var triremChains = `
-t OUTPUT  -N GlobalRules-OUTPUT
-t INPUT   -N GlobalRules-INPUT
-t OUTPUT  -N ProcessRules-OUTPUT
-t INPUT   -N ProcessRules-INPUT
-t OUTPUT  -N HostSvcRules-OUTPUT
-t INPUT   -N HostSvcRules-INPUT
-t OUTPUT  -N HostPU-OUTPUT
-t INPUT   -N HostPU-INPUT
`

// When enforcerd is managed by cns-agent, its parent is mgr and its grandparent is boot
// -cns-agent-boot
//   |----cns-agent-mgr
//         |----enforcerd
// However, when mgr is updated, it will be respawned with a new pid and enforcerd will no longer
// have a parent
// -cns-agent-boot
//   |----cns-agent-mgr
// -enforcerd
// We need to allow this new mgr to communicate with the API server too, so we can allow
// cns-agent-boot and its children, in order to satisfy this.
// Note also that any currently active mgr pid needs to be explicitly added as its own rule here.

// globalRules are the rules not tied to a PU chain.
var globalRules = `
INPUT  GlobalRules-INPUT  -m set --match-set {{.ExclusionsSet}} srcIP -j ACCEPT_ONCE
OUTPUT GlobalRules-OUTPUT -m set --match-set {{.ExclusionsSet}} dstIP -j ACCEPT_ONCE
{{if isIPv4}}
INPUT  GlobalRules-INPUT  -m owner --pid-owner {{EnforcerPID}} -j ACCEPT
OUTPUT GlobalRules-OUTPUT -m owner --pid-owner {{EnforcerPID}} -j ACCEPT
{{if isManagedByCnsAgentManager}}
INPUT  GlobalRules-INPUT  -m owner --pid-owner {{CnsAgentBootPID}} --pid-children -j ACCEPT
OUTPUT GlobalRules-OUTPUT -m owner --pid-owner {{CnsAgentBootPID}} --pid-children -j ACCEPT
INPUT  GlobalRules-INPUT  -m owner --pid-owner {{CnsAgentMgrPID}} -j ACCEPT
OUTPUT GlobalRules-OUTPUT -m owner --pid-owner {{CnsAgentMgrPID}} -j ACCEPT
{{end}}
{{if enableDNSProxy}}
INPUT  GlobalRules-INPUT  -p udp --sports 53 -m set --match-set {{windowsDNSServerName}} srcIP -j NFQUEUE_FORCE -j MARK 83
{{end}}
{{end}}
{{if needICMP}}
OUTPUT GlobalRules-OUTPUT -p icmpv6 --icmp-type 133/0 -j ACCEPT
OUTPUT GlobalRules-OUTPUT -p icmpv6 --icmp-type 134/0 -j ACCEPT
OUTPUT GlobalRules-OUTPUT -p icmpv6 --icmp-type 135/0 -j ACCEPT
OUTPUT GlobalRules-OUTPUT -p icmpv6 --icmp-type 136/0 -j ACCEPT
OUTPUT GlobalRules-OUTPUT -p icmpv6 --icmp-type 141/0 -j ACCEPT
OUTPUT GlobalRules-OUTPUT -p icmpv6 --icmp-type 142/0 -j ACCEPT
INPUT  GlobalRules-INPUT -p icmpv6 --icmp-type 133/0 -j ACCEPT
INPUT  GlobalRules-INPUT -p icmpv6 --icmp-type 134/0 -j ACCEPT
INPUT  GlobalRules-INPUT -p icmpv6 --icmp-type 135/0 -j ACCEPT
INPUT  GlobalRules-INPUT -p icmpv6 --icmp-type 136/0 -j ACCEPT
INPUT  GlobalRules-INPUT -p icmpv6 --icmp-type 141/0 -j ACCEPT
INPUT  GlobalRules-INPUT -p icmpv6 --icmp-type 142/0 -j ACCEPT
{{end}}

`
var istioChainTemplate = ``
var proxyDNSChainTemplate = ``

// cgroupCaptureTemplate are the list of iptables commands that will hook traffic and send it to a PU specific
// chain. The hook method depends on the type of PU.
var cgroupCaptureTemplate = `

INPUT  {{.NetChain}} -p udp -m string --string {{.UDPSignature}} --offset 4 -j NFQUEUE -j MARK {{.PacketMark}}
INPUT  {{.NetChain}} -p udp -m string --string {{.UDPSignature}} --offset 6 -j NFQUEUE -j MARK {{.PacketMark}}
OUTPUT {{.AppChain}} -p tcp --tcp-flags 18,18 -j NFQUEUE -j MARK {{.PacketMark}}
INPUT  {{.NetChain}} -p tcp --tcp-flags 18,18 -m set --match-set {{.TargetTCPNetSet}} srcIP -j NFQUEUE -j MARK {{.PacketMark}}
{{if isHostPU}}
OUTPUT HostPU-OUTPUT -p tcp -m set --match-set {{.TargetTCPNetSet}} dstIP -m set --match-set {{.DestIPSet}} dstIP,dstPort -j REDIRECT  --to-ports {{.ProxyPort}}
INPUT  HostPU-INPUT  -p tcp -m set --match-set {{.SrvIPSet}} dstPort -j REDIRECT --to-ports {{.ProxyPort}}
OUTPUT HostPU-OUTPUT -j {{.AppChain}}
INPUT  HostPU-INPUT  -j {{.NetChain}}
{{else}}
{{if isProcessPU}}
OUTPUT ProcessRules-OUTPUT -j {{.AppChain}} -m owner --pid-owner {{.ContextID}} --pid-childrenonly
INPUT  ProcessRules-INPUT  -j {{.NetChain}} -m owner --pid-owner {{.ContextID}} --pid-childrenonly
{{else}}
{{if isTCPPorts}}
OUTPUT HostSvcRules-OUTPUT -p tcp --dports {{.TCPPorts}} -j {{.AppChain}}
INPUT  HostSvcRules-INPUT  -p tcp --sports {{.TCPPorts}} -j {{.NetChain}}
{{end}}
{{if isUDPPorts}}
OUTPUT HostSvcRules-OUTPUT -p udp --dports {{.UDPPorts}} -j {{.AppChain}}
INPUT  HostSvcRules-INPUT  -p udp --sports {{.UDPPorts}} -j {{.NetChain}}
{{end}}
{{end}}
{{end}}
`

// containerChainTemplate will hook traffic towards the container specific chains.
var containerChainTemplate = ``

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

var preNetworkACLRuleTemplate = `
{{/* matches syn and ack packets FIN,RST,URG,PSH NONE */}}
INPUT  {{.NetChain}} -p tcp --tcp-flags 45,0 --tcp-option 34 -j NFQUEUE MARK {{.PacketMark}}
`

// packetCaptureTemplate are the rules that trap traffic towards the user space.
// windows uses it as a final deny-all.
var packetCaptureTemplate = `
OUTPUT {{.AppChain}} -p tcp --tcp-flags 1,1 -m set --match-set {{.TargetTCPNetSet}} dstIP -j ACCEPT
OUTPUT {{.AppChain}} -p tcp -m set --match-set {{.TargetTCPNetSet}} dstIP -j NFQUEUE -j MARK {{.PacketMark}}
OUTPUT {{.AppChain}} -p udp -m set --match-set {{.TargetUDPNetSet}} dstIP -j NFQUEUE -j MARK {{.PacketMark}}
INPUT  {{.NetChain}} -p tcp --tcp-flags 2,0 -j NFQUEUE -j MARK {{.PacketMark}}
{{range appAnyRules}}
{{joinRule .}}
{{end}}
{{range netAnyRules}}
{{joinRule .}}
{{end}}
{{range appAnyRules}}
{{joinRule .}}
{{end}}
{{range netAnyRules}}
{{joinRule .}}
{{end}}
{{if isAppDrop}}
OUTPUT {{.AppChain}} -m set --match-set {{windowsAllIpsetName}} dstIP -j NFLOG --nflog-group 10 --nflog-prefix {{.AppNFLOGDropPacketLogPrefix}}
{{end}}
OUTPUT {{.AppChain}} -m set --match-set {{windowsAllIpsetName}} dstIP -j {{.AppDefaultAction}} -j NFLOG --nflog-group 10 --nflog-prefix {{.AppNFLOGPrefix}}
{{if isNetDrop}}
INPUT  {{.NetChain}} -m set --match-set {{windowsAllIpsetName}} srcIP -j NFLOG --nflog-group 11 --nflog-prefix {{.NetNFLOGDropPacketLogPrefix}}
{{end}}
INPUT  {{.NetChain}} -m set --match-set {{windowsAllIpsetName}} srcIP -j {{.NetDefaultAction}} -j NFLOG --nflog-group 11 --nflog-prefix {{.NetNFLOGPrefix}}
`

var proxyChainTemplate = ``

var globalHooks = ``
