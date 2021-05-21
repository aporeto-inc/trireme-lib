// +build !windows,!rhel6

package iptablesctrl

import (
	"strconv"

	markconstants "go.aporeto.io/enforcerd/trireme-lib/utils/constants"
)

var enforcerCgroupMark = strconv.Itoa(markconstants.EnforcerCgroupMark)

var triremChains = `
{{if isLocalServer}}
-t {{.MangleTable}} -N {{.HostInput}}
-t {{.MangleTable}} -N {{.HostOutput}}
-t {{.MangleTable}} -N {{.NetworkSvcInput}}
-t {{.MangleTable}} -N {{.NetworkSvcOutput}}
-t {{.MangleTable}} -N {{.TriremeInput}}
-t {{.MangleTable}} -N {{.TriremeOutput}}
{{end}}
-t {{.MangleTable}} -N {{.NfqueueOutput}}
-t {{.MangleTable}} -N {{.NfqueueInput}}
-t {{.MangleTable}} -N {{.MangleProxyAppChain}}
-t {{.MangleTable}} -N {{.MainAppChain}}
-t {{.MangleTable}} -N {{.MainNetChain}}
-t {{.MangleTable}} -N {{.MangleProxyNetChain}}
-t {{.NatTable}} -N {{.NatProxyAppChain}}
-t {{.NatTable}} -N {{.NatProxyNetChain}}
{{if isIstioEnabled}}
-t {{.MangleTable}} -N {{.IstioChain}}
{{end}}
`

var globalRules = `

{{.MangleTable}} {{.NfqueueInput}} -j HMARK --hmark-tuple dport,sport --hmark-mod {{.NumNFQueues}} --hmark-offset {{.DefaultInputMark}} --hmark-rnd 0xdeadbeef

{{range $index,$queuenum := .NFQueues}}
{{$.MangleTable}} {{$.NfqueueInput}} -m mark --mark {{getInputMark}} -j NFQUEUE --queue-num {{$queuenum}} --queue-bypass
{{end}}

{{.MangleTable}} {{.NfqueueOutput}} -j HMARK --hmark-tuple sport,dport --hmark-mod {{.NumNFQueues}} --hmark-offset 0 --hmark-rnd 0xdeadbeef

{{range $index,$queuenum := .NFQueues}}
{{$.MangleTable}} {{$.NfqueueOutput}} -m mark --mark {{getOutputMark}} -j NFQUEUE --queue-num {{$queuenum}} --queue-bypass
{{end}}

{{.MangleTable}} INPUT -m set ! --match-set {{.ExclusionsSet}} src -j {{.MainNetChain}}
{{.MangleTable}} {{.MainNetChain}} -j {{ .MangleProxyNetChain }}

{{/* tcp rules */}}

{{.MangleTable}} {{.MainNetChain}} -p tcp -m mark --mark {{.PacketMarkToSetConnmark}} -j CONNMARK --set-mark {{.DefaultExternalConnmark}}
{{.MangleTable}} {{.MainNetChain}} -p tcp -m mark --mark {{.PacketMarkToSetConnmark}} -j ACCEPT
{{.MangleTable}} {{.MainNetChain}} -m connmark --mark {{.DefaultExternalConnmark}} -p tcp ! --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j ACCEPT
{{.MangleTable}} {{$.MainNetChain}} -m set --match-set {{$.TargetTCPNetSet}} src -p tcp -m tcp --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j {{.NfqueueInput}}

{{/* tcp rules ends */}}

{{/* udp rules */}}

{{.MangleTable}} {{$.MainNetChain}} -p udp -m string --string {{$.UDPSignature}} --algo bm --to 65535 -j {{.NfqueueInput}}
{{.MangleTable}} {{.MainNetChain}} -p udp -m connmark --mark {{.DefaultDropConnmark}} -m comment --comment "Drop UDP ACL" -j DROP 
{{.MangleTable}} {{.MainNetChain}} -m connmark --mark {{.DefaultConnmark}} -p udp -j ACCEPT

{{/* udp rules ends */}}

{{if isLocalServer}}
{{.MangleTable}} {{.MainNetChain}} -j {{.TriremeInput}}
{{.MangleTable}} {{.MainNetChain}} -j {{.NetworkSvcInput}}
{{.MangleTable}} {{.MainNetChain}} -j {{.HostInput}}
{{end}}

{{if isIstioEnabled}}
{{.MangleTable}} OUTPUT -j {{.IstioChain}}
{{.MangleTable}} {{.MainNetChain}} -p tcp --dport {{IstioRedirPort}} -m addrtype --dst-type LOCAL -m addrtype --src-type LOCAL -j ACCEPT
{{end}}
{{.MangleTable}} OUTPUT -m set ! --match-set {{.ExclusionsSet}} dst -j {{.MainAppChain}}

{{.MangleTable}} {{.MainAppChain}} -m mark --mark {{.PacketMarkToSetConnmark}} -j CONNMARK --set-mark {{.DefaultExternalConnmark}}
{{.MangleTable}} {{.MainAppChain}} -p tcp -m mark --mark {{.PacketMarkToSetConnmark}} -j ACCEPT

{{/* enforcer rules */}}
{{.MangleTable}} {{.MainAppChain}}  -p udp --dport 53 -m mark --mark 0x40 -m cgroup --cgroup ` + enforcerCgroupMark + ` -j CONNMARK --set-mark {{.DefaultExternalConnmark}}
{{.MangleTable}} {{.MainAppChain}}  -p udp --dport 53 -m mark --mark 0x40 -j CONNMARK --set-mark {{.DefaultExternalConnmark}}
{{/* enforcer rules ends */}}


{{.MangleTable}} {{.MainAppChain}} -j {{.MangleProxyAppChain}}
{{.MangleTable}} {{.MainAppChain}} -m connmark --mark {{.DefaultExternalConnmark}} -j ACCEPT
{{.MangleTable}} {{.MainAppChain}} -p udp -m connmark --mark {{.DefaultDropConnmark}} -m comment --comment "Drop UDP ACL" -j DROP
{{.MangleTable}} {{.MainAppChain}} -m connmark --mark {{.DefaultConnmark}} -p tcp ! --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK  -j ACCEPT
{{.MangleTable}} {{.MainAppChain}} -m connmark --mark {{.DefaultConnmark}} -p udp -j ACCEPT
{{.MangleTable}} {{.MainAppChain}} -m mark --mark {{.RawSocketMark}} -j ACCEPT
{{$.MangleTable}} {{$.MainAppChain}} -p tcp -m tcp --tcp-flags FIN,RST,URG,PSH,SYN,ACK SYN,ACK -j {{.NfqueueOutput}}

{{if isLocalServer}}
{{.MangleTable}} {{.MainAppChain}} -j {{.TriremeOutput}}
{{.MangleTable}} {{.MainAppChain}} -j {{.NetworkSvcOutput}}
{{.MangleTable}} {{.MainAppChain}} -j {{.HostOutput}}
{{end}}

{{.MangleTable}} {{.MangleProxyAppChain}} -m mark --mark {{.ProxyMark}} -j ACCEPT
{{.MangleTable}} {{.MangleProxyNetChain}} -m mark --mark {{.ProxyMark}} -j ACCEPT

{{/* Using RETURN instead of ACCEPT because ACCEPT skips k8s DNS NAT rules */}}
{{.NatTable}} {{.NatProxyAppChain}} -m mark --mark {{.ProxyMark}} -j RETURN
{{.NatTable}} {{.NatProxyNetChain}} -m mark --mark {{.ProxyMark}} -j ACCEPT
`

// cgroupCaptureTemplate are the list of iptables commands that will hook traffic and send it to a PU specific
// chain. The hook method depends on the type of PU.
var cgroupCaptureTemplate = `

{{if isTCPPorts}}
{{.MangleTable}} {{.NetSection}} -p tcp -m multiport --destination-ports {{.TCPPorts}} -m comment --comment PU-Chain -j {{.NetChain}}
{{else}}
{{.MangleTable}} {{.NetSection}} -p tcp -m set --match-set {{.TCPPortSet}} dst -m comment --comment PU-Chain -j {{.NetChain}}
{{end}}

{{if isHostPU}}
{{/* UDP response traffic needs to be accepted */}}
{{.MangleTable}} {{.NetSection}} -p udp -m udp -m state --state ESTABLISHED -m connmark ! --mark {{.DefaultHandShakeMark}} -j ACCEPT
{{/* Traffic to systemd resolver/dnsmasq gets accepted */}}
{{.MangleTable}} {{.NetSection}} -p udp -m udp --dport 53 -j ACCEPT
{{.MangleTable}} {{.NetSection}} -m comment --comment PU-Chain -j {{.NetChain}}
{{end}}

{{if isUDPPorts}}
{{.MangleTable}} {{.NetSection}} -p udp -m multiport --destination-ports {{.UDPPorts}} -m comment --comment PU-Chain -j {{.NetChain}}
{{end}}

{{if isHostPU}}
{{.MangleTable}} {{.AppSection}} -m cgroup ! --cgroup ` + enforcerCgroupMark + ` -m comment --comment PU-Chain -j MARK --set-mark {{.Mark}}
{{.MangleTable}} {{.AppSection}} -m mark --mark {{.Mark}} -m comment --comment PU-Chain -j {{.AppChain}}
{{else}}
{{.MangleTable}} {{.AppSection}} -m cgroup --cgroup {{.Mark}} -m comment --comment PU-Chain -j MARK --set-mark {{.Mark}}
{{.MangleTable}} {{.AppSection}} -m mark --mark {{.Mark}} -m comment --comment PU-Chain -j {{.AppChain}}
{{end}}

{{if isHostPU}}
{{if isIPV6Enabled}}
{{.MangleTable}} {{.AppSection}} -p icmpv6 -j {{.AppChain}}
{{else}}
{{.MangleTable}} {{.AppSection}} -p icmp -j {{.AppChain}}
{{end}}
{{end}}
`

// containerChainTemplate will hook traffic towards the container specific chains.
var containerChainTemplate = `
{{.MangleTable}} {{.AppSection}} -m comment --comment Container-specific-chain -j {{.AppChain}}
{{.MangleTable}} {{.NetSection}} -m comment --comment Container-specific-chain -j {{.NetChain}}`

var istioChainTemplate = `
{{.MangleTable}} {{.IstioChain}} -p tcp -m owner ! --uid-owner {{IstioUID}} -j ACCEPT
{{.MangleTable}} {{.IstioChain}} -p tcp -m owner --uid-owner {{IstioUID}} -m addrtype --dst-type LOCAL -m addrtype --src-type LOCAL -j CONNMARK --set-mark {{.DefaultExternalConnmark}}
{{.MangleTable}} {{.IstioChain}} -p tcp -m owner --uid-owner {{IstioUID}} -m addrtype --dst-type LOCAL -j ACCEPT`

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
{{/* matches syn and ack packets */}}
{{$.MangleTable}} {{$.NetChain}} -p tcp -m tcp --tcp-option 34 -m tcp --tcp-flags FIN,RST,URG,PSH NONE -j {{.NfqueueInput}}
`

// packetCaptureTemplate are the rules that trap traffic towards the user space.
var packetCaptureTemplate = `
{{if needICMP}}
{{.MangleTable}} {{.AppChain}} -p icmpv6 -m bpf --bytecode "{{.ICMPv6Allow}}" -j ACCEPT
{{end}}

{{if isNotContainerPU}}

{{$.MangleTable}} {{$.AppChain}} -m set --match-set {{$.TargetTCPNetSet}} dst -p tcp -m tcp --tcp-flags FIN FIN -j ACCEPT
{{$.MangleTable}} {{$.AppChain}} -m set --match-set {{$.TargetTCPNetSet}} dst -p tcp -j HMARK --hmark-tuple sport,dport --hmark-mod {{.NumNFQueues}} --hmark-offset {{packetMark}} --hmark-rnd 0xdeadbeef
{{$.MangleTable}} {{$.AppChain}} -p udp -m set --match-set {{$.TargetUDPNetSet}} dst -j HMARK --hmark-tuple sport,dport --hmark-mod {{.NumNFQueues}} --hmark-offset {{packetMark}} --hmark-rnd 0xdeadbeef

{{range $index,$queuenum := .NFQueues}}
{{$.MangleTable}} {{$.AppChain}} -m mark --mark {{getOutputMark}} -j NFQUEUE --queue-num {{$queuenum}} --queue-bypass
{{end}}

{{else}}
{{$.MangleTable}} {{$.AppChain}} -m set --match-set {{$.TargetTCPNetSet}} dst -p tcp -m tcp --tcp-flags FIN FIN -j ACCEPT
{{$.MangleTable}} {{$.AppChain}} -m set --match-set {{$.TargetTCPNetSet}} dst -p tcp -j {{.NfqueueOutput}}
{{$.MangleTable}} {{$.AppChain}} -p udp -m set --match-set {{$.TargetUDPNetSet}} dst -j {{.NfqueueOutput}}
{{end}}

{{.MangleTable}} {{.AppChain}} -p tcp -m state --state ESTABLISHED -m comment --comment TCP-Established-Connections -j ACCEPT

{{.MangleTable}} {{.AppChain}} -p udp -m state --state ESTABLISHED -m comment --comment UDP-Established-Connections -j ACCEPT

{{range appAnyRules}}
{{joinRule .}}
{{end}}
{{.MangleTable}} {{.AppChain}} -d {{.DefaultIP}} -m state --state NEW -j NFLOG  --nflog-group 10 --nflog-prefix {{.AppNFLOGPrefix}}
{{if isAppDrop}}
{{.MangleTable}} {{.AppChain}} -d {{.DefaultIP}} -m state ! --state NEW -j NFLOG --nflog-group 10 --nflog-prefix {{.AppNFLOGDropPacketLogPrefix}}
{{end}}
{{.MangleTable}} {{.AppChain}} -d {{.DefaultIP}} -j {{.AppDefaultAction}}

{{if needICMP}}
{{.MangleTable}} {{.NetChain}} -p icmpv6 -m bpf --bytecode "{{.ICMPv6Allow}}" -j ACCEPT
{{end}}


{{.MangleTable}} {{.NetChain}} -p tcp -m set --match-set {{$.TargetTCPNetSet}} src -m tcp --tcp-flags SYN NONE -j {{.NfqueueInput}}
{{.MangleTable}} {{.NetChain}} -p udp -m set --match-set {{.TargetUDPNetSet}} src --match limit --limit 1000/s -j {{.NfqueueInput}}

{{.MangleTable}} {{.NetChain}} -p tcp -m state --state ESTABLISHED -m comment --comment TCP-Established-Connections -j ACCEPT

{{range netAnyRules}}
{{joinRule .}}
{{end}}

{{.MangleTable}} {{.NetChain}} -s {{.DefaultIP}} -m state --state NEW -j NFLOG --nflog-group 11 --nflog-prefix {{.NetNFLOGPrefix}}
{{if isNetDrop}}
{{.MangleTable}} {{.NetChain}} -s {{.DefaultIP}} -m state ! --state NEW -j NFLOG --nflog-group 11 --nflog-prefix {{.NetNFLOGDropPacketLogPrefix}}
{{end}}
{{.MangleTable}} {{.NetChain}} -s {{.DefaultIP}} -j {{.NetDefaultAction}}
`

var proxyDNSChainTemplate = `
{{if enableDNSProxy}}
{{.MangleTable}} {{.MangleProxyAppChain}} -p udp -m udp --sport {{.DNSProxyPort}} -j ACCEPT
{{.MangleTable}} {{.MangleProxyNetChain}} -p udp -m udp --dport {{.DNSProxyPort}} -j ACCEPT
{{if isCgroupSet}}
{{.NatTable}} {{.NatProxyAppChain}} -d {{.DNSServerIP}} -p udp --dport 53 -m mark ! --mark {{.ProxyMark}} -m cgroup --cgroup {{.CgroupMark}} -j CONNMARK --save-mark
{{.NatTable}} {{.NatProxyAppChain}} -d {{.DNSServerIP}} -p udp --dport 53 -m mark ! --mark {{.ProxyMark}} -m cgroup --cgroup {{.CgroupMark}} -j REDIRECT --to-ports {{.DNSProxyPort}}
{{else}}
{{.NatTable}} {{.NatProxyAppChain}} -d {{.DNSServerIP}} -p udp --dport 53 -m mark ! --mark {{.ProxyMark}} -j REDIRECT --to-ports {{.DNSProxyPort}}
{{end}}
{{end}}
`
var proxyChainTemplate = `
{{.MangleTable}} {{.MangleProxyAppChain}} -p tcp -m tcp --sport {{.ProxyPort}} -j ACCEPT
{{.MangleTable}} {{.MangleProxyAppChain}} -p tcp -m set --match-set {{.SrvIPSet}} src -j ACCEPT
{{.MangleTable}} {{.MangleProxyAppChain}} -p tcp -m set --match-set {{.DestIPSet}} dst,dst -m mark ! --mark {{.ProxyMark}} -j ACCEPT

{{.MangleTable}} {{.MangleProxyNetChain}} -p tcp -m set --match-set {{.DestIPSet}} src,src -j ACCEPT
{{.MangleTable}} {{.MangleProxyNetChain}} -p tcp -m set --match-set {{.SrvIPSet}} src -m addrtype --src-type LOCAL -j ACCEPT
{{.MangleTable}} {{.MangleProxyNetChain}} -p tcp -m tcp --dport {{.ProxyPort}} -j ACCEPT

{{if isCgroupSet}}
{{.NatTable}} {{.NatProxyAppChain}} -p tcp -m set --match-set {{.DestIPSet}} dst,dst -m mark ! --mark {{.ProxyMark}} -m cgroup --cgroup {{.CgroupMark}} -j REDIRECT --to-ports {{.ProxyPort}}
{{else}}
{{.NatTable}} {{.NatProxyAppChain}} -p tcp -m set --match-set {{.DestIPSet}} dst,dst -m mark ! --mark {{.ProxyMark}} -j REDIRECT --to-ports {{.ProxyPort}}
{{end}}
{{.NatTable}} {{.NatProxyNetChain}} -p tcp -m set --match-set {{.SrvIPSet}} dst -m mark ! --mark {{.ProxyMark}} -j REDIRECT --to-ports {{.ProxyPort}}`

var globalHooks = `
{{.MangleTable}} INPUT -m set ! --match-set {{.ExclusionsSet}} src -j {{.MainNetChain}}
{{.MangleTable}} OUTPUT -m set ! --match-set {{.ExclusionsSet}} dst -j {{.MainAppChain}}
{{.NatTable}} PREROUTING -p tcp -m addrtype --dst-type LOCAL -m set ! --match-set {{.ExclusionsSet}} src -j {{.NatProxyNetChain}}
{{.NatTable}} OUTPUT -m set ! --match-set {{.ExclusionsSet}} dst -j {{.NatProxyAppChain}}
`
