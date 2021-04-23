// +build rhel6

package iptablesctrl

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
`

var globalRules = `

{{$.MangleTable}} {{$.NfqueueInput}} -j MARK --set-mark {{.DefaultInputMark}}
{{$.MangleTable}} {{$.NfqueueInput}} -m mark --mark {{.DefaultInputMark}} -j NFQUEUE --queue-balance {{queueBalance}} --queue-bypass

{{$.MangleTable}} {{$.NfqueueOutput}} -j MARK --set-mark 0
{{$.MangleTable}} {{$.NfqueueOutput}} -m mark --mark 0 -j NFQUEUE --queue-balance {{queueBalance}} --queue-bypass

{{.MangleTable}} INPUT -m set ! --match-set {{.ExclusionsSet}} src -j {{.MainNetChain}}
{{.MangleTable}} {{.MainNetChain}} -p udp --sport 53 -j ACCEPT
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

{{.MangleTable}} OUTPUT -m set ! --match-set {{.ExclusionsSet}} dst -j {{.MainAppChain}}
{{.MangleTable}} {{.MainAppChain}} -p udp --dport 53 -j ACCEPT

{{.MangleTable}} {{.MainAppChain}} -m mark --mark {{.PacketMarkToSetConnmark}} -j CONNMARK --set-mark {{.DefaultExternalConnmark}}
{{.MangleTable}} {{.MainAppChain}} -p tcp -m mark --mark {{.PacketMarkToSetConnmark}} -j ACCEPT

{{.MangleTable}} {{.MainAppChain}}  -p udp --dport 53 -m mark --mark 0x40 -j CONNMARK --set-mark {{.DefaultExternalConnmark}}

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

{{.NatTable}} {{.NatProxyAppChain}} -m mark --mark {{.ProxyMark}} -j ACCEPT
{{.NatTable}} {{.NatProxyNetChain}} -m mark --mark {{.ProxyMark}} -j ACCEPT
`

// cgroupCaptureTemplate is not used for rhel6
var cgroupCaptureTemplate = ``

// containerChainTemplate is not used for rhel6
var containerChainTemplate = ``

// istioChainTemplate is not used for rhel6
var istioChainTemplate = ``

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

{{.MangleTable}} {{.AppChain}} -p icmp -j NFQUEUE --queue-balance {{queueBalance}}
{{.MangleTable}} {{.NetChain}} -p icmp -j NFQUEUE --queue-balance {{queueBalance}}

{{$.MangleTable}} {{$.AppChain}} -m set --match-set {{$.TargetTCPNetSet}} dst -p tcp -m tcp --tcp-flags FIN FIN -j ACCEPT
{{$.MangleTable}} {{$.AppChain}} -m set --match-set {{$.TargetTCPNetSet}} dst -p tcp -j MARK --set-mark {{packetMark}}
{{$.MangleTable}} {{$.AppChain}} -p udp -m set --match-set {{$.TargetUDPNetSet}} dst -j MARK --set-mark {{packetMark}}
{{$.MangleTable}} {{$.AppChain}} -m mark --mark {{packetMark}} -j NFQUEUE --queue-balance {{queueBalance}} --queue-bypass

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

// proxyDNSChainTemplate is not used for rhel6
var proxyDNSChainTemplate = ``

// proxyChainTemplate is not used for rhel6
var proxyChainTemplate = ``

var globalHooks = `
{{.MangleTable}} INPUT -m set ! --match-set {{.ExclusionsSet}} src -j {{.MainNetChain}}
{{.MangleTable}} OUTPUT -m set ! --match-set {{.ExclusionsSet}} dst -j {{.MainAppChain}}
{{.NatTable}} PREROUTING -p tcp -m addrtype --dst-type LOCAL -m set ! --match-set {{.ExclusionsSet}} src -j {{.NatProxyNetChain}}
{{.NatTable}} OUTPUT -m set ! --match-set {{.ExclusionsSet}} dst -j {{.NatProxyAppChain}}
`

var legacyProxyRules = `
{{.MangleTable}} {{.MangleProxyAppChain}} -p tcp -m tcp --sport {{.ProxyPort}} -j ACCEPT
{{if enableDNSProxy}}
{{.MangleTable}} {{.MangleProxyAppChain}} -p udp -m udp --sport {{.DNSProxyPort}} -j ACCEPT
{{end}}
{{.MangleTable}} {{.MangleProxyAppChain}} -p tcp -m set --match-set {{.SrvIPSet}} src -j ACCEPT
{{.MangleTable}} {{.MangleProxyAppChain}} -p tcp -m set --match-set {{.DestIPSet}} dst,dst -m mark ! --mark {{.ProxyMark}} -j ACCEPT

{{.MangleTable}} {{.MangleProxyNetChain}} -p tcp -m set --match-set {{.DestIPSet}} src,src -j ACCEPT
{{.MangleTable}} {{.MangleProxyNetChain}} -p tcp -m set --match-set {{.SrvIPSet}} src -m addrtype --src-type LOCAL -j ACCEPT
{{.MangleTable}} {{.MangleProxyNetChain}} -p tcp -m tcp --dport {{.ProxyPort}} -j ACCEPT
{{if enableDNSProxy}}
{{.MangleTable}} {{.MangleProxyNetChain}} -p udp -m udp --dport {{.DNSProxyPort}} -j ACCEPT
{{end}}

{{if isCgroupSet}}
{{.NatTable}} {{.NatProxyAppChain}} -p tcp -m set --match-set {{.DestIPSet}} dst,dst -m mark ! --mark {{.ProxyMark}} -m multiport --source-ports {{.TCPPorts}} -j REDIRECT --to-ports {{.ProxyPort}}
{{else}}
{{.NatTable}} {{.NatProxyAppChain}} -p tcp -m set --match-set {{.DestIPSet}} dst,dst -m mark ! --mark {{.ProxyMark}} -j REDIRECT --to-ports {{.ProxyPort}}
{{end}}

{{if enableDNSProxy}}
{{.NatTable}} {{.NatProxyAppChain}} -p udp --dport 53 -m mark ! --mark {{.ProxyMark}} -j REDIRECT --to-ports {{.DNSProxyPort}}
{{end}}

{{.NatTable}} {{.NatProxyNetChain}} -p tcp -m set --match-set {{.SrvIPSet}} dst -m mark ! --mark {{.ProxyMark}} -j REDIRECT --to-ports {{.ProxyPort}}`
