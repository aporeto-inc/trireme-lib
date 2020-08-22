// +build linux !windows

package iptablesctrl

var triremChains = `
{{if isLocalServer}}-t {{.MangleTable}} -N {{.HostInput}}
-t {{.MangleTable}} -N {{.HostOutput}}
-t {{.MangleTable}} -N {{.NetworkSvcInput}}
-t {{.MangleTable}} -N {{.NetworkSvcOutput}}
-t {{.MangleTable}} -N {{.TriremeInput}}
-t {{.MangleTable}} -N {{.TriremeOutput}}
-t {{.MangleTable}} -N {{.UIDInput}}
-t {{.MangleTable}} -N {{.UIDOutput}}
{{end}}-t {{.MangleTable}} -N {{.MangleProxyAppChain}}
-t {{.MangleTable}} -N {{.MainAppChain}}
-t {{.MangleTable}} -N {{.MainNetChain}}
-t {{.MangleTable}} -N {{.MangleProxyNetChain}}
-t {{.NatTable}} -N {{.NatProxyAppChain}}
-t {{.NatTable}} -N {{.NatProxyNetChain}}
`
var globalRules = `
{{$length := len .NetSynQueues}}
{{.MangleTable}} INPUT -m set ! --match-set {{.ExclusionsSet}} src -j {{.MainNetChain}}
{{.MangleTable}} {{.MainNetChain}} -j {{ .MangleProxyNetChain }}
{{if .IsLegacyKernel}}
{{.MangleTable}} {{.MainNetChain}} -p udp -m set --match-set {{.TargetUDPNetSet}} src -m string --string {{.UDPSignature}} --algo bm --to 65535 -j NFQUEUE --queue-bypass --queue-balance {{.QueueBalanceNetSynAck}}	
{{.MangleTable}} {{.MainNetChain}} -m set --match-set {{.TargetTCPNetSet}} src -p tcp --tcp-flags ALL ACK -m tcp --tcp-option 34 -j NFQUEUE --queue-balance {{.QueueBalanceNetAck}}
{{else}}
{{$.MangleTable}} {{$.MainNetChain}} -p udp -m set --match-set {{$.TargetUDPNetSet}} src -j HMARK --hmark-tuple src,sport,dst,dport --hmark-offset 0x1 --hmark-rnd {{$.HMarkRandomSeed}} --hmark-mod {{$length}}
{{range $index,$queuenum := .NetSynAckQueues}}
{{$.MangleTable}} {{$.MainNetChain}} -p udp -m set --match-set {{$.TargetUDPNetSet}} src -m string --string {{$.UDPSignature}} --algo bm --to 65535 -m mark --mark {{Increment $index}}/{{$.QueueMask}} -j NFQUEUE --queue-bypass --queue-num {{$queuenum}}
{{end}}
{{$.MangleTable}} {{$.MainNetChain}} -p tcp -m set --match-set {{$.TargetTCPNetSet}} src -j HMARK --hmark-tuple src,sport,dst,dport --hmark-offset 0x1 --hmark-rnd {{$.HMarkRandomSeed}} --hmark-mod {{$length}}
{{range $index,$queuenum := .NetAckQueues}}
{{$.MangleTable}} {{$.MainNetChain}} -m set --match-set {{$.TargetTCPNetSet}} src -p tcp --tcp-flags ALL ACK -m tcp --tcp-option 34 -m mark --mark {{Increment $index}}/{{$.QueueMask}} -j NFQUEUE --queue-num {{$queuenum}}
{{end}}
{{end}}

{{if isBPFEnabled}}
{{else}}
{{.MangleTable}} {{.MainNetChain}} -m connmark --mark {{.DefaultExternalConnmark}} -j ACCEPT
{{.MangleTable}} {{.MainNetChain}} -m connmark --mark {{.DefaultConnmark}} -p tcp ! --tcp-flags SYN,ACK SYN,ACK -j ACCEPT
{{end}}

{{if isLocalServer}}
{{.MangleTable}} {{.MainNetChain}} -j {{.UIDInput}}
{{end}}

{{if .IsLegacyKernel}}
{{.MangleTable}} {{.MainNetChain}} -m set --match-set {{.TargetTCPNetSet}} src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-balance {{.QueueBalanceNetSynAck}} --queue-bypass	
{{.MangleTable}} {{.MainNetChain}} -p tcp -m set --match-set {{.TargetTCPNetSet}} src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -j NFQUEUE --queue-balance {{.QueueBalanceNetSyn}} --queue-bypass
{{else}}
{{range $index,$queuenum := .NetSynAckQueues}}
{{$.MangleTable}} {{$.MainNetChain}} -m set --match-set {{$.TargetTCPNetSet}} src -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark {{Increment $index}}/{{$.QueueMask}} -j NFQUEUE --queue-num {{$queuenum}} --queue-bypass
{{end}}

{{range $index,$queuenum := .NetSynQueues}} 
{{$.MangleTable}} {{$.MainNetChain}} -p tcp -m set --match-set {{$.TargetTCPNetSet}} src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -m mark --mark {{Increment $index}}/{{$.QueueMask}} -j NFQUEUE --queue-num {{$queuenum}} --queue-bypass
{{end}}
{{end}}


{{if isLocalServer}}
{{.MangleTable}} {{.MainNetChain}} -j {{.TriremeInput}}
{{.MangleTable}} {{.MainNetChain}} -j {{.NetworkSvcInput}}
{{.MangleTable}} {{.MainNetChain}} -j {{.HostInput}}
{{end}}

{{.MangleTable}} OUTPUT -m set ! --match-set {{.ExclusionsSet}} dst -j {{.MainAppChain}}
{{.MangleTable}} {{.MainAppChain}} -j {{.MangleProxyAppChain}}
{{.MangleTable}} {{.MainAppChain}} -m mark --mark {{.RawSocketMark}} -j ACCEPT

{{if isBPFEnabled}}
{{else}}
{{.MangleTable}} {{.MainAppChain}} -m connmark --mark {{.DefaultExternalConnmark}} -j ACCEPT
{{.MangleTable}} {{.MainAppChain}} -m connmark --mark {{.DefaultConnmark}} -p tcp ! --tcp-flags SYN,ACK SYN,ACK  -j ACCEPT
{{end}}

{{if .IsLegacyKernel}}

{{else}}
{{$length := len .AppSynQueues}}
{{$.MangleTable}} {{$.MainAppChain}} -p tcp -m set --match-set {{$.TargetTCPNetSet}} dst -j HMARK --hmark-tuple dst,dport,src,sport --hmark-offset 0x1 --hmark-rnd {{$.HMarkRandomSeed}} --hmark-mod {{$length}}
{{$.MangleTable}} {{$.MainAppChain}} -p udp -m set --match-set {{$.TargetUDPNetSet}} dst -j HMARK --hmark-tuple dst,dport,src,sport --hmark-offset 0x1 --hmark-rnd {{$.HMarkRandomSeed}} --hmark-mod {{$length}}
{{end}}

{{if isLocalServer}}
{{.MangleTable}} {{.MainAppChain}} -j {{.UIDOutput}}
{{end}}

{{.MangleTable}} {{.MainAppChain}} -p tcp -m set --match-set {{.TargetTCPNetSet}} dst -m tcp --tcp-flags SYN,ACK SYN,ACK -j MARK --set-mark {{.InitialMarkVal}}/{{.MarkMask}}

{{if .IsLegacyKernel}}
{{.MangleTable}} {{.MainAppChain}} -p tcp -m set --match-set {{.TargetTCPNetSet}} dst -m tcp --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-balance {{.QueueBalanceAppSynAck}} --queue-bypass
{{else}}
{{range $index,$queuenum := .AppSynAckQueues}}
{{$.MangleTable}} {{$.MainAppChain}} -p tcp -m set --match-set {{$.TargetTCPNetSet}} dst -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark {{Increment $index}}/{{$.QueueMask}} -j NFQUEUE --queue-num {{$queuenum}} --queue-bypass
 {{end}}
{{end}}

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
{{.MangleTable}} {{.NetSection}} -p udp -m udp -m state --state ESTABLISHED -j ACCEPT
{{/* Traffic to systemd resolver/dnsmasq gets accepted */}}
{{.MangleTable}} {{.NetSection}} -p udp -m udp --dport 53 -j ACCEPT
{{.MangleTable}} {{.NetSection}} -m comment --comment PU-Chain -j {{.NetChain}}
{{end}}

{{if isUDPPorts}}
{{.MangleTable}} {{.NetSection}} -p udp -m multiport --destination-ports {{.UDPPorts}} -m comment --comment PU-Chain -j {{.NetChain}}
{{end}}

{{.MangleTable}} {{.AppSection}} -m cgroup --cgroup {{.Mark}} -m comment --comment PU-Chain -j MARK --set-mark {{.PacketMark}}/{{.MarkMask}}
{{.MangleTable}} {{.AppSection}} -m mark --mark {{.PacketMark}}/{{.MarkMask}} -m comment --comment PU-Chain -j {{.AppChain}}

`

// containerChainTemplate will hook traffic towards the container specific chains.
var containerChainTemplate = `
{{.MangleTable}} {{.AppSection}} -m comment --comment Container-specific-chain -j {{.AppChain}}
{{.MangleTable}} {{.NetSection}} -m comment --comment Container-specific-chain -j {{.NetChain}}`

var uidChainTemplate = `
{{.MangleTable}} {{.UIDOutput}} -m owner --uid-owner {{.UID}} -j MARK --set-mark {{.PacketMark}}/{{.MarkMask}}
{{.MangleTable}} {{.UIDOutput}} -m mark --mark {{.PacketMark}}/{{.MarkMask}} -m comment --comment Server-specific-chain -j {{.AppChain}}
{{.MangleTable}} {{.UIDInput}} -m set --match-set {{.PortSet}} dst -j MARK --set-mark {{.PacketMark}}/{{.MarkMask}}
{{.MangleTable}} {{.UIDInput}} -p tcp -m mark --mark {{.PacketMark}}/{{.MarkMask}} -m comment --comment Container-specific-chain -j {{.NetChain}}
`

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
var packetCaptureTemplate = `
{{if needICMP}}
{{.MangleTable}} {{.AppChain}} -p icmpv6 -j ACCEPT
{{end}}

{{if isBPFEnabled}}
{{.MangleTable}} {{.AppChain}} -m set --match-set {{.TargetTCPNetSet}} dst -p tcp --tcp-flags SYN NONE -m bpf --object-pinned {{.BPFPath}} -m state --state ESTABLISHED -j ACCEPT
{{.MangleTable}} {{.NetChain}} -m set --match-set {{.TargetTCPNetSet}} src -p tcp --tcp-flags SYN NONE -m bpf --object-pinned {{.BPFPath}} -m state --state ESTABLISHED -j ACCEPT
{{end}}

{{if .IsLegacyKernel}}
{{.MangleTable}} {{.AppChain}} -p tcp -m tcp --tcp-flags SYN,ACK SYN -j NFQUEUE --queue-balance {{.QueueBalanceAppSyn}}	
{{.MangleTable}} {{.AppChain}} -p tcp -m tcp --tcp-flags SYN,ACK ACK -j NFQUEUE --queue-balance {{.QueueBalanceAppAck}}
{{if isUIDProcess}}
{{.MangleTable}} {{.AppChain}} -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-balance {{.QueueBalanceAppSynAck}}
{{end}}
{{else}}
   {{range $index,$queuenum := .AppSynQueues}}
     {{$.MangleTable}} {{$.AppChain}} -p tcp -m tcp --tcp-flags SYN,ACK SYN -m mark --mark {{Increment $index}}/{{$.QueueMask}} -j NFQUEUE --queue-num {{$queuenum}}
   {{end}}
   {{range $index,$queuenum := .AppAckQueues}}
     {{$.MangleTable}} {{$.AppChain}} -p tcp -m tcp --tcp-flags SYN,ACK ACK -m mark --mark {{Increment $index}}/{{$.QueueMask}} -j NFQUEUE --queue-num {{$queuenum}}
   {{end}}
   {{if isUIDProcess}}
     {{range $index,$queuenum := .AppSynAckQueues}}
       {{$.MangleTable}} {{$.AppChain}} -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark {{Increment $index}}/{{$.QueueMask}} -j NFQUEUE --queue-num {{$queuenum}}
     {{end}}
   {{end}}
   {{range $index,$queuenum := .AppSynQueues}}
     {{$.MangleTable}} {{$.AppChain}} -p udp -m set --match-set {{$.TargetUDPNetSet}} dst -m mark --mark {{Increment $index}}/{{$.QueueMask}} -j NFQUEUE --queue-num {{$queuenum}}
   {{end}}
{{end}}

{{.MangleTable}} {{.AppChain}} -p udp -m set --match-set {{.TargetUDPNetSet}} dst -m state --state ESTABLISHED -m comment --comment UDP-Established-Connections -j ACCEPT
{{.MangleTable}} {{.AppChain}} -p tcp -m state --state ESTABLISHED -m comment --comment TCP-Established-Connections -j ACCEPT

{{range appAnyRules}}
{{joinRule .}}
{{end}}
{{.MangleTable}} {{.AppChain}} -d {{.DefaultIP}} -m state --state NEW -j NFLOG  --nflog-group 10 --nflog-prefix {{.NFLOGPrefix}}
{{.MangleTable}} {{.AppChain}} -d {{.DefaultIP}} -m state ! --state NEW -j NFLOG --nflog-group 10 --nflog-prefix {{.DefaultNFLOGDropPrefix}}
{{.MangleTable}} {{.AppChain}} -d {{.DefaultIP}} -j DROP

{{if needICMP}}
{{.MangleTable}} {{.NetChain}} -p icmpv6 -j ACCEPT
{{end}}

{{if .IsLegacyKernel}}
   {{.MangleTable}} {{.NetChain}} -p tcp -m set --match-set {{.TargetTCPNetSet}} src -m tcp --tcp-flags SYN,ACK SYN -j NFQUEUE --queue-balance {{.QueueBalanceNetSyn}}
   {{.MangleTable}} {{.NetChain}} -p tcp -m set --match-set {{.TargetTCPNetSet}} src -m tcp --tcp-flags SYN,ACK ACK -j NFQUEUE --queue-balance {{.QueueBalanceNetAck}}
   {{if isUIDProcess}}
     {{.MangleTable}} {{.NetChain}} -p tcp -m set --match-set {{.TargetTCPNetSet}} src -m tcp --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-balance {{.QueueBalanceNetSynAck}}
   {{end}}
   {{.MangleTable}} {{.NetChain}} -p udp -m set --match-set {{.TargetUDPNetSet}} src --match limit --limit 1000/s -j NFQUEUE --queue-balance {{.QueueBalanceNetSyn}}
{{else}}
  {{range $index,$queuenum := .NetSynQueues}} 
    {{$.MangleTable}} {{$.NetChain}} -p tcp -m set --match-set {{$.TargetTCPNetSet}} src -m tcp --tcp-flags SYN,ACK SYN -m mark --mark {{Increment $index}}/{{$.QueueMask}} -j NFQUEUE --queue-num {{$queuenum}}
  {{end}}
  {{range $index,$queuenum := .NetAckQueues}}
    {{$.MangleTable}} {{$.NetChain}} -p tcp -m set --match-set {{$.TargetTCPNetSet}} src -m tcp --tcp-flags SYN,ACK ACK -m mark --mark {{Increment $index}}/{{$.QueueMask}} -j NFQUEUE --queue-num {{$queuenum}}
  {{end}}

  {{if isUIDProcess}}
    {{range $index,$queuenum := .NetSynAckQueues}}
      {{$.MangleTable}} {{$.NetChain}} -p tcp -m set --match-set {{$.TargetTCPNetSet}} src -m tcp --tcp-flags SYN,ACK SYN,ACK -m mark --mark {{Increment $index}}/{{$.QueueMask}} -j NFQUEUE --queue-num {{$queuenum}}
    {{end}}
  {{end}}
  {{range $index,$queuenum := .NetSynQueues}}
    {{$.MangleTable}} {{$.NetChain}} -p udp -m set --match-set {{$.TargetUDPNetSet}} src --match limit --limit 1000/s -m mark --mark {{Increment $index}}/{{$.QueueMask}} -j NFQUEUE --queue-num {{$queuenum}}
  {{end}}
{{end}}

{{.MangleTable}} {{.NetChain}} -p tcp -m state --state ESTABLISHED -m comment --comment TCP-Established-Connections -j ACCEPT
{{range netAnyRules}}
{{joinRule .}}
{{end}}

{{.MangleTable}} {{.NetChain}} -s {{.DefaultIP}} -m state --state NEW -j NFLOG --nflog-group 11 --nflog-prefix {{.NFLOGPrefix}}
{{.MangleTable}} {{.NetChain}} -s {{.DefaultIP}} -m state ! --state NEW -j NFLOG --nflog-group 11 --nflog-prefix {{.DefaultNFLOGDropPrefix}}
{{.MangleTable}} {{.NetChain}} -s {{.DefaultIP}} -j DROP
`

var proxyChainTemplate = `
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
{{.NatTable}} {{.NatProxyAppChain}} -p tcp -m set --match-set {{.DestIPSet}} dst,dst -m mark ! --mark {{.ProxyMark}} -m cgroup --cgroup {{.CgroupMark}} -j REDIRECT --to-ports {{.ProxyPort}}
{{if enableDNSProxy}}
{{.NatTable}} {{.NatProxyAppChain}} -d {{.DNSServerIP}} -p udp --dport 53 -m mark ! --mark {{.ProxyMark}} -m cgroup --cgroup {{.CgroupMark}} -j CONNMARK --save-mark
{{.NatTable}} {{.NatProxyAppChain}} -d {{.DNSServerIP}} -p udp --dport 53 -m mark ! --mark {{.ProxyMark}} -m cgroup --cgroup {{.CgroupMark}} -j REDIRECT --to-ports {{.DNSProxyPort}}
{{end}}
{{else}}
{{.NatTable}} {{.NatProxyAppChain}} -p tcp -m set --match-set {{.DestIPSet}} dst,dst -m mark ! --mark {{.ProxyMark}} -j REDIRECT --to-ports {{.ProxyPort}}
{{if enableDNSProxy}}
{{.NatTable}} {{.NatProxyAppChain}} -d {{.DNSServerIP}} -p udp --dport 53 -m mark ! --mark {{.ProxyMark}} -j REDIRECT --to-ports {{.DNSProxyPort}}
{{end}}
{{end}}
{{.NatTable}} {{.NatProxyNetChain}} -p tcp -m set --match-set {{.SrvIPSet}} dst -m mark ! --mark {{.ProxyMark}} -j REDIRECT --to-ports {{.ProxyPort}}`

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
