package cri

import "time"

// maxMsgSize use 16MB as the default message size limit.
// grpc library default is 4MB
// NOTE: this should be the exact same constant as used in the kubelet
//       this used to be here: https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/cri/remote/utils.go#L29
const maxMsgSize = 1024 * 1024 * 16 // nolint: varcheck

var (
	// connectTimeout is used for establishing the initial grpc dial context
	connectTimeout = time.Second * 30

	// callTimeout is used for every single call to CRI
	callTimeout = time.Second * 5 // nolint: varcheck
)
