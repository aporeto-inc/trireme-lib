// +build !linux, !windows

package nfqdatapath

import "context"

// Go libraries

// startNetworkInterceptor will the process that processes  packets from the network
// Still has one more copy than needed. Can be improved.
func (d *Datapath) startNetworkInterceptor(ctx context.Context) {}

// startApplicationInterceptor will create a interceptor that processes
// packets originated from a local application
func (d *Datapath) startApplicationInterceptor(ctx context.Context) {}

func (d *Datapath) cleanupPlatform() {}
