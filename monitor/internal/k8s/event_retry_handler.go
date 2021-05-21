package k8smonitor

import (
	"context"
	"time"

	"go.aporeto.io/enforcerd/internal/extractors/containermetadata"
	"go.uber.org/zap"
)

var (
	retryWaittimeUnit = time.Second
	retryTimeout      = time.Second * 30
)

type startEventRetryFunc func(containermetadata.CommonKubernetesContainerMetadata, uint)

func newStartEventRetryFunc(mainCtx context.Context, extractor containermetadata.CommonContainerMetadataExtractor, startEvent startEventFunc) startEventRetryFunc {
	return func(kmd containermetadata.CommonKubernetesContainerMetadata, retry uint) {
		// we only care about pod sandboxes for restarts
		// make sure that we stick to that
		if kmd.Kind() != containermetadata.PodSandbox {
			zap.L().Debug(
				"K8sMonitor: startEventRetry: this is not a pod sandbox. Aborting retry...",
				zap.Uint("retry", retry),
				zap.String("kind", kmd.Kind().String()),
				zap.String("id", kmd.ID()),
			)
			return
		}

		// wait before we retry
		waitTime := calculateWaitTime(retry)
		zap.L().Debug(
			"K8sMonitor: startEventRetry: waiting before retry...",
			zap.Uint("retry", retry),
			zap.Duration("waitTime", waitTime),
			zap.String("id", kmd.ID()),
		)
		select {
		case <-mainCtx.Done():
			// no point in continuing if the main context is done
			return
		case <-time.After(waitTime):
		}

		// check if the sandbox still exists, otherwise we can abort the retries
		if !extractor.Has(containermetadata.NewRuncArguments(containermetadata.StartAction, kmd.ID())) {
			zap.L().Debug(
				"K8sMonitor: startEventRetry: container for start event does not exist any longer. Aborting...",
				zap.Uint("retry", retry),
				zap.String("id", kmd.ID()),
			)
			return
		}

		// now create a new context and retry
		// the recursion occurs within the startEvent
		ctx, cancel := context.WithTimeout(mainCtx, retryTimeout)
		defer cancel()
		if err := startEvent(ctx, kmd, retry); err != nil {
			zap.L().Error(
				"K8sMonitor: startEventRetry: failed to process start event on retry",
				zap.Uint("retry", retry),
				zap.Error(err),
				zap.String("id", kmd.ID()),
				zap.String("podUID", kmd.PodUID()),
				zap.String("podName", kmd.PodName()),
				zap.String("podNamespace", kmd.PodNamespace()),
			)
		}
	}
}

// calculateWaitTime calculates a fibonacci style backoff wait time based on the number of retry
// It uses `retryWaittimeUnit` as the base unit for the wait time
func calculateWaitTime(retry uint) time.Duration {
	var n uint
	switch retry {
	case 0:
		n = 0
	case 1:
		n = 1
	case 2:
		n = 1
	case 3:
		n = 2
	case 4:
		n = 3
	case 5:
		n = 5
	case 6:
		n = 8
	case 7:
		n = 13
	case 8:
		n = 21
	case 9:
		n = 34
	default:
		n = 55
	}
	return retryWaittimeUnit * time.Duration(n)
}
