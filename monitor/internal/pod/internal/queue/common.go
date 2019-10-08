package queue

import (
	"context"
	"fmt"

	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/monitor/extractors"
	"go.aporeto.io/trireme-lib/policy"
	"go.uber.org/zap"
	"k8s.io/client-go/tools/record"
)

// processEvent can be used by any queue implementation to actually process an event with the policy engine
func processEvent(ctx context.Context, pe policy.Resolver, netclsProgrammer extractors.PodNetclsProgrammer, r record.EventRecorder, ev *PolicyEngineEvent) error {
	if ev == nil {
		zap.L().Error("PolicyEngineQueue: no event passed for processing")
		return fmt.Errorf("missing event")
	}
	if r == nil {
		zap.L().Error("PolicyEngineQueue: no policy resolver passed for processing")
		return fmt.Errorf("missing policy resolver")
	}
	switch ev.Event {
	case common.EventCreate:
		if err := pe.HandlePUEvent(ctx, string(ev.ID), common.EventCreate, ev.Runtime); err != nil {
			zap.L().Error("PolicyEngineQueue: failed to process create event", zap.String("id", string(ev.ID)), zap.String("event", string(ev.Event)), zap.Error(err))
			if r != nil && ev.Pod != nil {
				r.Eventf(ev.Pod, "Warning", "PUCreate", "PU '%s' failed to get created: %s", string(ev.ID), err.Error())
			}
			return err
		}
		zap.L().Debug("PolicyEngineQueue: successfully processed create event", zap.String("id", string(ev.ID)), zap.String("event", string(ev.Event)))
		if r != nil && ev.Pod != nil {
			r.Eventf(ev.Pod, "Normal", "PUCreate", "PU '%s' has been successfully created", string(ev.ID))
		}
		return nil
	case common.EventUpdate:
		if err := pe.HandlePUEvent(ctx, string(ev.ID), common.EventUpdate, ev.Runtime); err != nil {
			zap.L().Error("PolicyEngineQueue: failed to process update event", zap.String("id", string(ev.ID)), zap.String("event", string(ev.Event)), zap.Error(err))
			if r != nil && ev.Pod != nil {
				r.Eventf(ev.Pod, "Warning", "PUUpdate", "failed to handle update event for PU '%s': %s", string(ev.ID), err.Error())
			}
			return err
		}
		zap.L().Debug("PolicyEngineQueue: successfully processed update event", zap.String("id", string(ev.ID)), zap.String("event", string(ev.Event)))
		if r != nil && ev.Pod != nil {
			r.Eventf(ev.Pod, "Normal", "PUUpdate", "PU '%s' updated successfully", string(ev.ID))
		}
		return nil
	case common.EventStop:
		if err := pe.HandlePUEvent(ctx, string(ev.ID), common.EventStop, ev.Runtime); err != nil {
			zap.L().Error("PolicyEngineQueue: failed to process stop event", zap.String("id", string(ev.ID)), zap.String("event", string(ev.Event)), zap.Error(err))
			if r != nil && ev.Pod != nil {
				r.Eventf(ev.Pod, "Warning", "PUStop", "PU '%s' failed to stop: %s", string(ev.ID), err.Error())
			}
			return err
		}
		zap.L().Debug("PolicyEngineQueue: successfully processed stop event", zap.String("id", string(ev.ID)), zap.String("event", string(ev.Event)))
		if r != nil && ev.Pod != nil {
			r.Eventf(ev.Pod, "Normal", "PUStop", "PU '%s' has been successfully stopped", string(ev.ID))
		}
		return nil
	case common.EventStart:
		if err := pe.HandlePUEvent(ctx, string(ev.ID), common.EventStart, ev.Runtime); err != nil {
			zap.L().Error("PolicyEngineQueue: failed to process start event", zap.String("id", string(ev.ID)), zap.String("event", string(ev.Event)), zap.Error(err))
			if r != nil && ev.Pod != nil {
				r.Eventf(ev.Pod, "Warning", "PUStart", "PU '%s' failed to start: %s", string(ev.ID), err.Error())
			}
			return err
		}
		zap.L().Debug("PolicyEngineQueue: successfully processed start event", zap.String("id", string(ev.ID)), zap.String("event", string(ev.Event)))
		if r != nil && ev.Pod != nil {
			r.Eventf(ev.Pod, "Normal", "PUStart", "PU '%s' started successfully", string(ev.ID))
		}
		return nil
	case common.EventDestroy:
		if err := pe.HandlePUEvent(ctx, string(ev.ID), common.EventDestroy, ev.Runtime); err != nil {
			zap.L().Error("PolicyEngineQueue: failed to process destroy event", zap.String("id", string(ev.ID)), zap.String("event", string(ev.Event)), zap.Error(err))
			return err
		}
		zap.L().Debug("PolicyEngineQueue: successfully processed destroy event", zap.String("id", string(ev.ID)), zap.String("event", string(ev.Event)))
		return nil
	case common.Event("netcls"):
		if netclsProgrammer == nil {
			zap.L().Error("PolicyEngineQueue: no netclsProgrammer passed for processing")
			return fmt.Errorf("missing netclsProgrammer")
		}
		if err := netclsProgrammer(ctx, ev.Pod, ev.Runtime); err != nil {
			zap.L().Error("PolicyEngineQueue: failed to process netcls event", zap.String("id", string(ev.ID)), zap.String("event", string(ev.Event)), zap.Error(err))
			if r != nil && ev.Pod != nil {
				r.Eventf(ev.Pod, "Warning", "PUStart", "Host Network PU '%s' failed to program its net_cls cgroups: %s", string(ev.ID), err.Error())
			}
			return err
		}
		zap.L().Debug("PolicyEngineQueue: successfully processed netcls event", zap.String("id", string(ev.ID)), zap.String("event", string(ev.Event)))
		if r != nil && ev.Pod != nil {
			r.Eventf(ev.Pod, "Normal", "PUStart", "Host Network PU '%s' has successfully programmed its net_cls cgroups", string(ev.ID))
		}
		return nil
	default:
		zap.L().Error("PolicyEngineQueue: unknown event", zap.String("id", string(ev.ID)), zap.String("event", string(ev.Event)))
		if r != nil && ev.Pod != nil {
			r.Eventf(ev.Pod, "Warning", "PUUnknownEvent", "received an unknown policy engine event: '%s'", string(ev.Event))
		}
		return fmt.Errorf("unknown event: %s", string(ev.Event))
	}
}
