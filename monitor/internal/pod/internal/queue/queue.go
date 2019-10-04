package queue

import (
	"context"
	"time"

	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/monitor/config"
	"go.aporeto.io/trireme-lib/monitor/extractors"
	"go.aporeto.io/trireme-lib/policy"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

// PolicyEngineEvent holds all the event information for an event that we send to the policy engine
type PolicyEngineEvent struct {
	ID      types.UID
	Event   common.Event
	Runtime policy.RuntimeReader
	Pod     *corev1.Pod
}

// PolicyEngineQueue queues events to the policy engine and processes them in serial *per pod*
type PolicyEngineQueue struct {
	queue            chan *PolicyEngineEvent
	pc               *config.ProcessorConfig
	netclsProgrammer extractors.PodNetclsProgrammer
}

// NewPolicyEngineQueue creates a new policy engine queue
func NewPolicyEngineQueue(pc *config.ProcessorConfig, queueSize int, netclsProgrammer extractors.PodNetclsProgrammer) *PolicyEngineQueue {
	return &PolicyEngineQueue{
		pc:               pc,
		netclsProgrammer: netclsProgrammer,
		queue:            make(chan *PolicyEngineEvent, queueSize),
	}
}

// Queue returns the channel that clients can use to send events to the policy engine
func (q *PolicyEngineQueue) Queue() chan<- *PolicyEngineEvent {
	return q.queue
}

// Start starts the queue and will block until z is closed
func (q *PolicyEngineQueue) Start(z <-chan struct{}) error {
	go q.loop(z)
	<-z
	return nil
}

func (q *PolicyEngineQueue) loop(z <-chan struct{}) {
	m := make(map[types.UID]*podevents)
loop:
	for {
		select {
		case <-z:
			for _, p := range m {
				close(p.stopCh)
			}
			break loop
		case ev := <-q.queue:
			p, ok := m[ev.ID]
			if !ok {
				m[ev.ID] = newPodevents(ev, q.pc, q.netclsProgrammer)
				break
			}
			p.rxEvCh <- ev
		}
	}
}

type podevents struct {
	id types.UID

	isCreated          bool
	isStarted          bool
	isNetclsProgrammed bool

	rxEvCh        chan *PolicyEngineEvent
	stopCh        chan struct{}
	processCh     chan struct{}
	postProcessCh chan postProcessEvent

	create  policy.RuntimeReader
	update  policy.RuntimeReader
	start   policy.RuntimeReader
	stop    policy.RuntimeReader
	destroy policy.RuntimeReader
	netcls  policy.RuntimeReader

	netclsPod *corev1.Pod

	pc               *config.ProcessorConfig
	netclsProgrammer extractors.PodNetclsProgrammer
}

type postProcessEvent struct {
	err     error
	ev      common.Event
	runtime policy.RuntimeReader
	pod     *corev1.Pod
}

func newPodevents(ev *PolicyEngineEvent, pc *config.ProcessorConfig, netclsProgrammer extractors.PodNetclsProgrammer) *podevents {
	ret := &podevents{
		id:               ev.ID,
		rxEvCh:           make(chan *PolicyEngineEvent),
		stopCh:           make(chan struct{}),
		processCh:        make(chan struct{}, 1),
		postProcessCh:    make(chan postProcessEvent),
		pc:               pc,
		netclsProgrammer: netclsProgrammer,
	}
	go ret.loop()
	ret.rxEvCh <- ev
	return ret
}

func (p *podevents) loop() {
	var processing, needsProcesssing bool
loop:
	for {
		select {
		case <-p.stopCh:
			if processing {
				time.Sleep(time.Second)
				break
			}
			break loop
		case ev := <-p.rxEvCh:
			p.rxEvent(ev)
			select {
			case p.processCh <- struct{}{}:
			default:
			}
		case <-p.processCh:
			if processing {
				needsProcesssing = true
				break
			}
			processing = true
			p.processEvent()
		case ev := <-p.postProcessCh:
			p.postProcessEvent(ev)
			processing = false
			if needsProcesssing {
				select {
				case p.processCh <- struct{}{}:
				default:
				}
				needsProcesssing = false
			}
		}
	}
	close(p.rxEvCh)
	close(p.processCh)
	close(p.postProcessCh)
}

func (p *podevents) rxEvent(ev *PolicyEngineEvent) {
	switch ev.Event {
	case common.EventCreate:
		if !p.isCreated || p.stop != nil || p.destroy != nil {
			p.create = ev.Runtime
		}
	case common.EventUpdate:
		p.update = ev.Runtime
	case common.EventStart:
		if !p.isStarted || p.stop != nil || p.destroy != nil {
			p.start = ev.Runtime
		}
	case common.EventStop:
		p.start = nil
		p.stop = ev.Runtime
	case common.EventDestroy:
		p.create = nil
		p.update = nil
		p.start = nil
		p.stop = nil
		p.netcls = nil
		p.netclsPod = nil
		p.destroy = ev.Runtime
	case common.Event("netcls"):
		if !p.isNetclsProgrammed {
			p.netcls = ev.Runtime
			p.netclsPod = ev.Pod
		}
	}
}

func (p *podevents) processEvent() {
	if p.destroy != nil {
		runtime := p.destroy
		p.destroy = nil
		go func() {
			if err := p.pc.Policy.HandlePUEvent(context.Background(), string(p.id), common.EventDestroy, runtime); err != nil {
				p.postProcessCh <- postProcessEvent{
					err:     err,
					ev:      common.EventDestroy,
					runtime: runtime,
				}
				return
			}
			p.postProcessCh <- postProcessEvent{ev: common.EventDestroy}
		}()
		return
	}

	if p.stop != nil {
		runtime := p.stop
		p.stop = nil
		go func() {
			if err := p.pc.Policy.HandlePUEvent(context.Background(), string(p.id), common.EventStop, runtime); err != nil {
				p.postProcessCh <- postProcessEvent{
					err:     err,
					ev:      common.EventStop,
					runtime: runtime,
				}
				return
			}
			p.postProcessCh <- postProcessEvent{ev: common.EventStop}
		}()
		return
	}

	if p.create != nil {
		runtime := p.create
		p.create = nil
		go func() {
			if err := p.pc.Policy.HandlePUEvent(context.Background(), string(p.id), common.EventCreate, runtime); err != nil {
				p.postProcessCh <- postProcessEvent{
					err:     err,
					ev:      common.EventCreate,
					runtime: runtime,
				}
				return
			}
			p.postProcessCh <- postProcessEvent{ev: common.EventCreate}
		}()
		return
	}

	if p.start != nil {
		runtime := p.start
		p.start = nil
		go func() {
			if err := p.pc.Policy.HandlePUEvent(context.Background(), string(p.id), common.EventStart, runtime); err != nil {
				p.postProcessCh <- postProcessEvent{
					err:     err,
					ev:      common.EventStart,
					runtime: runtime,
				}
				return
			}
			p.postProcessCh <- postProcessEvent{ev: common.EventStart}
		}()
		return
	}

	if p.netcls != nil {
		runtime := p.netcls
		pod := p.netclsPod
		p.netcls = nil
		p.netclsPod = nil
		go func() {
			if err := p.netclsProgrammer(context.Background(), pod, runtime); err != nil {
				p.postProcessCh <- postProcessEvent{
					err:     err,
					ev:      common.Event("netcls"),
					runtime: runtime,
					pod:     pod,
				}
				return
			}
			p.postProcessCh <- postProcessEvent{ev: common.Event("netcls")}
		}()
		return
	}

	if p.update != nil {
		runtime := p.update
		p.update = nil
		go func() {
			if err := p.pc.Policy.HandlePUEvent(context.Background(), string(p.id), common.EventUpdate, runtime); err != nil {
				p.postProcessCh <- postProcessEvent{
					err:     err,
					ev:      common.EventUpdate,
					runtime: runtime,
				}
				return
			}
			p.postProcessCh <- postProcessEvent{ev: common.EventUpdate}
		}()
		return
	}
}

func (p *podevents) postProcessEvent(ev postProcessEvent) {
	err := ev.err
	switch ev.ev {
	case common.EventDestroy:
		// nothing to do here if we failed, there is nothing that we can do
		if err == nil {
			p.isCreated = false
			p.isStarted = false
			p.isNetclsProgrammed = false
			p.destroy = nil
		}
	case common.EventStop:
		// nothing to do here if it failed
		if err == nil {
			p.isStarted = false
			p.isNetclsProgrammed = false
			p.stop = nil
		}
	case common.EventCreate:
		// again, nothing here that we can do if it fails
		if err == nil {
			p.isCreated = true
			p.create = nil
		}
	case common.EventStart:
		// we will try to retry the start
		if err == nil {
			p.isCreated = true
			p.isStarted = true
			p.start = nil
		} else {
			if p.start == nil {
				p.start = ev.runtime
			}
		}
	case common.Event("netcls"):
		if err == nil {
			p.isNetclsProgrammed = true
			p.netcls = nil
			p.netclsPod = nil
		} else {
			if p.netcls == nil && p.netclsPod == nil {
				p.netcls = ev.runtime
				p.netclsPod = ev.pod
			}
		}
	case common.EventUpdate:
		if err == nil {
			p.isCreated = true
		}
	}
}
