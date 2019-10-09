// Package pleg implements a Pod Lifecycle Event Generator as outlined in the kubelet.
// We don't want to use the exact simple PLEG implementation from the kubelet because it
// gets and retrieves and cached more information than necessary for us.
//
// NOTE: This implementation has been adopting the Generic PLEG for our needs here.
//       The origional source code is located at: `github.com/kubernetes/kubernetes/pkg/kubelet/pleg/generic.go`
//
package pleg

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/clock"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog"

	criapi "k8s.io/cri-api/pkg/apis"
	criruntimeapi "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
)

// NOTE: taken from `github.com/kubernetes/kubernetes/pkg/kubelet/kubelet.go`
// We want to do everything as close as possible to the kubelet,
// so let's take these values as well,
const (
	// Capacity of the channel for receiving pod lifecycle events. This number
	// is a bit arbitrary and may be adjusted in the future.
	plegChannelCapacity = 1000

	// Generic PLEG relies on relisting for discovering container events.
	// A longer period means that kubelet will take longer to detect container
	// changes and to update pod status. On the other hand, a shorter period
	// will cause more frequent relisting (e.g., container runtime operations),
	// leading to higher cpu usage.
	// Note that even though we set the period to 1s, the relisting itself can
	// take more than 1s to finish if the container runtime responds slowly
	// and/or when there are many container changes in one cycle.
	plegRelistPeriod = time.Second * 1
)

// CRIPLEG holds the state for the CRI PLEG implementation
type CRIPLEG struct {
	// The period for relisting.
	relistPeriod time.Duration
	// The container runtime.
	runtime     criapi.RuntimeService
	runtimeName string
	// The channel from which the subscriber listens events.
	eventChannel chan *PodLifecycleEvent
	// The internal cache for pod/container information.
	podRecords podRecords
	// Time of the last relisting.
	relistTime atomic.Value
	// Cache for storing the runtime states required for syncing pods.
	cache Cache
	// For testability.
	clock clock.Clock
	// Pods that failed to have their status retrieved during a relist. These pods will be
	// retried during the next relisting.
	podsToReinspect map[types.UID]*Pod
}

// plegContainerState has a one-to-one mapping to the
// kubecontainer.ContainerState except for the non-existent state. This state
// is introduced here to complete the state transition scenarios.
type plegContainerState string

const (
	plegContainerRunning     plegContainerState = "running"
	plegContainerExited      plegContainerState = "exited"
	plegContainerUnknown     plegContainerState = "unknown"
	plegContainerNonExistent plegContainerState = "non-existent"

	// The threshold needs to be greater than the relisting period + the
	// relisting time, which can vary significantly. Set a conservative
	// threshold to avoid flipping between healthy and unhealthy.
	relistThreshold = 3 * time.Minute
)

func convertState(state ContainerState) plegContainerState {
	switch state {
	case ContainerStateCreated:
		// kubelet doesn't use the "created" state yet, hence convert it to "unknown".
		return plegContainerUnknown
	case ContainerStateRunning:
		return plegContainerRunning
	case ContainerStateExited:
		return plegContainerExited
	case ContainerStateUnknown:
		return plegContainerUnknown
	default:
		panic(fmt.Sprintf("unrecognized container state: %v", state))
	}
}

type podRecord struct {
	old     *Pod
	current *Pod
}

type podRecords map[types.UID]*podRecord

// NewCRIPLEG instantiates a new CRIPLEG object and return it.
func NewCRIPLEG(runtime criapi.RuntimeService, runtimeName string) PodLifecycleEventGenerator {
	return &CRIPLEG{
		relistPeriod: plegRelistPeriod,
		runtime:      runtime,
		runtimeName:  runtimeName,
		eventChannel: make(chan *PodLifecycleEvent, plegChannelCapacity),
		podRecords:   make(podRecords),
		cache:        NewCache(),
		clock:        clock.RealClock{},
	}
}

// Watch returns a channel from which the subscriber can receive PodLifecycleEvent
// events.
// TODO: support multiple subscribers.
func (g *CRIPLEG) Watch() chan *PodLifecycleEvent {
	return g.eventChannel
}

// Start spawns a goroutine to relist periodically.
func (g *CRIPLEG) Start(stopCh <-chan struct{}) {
	go wait.Until(g.relist, g.relistPeriod, stopCh)
}

// Healthy check if PLEG work properly.
// relistThreshold is the maximum interval between two relist.
func (g *CRIPLEG) Healthy() (bool, error) {
	relistTime := g.getRelistTime()
	if relistTime.IsZero() {
		return false, fmt.Errorf("pleg has yet to be successful")
	}
	elapsed := g.clock.Since(relistTime)
	if elapsed > relistThreshold {
		return false, fmt.Errorf("pleg was last seen active %v ago; threshold is %v", elapsed, relistThreshold)
	}
	return true, nil
}

func generateEvents(podID types.UID, cidID *ContainerID, oldPod, newPod *Pod) []*PodLifecycleEvent {
	cid := cidID.ID
	oldState := getContainerState(oldPod, cidID)
	newState := getContainerState(newPod, cidID)
	if newState == oldState {
		return nil
	}
	var nn types.NamespacedName
	if newPod != nil {
		nn = types.NamespacedName{
			Name:      newPod.Name,
			Namespace: newPod.Namespace,
		}
	}
	if nn.Name == "" && oldPod != nil && oldPod.Name != "" {
		nn.Name = oldPod.Name
	}
	if nn.Namespace == "" && oldPod != nil && oldPod.Namespace != "" {
		nn.Namespace = oldPod.Namespace
	}

	//zap.L().Debug(fmt.Sprintf("CRIPLEG: (%s) %v/%v: %v -> %v", nn, podID, cid, oldState, newState))
	switch newState {
	case plegContainerRunning:
		return []*PodLifecycleEvent{{ID: podID, NamespacedName: nn, Type: ContainerStarted, Data: cid}}
	case plegContainerExited:
		return []*PodLifecycleEvent{{ID: podID, NamespacedName: nn, Type: ContainerDied, Data: cid}}
	case plegContainerUnknown:
		return []*PodLifecycleEvent{{ID: podID, NamespacedName: nn, Type: ContainerChanged, Data: cid}}
	case plegContainerNonExistent:
		switch oldState {
		case plegContainerExited:
			// We already reported that the container died before.
			return []*PodLifecycleEvent{{ID: podID, NamespacedName: nn, Type: ContainerRemoved, Data: cid}}
		default:
			return []*PodLifecycleEvent{{ID: podID, NamespacedName: nn, Type: ContainerDied, Data: cid}, {ID: podID, Type: ContainerRemoved, Data: cid}}
		}
	default:
		panic(fmt.Sprintf("unrecognized container state: %v", newState))
	}
}

func (g *CRIPLEG) getRelistTime() time.Time {
	val := g.relistTime.Load()
	if val == nil {
		return time.Time{}
	}
	return val.(time.Time)
}

func (g *CRIPLEG) updateRelistTime(timestamp time.Time) {
	g.relistTime.Store(timestamp)
}

// relist queries the container runtime for list of pods/containers, compare
// with the internal pods/containers, and generates events accordingly.
func (g *CRIPLEG) relist() {
	//zap.L().Debug("CRIPLEG: Relisting")

	//if lastRelistTime := g.getRelistTime(); !lastRelistTime.IsZero() {
	//	metrics.PLEGRelistInterval.Observe(metrics.SinceInSeconds(lastRelistTime))
	//	metrics.DeprecatedPLEGRelistInterval.Observe(metrics.SinceInMicroseconds(lastRelistTime))
	//}

	timestamp := g.clock.Now()
	//defer func() {
	//	metrics.PLEGRelistDuration.Observe(metrics.SinceInSeconds(timestamp))
	//	metrics.DeprecatedPLEGRelistLatency.Observe(metrics.SinceInMicroseconds(timestamp))
	//}()

	// Get all the pods.
	podList, err := GetPods(g.runtime, g.runtimeName, true)
	if err != nil {
		klog.Errorf("CRIPLEG: Unable to retrieve pods: %v", err)
		return
	}

	g.updateRelistTime(timestamp)

	pods := Pods(podList)
	// update running pod and container count
	//updateRunningPodAndContainerMetrics(pods)
	g.podRecords.setCurrent(pods)

	// Compare the old and the current pods, and generate events.
	eventsByPodID := map[types.UID][]*PodLifecycleEvent{}
	for pid := range g.podRecords {
		oldPod := g.podRecords.getOld(pid)
		pod := g.podRecords.getCurrent(pid)
		// Get all containers in the old and the new pod.
		allContainers := getContainersFromPods(oldPod, pod)
		for _, container := range allContainers {
			events := computeEvents(oldPod, pod, &container.ID)
			for _, e := range events {
				updateEvents(eventsByPodID, e)
			}
		}
	}

	var needsReinspection map[types.UID]*Pod
	if g.cacheEnabled() {
		needsReinspection = make(map[types.UID]*Pod)
	}

	// If there are events associated with a pod, we should update the
	// podCache.
	for pid, events := range eventsByPodID {
		pod := g.podRecords.getCurrent(pid)
		if g.cacheEnabled() {
			// updateCache() will inspect the pod and update the cache. If an
			// error occurs during the inspection, we want PLEG to retry again
			// in the next relist. To achieve this, we do not update the
			// associated podRecord of the pod, so that the change will be
			// detect again in the next relist.
			// TODO: If many pods changed during the same relist period,
			// inspecting the pod and getting the PodStatus to update the cache
			// serially may take a while. We should be aware of this and
			// parallelize if needed.
			if err := g.updateCache(pod, pid); err != nil {
				// Rely on updateCache calling GetPodStatus to log the actual error.
				zap.L().Debug(fmt.Sprintf("CRIPLEG: Ignoring events for pod %s/%s: %v", pod.Name, pod.Namespace, err))

				// make sure we try to reinspect the pod during the next relisting
				needsReinspection[pid] = pod

				continue
			} else {
				// this pod was in the list to reinspect and we did so because it had events, so remove it
				// from the list (we don't want the reinspection code below to inspect it a second time in
				// this relist execution)
				delete(g.podsToReinspect, pid)
			}
		}
		// Update the internal storage and send out the events.
		g.podRecords.update(pid)
		for i := range events {
			// Filter out events that are not reliable and no other components use yet.
			if events[i].Type == ContainerChanged {
				continue
			}
			select {
			case g.eventChannel <- events[i]:
			default:
				//metrics.PLEGDiscardEvents.WithLabelValues().Inc()
				zap.L().Debug("CRIPLEG: event channel is full, discard this relist() cycle event")
			}
		}
	}

	if g.cacheEnabled() {
		// reinspect any pods that failed inspection during the previous relist
		if len(g.podsToReinspect) > 0 {
			zap.L().Debug("CRIPLEG: Reinspecting pods that previously failed inspection")
			for pid, pod := range g.podsToReinspect {
				if err := g.updateCache(pod, pid); err != nil {
					// Rely on updateCache calling GetPodStatus to log the actual error.
					zap.L().Debug(fmt.Sprintf("PLEG: pod %s/%s failed reinspection: %v", pod.Name, pod.Namespace, err))
					needsReinspection[pid] = pod
				}
			}
		}

		// Update the cache timestamp.  This needs to happen *after*
		// all pods have been properly updated in the cache.
		g.cache.UpdateTime(timestamp)
	}

	// make sure we retain the list of pods that need reinspecting the next time relist is called
	g.podsToReinspect = needsReinspection
}

func getContainersFromPods(pods ...*Pod) []*Container {
	cidSet := sets.NewString()
	var containers []*Container
	for _, p := range pods {
		if p == nil {
			continue
		}
		for _, c := range p.Containers {
			cid := string(c.ID.ID)
			if cidSet.Has(cid) {
				continue
			}
			cidSet.Insert(cid)
			containers = append(containers, c)
		}
		// Update sandboxes as containers
		// TODO: keep track of sandboxes explicitly.
		for _, c := range p.Sandboxes {
			cid := string(c.ID.ID)
			if cidSet.Has(cid) {
				continue
			}
			cidSet.Insert(cid)
			containers = append(containers, c)
		}

	}
	return containers
}

func computeEvents(oldPod, newPod *Pod, cid *ContainerID) []*PodLifecycleEvent {
	var pid types.UID
	if oldPod != nil {
		pid = oldPod.ID
	} else if newPod != nil {
		pid = newPod.ID
	}

	return generateEvents(pid, cid, oldPod, newPod)
}

func (g *CRIPLEG) cacheEnabled() bool {
	return g.cache != nil
}

// getPodIP preserves an older cached status' pod IP if the new status has no pod IPs
// and its sandboxes have exited
func (g *CRIPLEG) getPodIPs(pid types.UID, status *PodStatus) []string {
	if len(status.IPs) != 0 {
		return status.IPs
	}

	oldStatus, err := g.cache.Get(pid)
	if err != nil || len(oldStatus.IPs) == 0 {
		return nil
	}

	for _, sandboxStatus := range status.SandboxStatuses {
		// If at least one sandbox is ready, then use this status update's pod IP
		if sandboxStatus.State == criruntimeapi.PodSandboxState_SANDBOX_READY {
			return status.IPs
		}
	}

	if len(status.SandboxStatuses) == 0 {
		// Without sandboxes (which built-in runtimes like rkt don't report)
		// look at all the container statuses, and if any containers are
		// running then use the new pod IP
		for _, containerStatus := range status.ContainerStatuses {
			if containerStatus.State == ContainerStateCreated || containerStatus.State == ContainerStateRunning {
				return status.IPs
			}
		}
	}

	// For pods with no ready containers or sandboxes (like exited pods)
	// use the old status' pod IP
	return oldStatus.IPs
}

func (g *CRIPLEG) updateCache(pod *Pod, pid types.UID) error {
	if pod == nil {
		// The pod is missing in the current relist. This means that
		// the pod has no visible (active or inactive) containers.
		//zap.L().Debug(fmt.Sprintf("CRIPLEG: Delete status for pod %q", string(pid)))
		g.cache.Delete(pid)
		return nil
	}
	timestamp := g.clock.Now()
	// TODO: Consider adding a new runtime method
	// GetPodStatus(pod *kubecontainer.Pod) so that Docker can avoid listing
	// all containers again.
	status, err := GetPodStatus(g.runtime, g.runtimeName, pod.ID, pod.Name, pod.Namespace)
	//zap.L().Debug(fmt.Sprintf("CRIPLEG: Write status for %s/%s: %#v (err: %v)", pod.Name, pod.Namespace, status, err))
	if err == nil {
		// Preserve the pod IP across cache updates if the new IP is empty.
		// When a pod is torn down, kubelet may race with PLEG and retrieve
		// a pod status after network teardown, but the kubernetes API expects
		// the completed pod's IP to be available after the pod is dead.
		status.IPs = g.getPodIPs(pid, status)
	}

	g.cache.Set(pod.ID, status, err, timestamp)
	return err
}

func updateEvents(eventsByPodID map[types.UID][]*PodLifecycleEvent, e *PodLifecycleEvent) {
	if e == nil {
		return
	}
	eventsByPodID[e.ID] = append(eventsByPodID[e.ID], e)
}

func getContainerState(pod *Pod, cid *ContainerID) plegContainerState {
	// Default to the non-existent state.
	state := plegContainerNonExistent
	if pod == nil {
		return state
	}
	c := pod.FindContainerByID(*cid)
	if c != nil {
		return convertState(c.State)
	}
	// Search through sandboxes too.
	c = pod.FindSandboxByID(*cid)
	if c != nil {
		return convertState(c.State)
	}

	return state
}

//func updateRunningPodAndContainerMetrics(pods []*Pod) {
//	// Set the number of running pods in the parameter
//	//metrics.RunningPodCount.Set(float64(len(pods)))
//	// intermediate map to store the count of each "container_state"
//	containerStateCount := make(map[string]int)
//
//	for _, pod := range pods {
//		containers := pod.Containers
//		for _, container := range containers {
//			// update the corresponding "container_state" in map to set value for the gaugeVec metrics
//			containerStateCount[string(container.State)]++
//		}
//	}
//	for key, value := range containerStateCount {
//		metrics.RunningContainerCount.WithLabelValues(key).Set(float64(value))
//	}
//}

func (pr podRecords) getOld(id types.UID) *Pod {
	r, ok := pr[id]
	if !ok {
		return nil
	}
	return r.old
}

func (pr podRecords) getCurrent(id types.UID) *Pod {
	r, ok := pr[id]
	if !ok {
		return nil
	}
	return r.current
}

func (pr podRecords) setCurrent(pods []*Pod) {
	for i := range pr {
		pr[i].current = nil
	}
	for _, pod := range pods {
		if r, ok := pr[pod.ID]; ok {
			r.current = pod
		} else {
			pr[pod.ID] = &podRecord{current: pod}
		}
	}
}

func (pr podRecords) update(id types.UID) {
	r, ok := pr[id]
	if !ok {
		return
	}
	pr.updateInternal(id, r)
}

func (pr podRecords) updateInternal(id types.UID, r *podRecord) {
	if r.current == nil {
		// Pod no longer exists; delete the entry.
		delete(pr, id)
		return
	}
	r.old = r.current
	r.current = nil
}

// GetPods returns a list of containers grouped by pods.
func GetPods(runtime criapi.RuntimeService, runtimeName string, all bool) ([]*Pod, error) {
	pods := make(map[types.UID]*Pod)
	sandboxes, err := getKubeletSandboxes(runtime, all)
	if err != nil {
		return nil, err
	}
	for i := range sandboxes {
		s := sandboxes[i]
		if s.Metadata == nil {
			continue
		}
		podUID := types.UID(s.Metadata.Uid)
		if _, ok := pods[podUID]; !ok {
			pods[podUID] = &Pod{
				ID:        podUID,
				Name:      s.Metadata.Name,
				Namespace: s.Metadata.Namespace,
			}
		}
		p := pods[podUID]
		converted, err := sandboxToKubeContainer(s, runtimeName)
		if err != nil {
			continue
		}
		p.Sandboxes = append(p.Sandboxes, converted)
	}

	containers, err := getKubeletContainers(runtime, all)
	if err != nil {
		return nil, err
	}
	for i := range containers {
		c := containers[i]
		if c.Metadata == nil {
			continue
		}

		labelledInfo := getContainerInfoFromLabels(c.Labels)
		pod, found := pods[labelledInfo.PodUID]
		if !found {
			pod = &Pod{
				ID:        labelledInfo.PodUID,
				Name:      labelledInfo.PodName,
				Namespace: labelledInfo.PodNamespace,
			}
			pods[labelledInfo.PodUID] = pod
		}

		converted, err := toKubeContainer(c, runtimeName)
		if err != nil {
			continue
		}

		pod.Containers = append(pod.Containers, converted)
	}

	// Convert map to list.
	var result []*Pod
	for _, pod := range pods {
		result = append(result, pod)
	}

	return result, nil
}

type labeledContainerInfo struct {
	ContainerName string
	PodName       string
	PodNamespace  string
	PodUID        types.UID
}

type annotatedContainerInfo struct {
	Hash                      uint64
	RestartCount              int
	PodDeletionGracePeriod    *int64
	PodTerminationGracePeriod *int64
	TerminationMessagePath    string
	TerminationMessagePolicy  v1.TerminationMessagePolicy
	PreStopHandler            *v1.Handler
	ContainerPorts            []v1.ContainerPort
}

const (
	// KubernetesPodNameLabel label
	KubernetesPodNameLabel = "io.kubernetes.pod.name"
	// KubernetesPodNamespaceLabel label
	KubernetesPodNamespaceLabel = "io.kubernetes.pod.namespace"
	// KubernetesPodUIDLabel label
	KubernetesPodUIDLabel = "io.kubernetes.pod.uid"
	// KubernetesContainerNameLabel label
	KubernetesContainerNameLabel = "io.kubernetes.container.name"

	podDeletionGracePeriodLabel    = "io.kubernetes.pod.deletionGracePeriod"
	podTerminationGracePeriodLabel = "io.kubernetes.pod.terminationGracePeriod"

	containerHashLabel                     = "io.kubernetes.container.hash"
	containerRestartCountLabel             = "io.kubernetes.container.restartCount"
	containerTerminationMessagePathLabel   = "io.kubernetes.container.terminationMessagePath"
	containerTerminationMessagePolicyLabel = "io.kubernetes.container.terminationMessagePolicy"
	containerPreStopHandlerLabel           = "io.kubernetes.container.preStopHandler"
	containerPortsLabel                    = "io.kubernetes.container.ports"
)

// getContainerInfoFromLabels gets labeledContainerInfo from labels.
func getContainerInfoFromLabels(labels map[string]string) *labeledContainerInfo {
	return &labeledContainerInfo{
		PodName:       getStringValueFromLabel(labels, KubernetesPodNameLabel),
		PodNamespace:  getStringValueFromLabel(labels, KubernetesPodNamespaceLabel),
		PodUID:        types.UID(getStringValueFromLabel(labels, KubernetesPodUIDLabel)),
		ContainerName: getStringValueFromLabel(labels, KubernetesContainerNameLabel),
	}
}

// getContainerInfoFromAnnotations gets annotatedContainerInfo from annotations.
func getContainerInfoFromAnnotations(annotations map[string]string) *annotatedContainerInfo {
	var err error
	containerInfo := &annotatedContainerInfo{
		TerminationMessagePath:   getStringValueFromLabel(annotations, containerTerminationMessagePathLabel),
		TerminationMessagePolicy: v1.TerminationMessagePolicy(getStringValueFromLabel(annotations, containerTerminationMessagePolicyLabel)),
	}

	if containerInfo.Hash, err = getUint64ValueFromLabel(annotations, containerHashLabel); err != nil {
	}
	if containerInfo.RestartCount, err = getIntValueFromLabel(annotations, containerRestartCountLabel); err != nil {
	}
	if containerInfo.PodDeletionGracePeriod, err = getInt64PointerFromLabel(annotations, podDeletionGracePeriodLabel); err != nil {
	}
	if containerInfo.PodTerminationGracePeriod, err = getInt64PointerFromLabel(annotations, podTerminationGracePeriodLabel); err != nil {
	}

	preStopHandler := &v1.Handler{}
	if found, err := getJSONObjectFromLabel(annotations, containerPreStopHandlerLabel, preStopHandler); err != nil {
	} else if found {
		containerInfo.PreStopHandler = preStopHandler
	}

	containerPorts := []v1.ContainerPort{}
	if found, err := getJSONObjectFromLabel(annotations, containerPortsLabel, &containerPorts); err != nil {
	} else if found {
		containerInfo.ContainerPorts = containerPorts
	}

	return containerInfo
}

func getStringValueFromLabel(labels map[string]string, label string) string {
	if value, found := labels[label]; found {
		return value
	}
	// Do not report error, because there should be many old containers without label now.
	// Return empty string "" for these containers, the caller will get value by other ways.
	return ""
}

func getIntValueFromLabel(labels map[string]string, label string) (int, error) {
	if strValue, found := labels[label]; found {
		intValue, err := strconv.Atoi(strValue)
		if err != nil {
			// This really should not happen. Just set value to 0 to handle this abnormal case
			return 0, err
		}
		return intValue, nil
	}
	// Do not report error, because there should be many old containers without label now.
	// Just set the value to 0
	return 0, nil
}

func getUint64ValueFromLabel(labels map[string]string, label string) (uint64, error) {
	if strValue, found := labels[label]; found {
		intValue, err := strconv.ParseUint(strValue, 16, 64)
		if err != nil {
			// This really should not happen. Just set value to 0 to handle this abnormal case
			return 0, err
		}
		return intValue, nil
	}
	// Do not report error, because there should be many old containers without label now.
	// Just set the value to 0
	return 0, nil
}

func getInt64PointerFromLabel(labels map[string]string, label string) (*int64, error) {
	if strValue, found := labels[label]; found {
		int64Value, err := strconv.ParseInt(strValue, 10, 64)
		if err != nil {
			return nil, err
		}
		return &int64Value, nil
	}
	// If the label is not found, return pointer nil.
	return nil, nil
}

// getJSONObjectFromLabel returns a bool value indicating whether an object is found.
func getJSONObjectFromLabel(labels map[string]string, label string, value interface{}) (bool, error) {
	if strValue, found := labels[label]; found {
		err := json.Unmarshal([]byte(strValue), value)
		return found, err
	}
	// If the label is not found, return not found.
	return false, nil
}

// GetPodStatus retrieves the status of the pod, including the
// information of all containers in the pod that are visible in Runtime.
func GetPodStatus(runtime criapi.RuntimeService, runtimeName string, uid types.UID, name, namespace string) (*PodStatus, error) {
	// Now we retain restart count of container as a container label. Each time a container
	// restarts, pod will read the restart count from the registered dead container, increment
	// it to get the new restart count, and then add a label with the new restart count on
	// the newly started container.
	// However, there are some limitations of this method:
	//	1. When all dead containers were garbage collected, the container status could
	//	not get the historical value and would be *inaccurate*. Fortunately, the chance
	//	is really slim.
	//	2. When working with old version containers which have no restart count label,
	//	we can only assume their restart count is 0.
	// Anyhow, we only promised "best-effort" restart count reporting, we can just ignore
	// these limitations now.
	// TODO: move this comment to SyncPod.
	podSandboxIDs, err := getSandboxIDByPodUID(runtime, uid, nil)
	if err != nil {
		return nil, err
	}

	//podFullName := FormatPod(&v1.Pod{
	//	ObjectMeta: metav1.ObjectMeta{
	//		Name:      name,
	//		Namespace: namespace,
	//		UID:       uid,
	//	},
	//})

	sandboxStatuses := make([]*criruntimeapi.PodSandboxStatus, len(podSandboxIDs))
	podIPs := []string{}
	for idx, podSandboxID := range podSandboxIDs {
		podSandboxStatus, err := runtime.PodSandboxStatus(podSandboxID)
		if err != nil {
			return nil, err
		}
		sandboxStatuses[idx] = podSandboxStatus

		// Only get pod IP from latest sandbox
		if idx == 0 && podSandboxStatus.State == criruntimeapi.PodSandboxState_SANDBOX_READY {
			podIPs = determinePodSandboxIPs(runtime, namespace, name, podSandboxStatus)
		}
	}

	// Get statuses of all containers visible in the pod.
	containerStatuses, err := getPodContainerStatuses(runtime, runtimeName, uid, name, namespace)
	if err != nil {
		return nil, err
	}

	return &PodStatus{
		ID:                uid,
		Name:              name,
		Namespace:         namespace,
		IPs:               podIPs,
		SandboxStatuses:   sandboxStatuses,
		ContainerStatuses: containerStatuses,
	}, nil
}

//// FormatPod returns a string representing a pod in a consistent human readable format,
//// with pod UID as part of the string.
//func FormatPod(pod *v1.Pod) string {
//	return FormatPodDesc(pod.Name, pod.Namespace, pod.UID)
//}

//// FormatPodDesc returns a string representing a pod in a consistent human readable format,
//// with pod UID as part of the string.
//func FormatPodDesc(podName, podNamespace string, podUID types.UID) string {
//	// Use underscore as the delimiter because it is not allowed in pod name
//	// (DNS subdomain format), while allowed in the container name format.
//	return fmt.Sprintf("%s_%s(%s)", podName, podNamespace, podUID)
//}

// getKubeletSandboxes lists all (or just the running) sandboxes managed by kubelet.
func getKubeletSandboxes(runtime criapi.RuntimeService, all bool) ([]*criruntimeapi.PodSandbox, error) {
	var filter *criruntimeapi.PodSandboxFilter
	if !all {
		readyState := criruntimeapi.PodSandboxState_SANDBOX_READY
		filter = &criruntimeapi.PodSandboxFilter{
			State: &criruntimeapi.PodSandboxStateValue{
				State: readyState,
			},
		}
	}

	resp, err := runtime.ListPodSandbox(filter)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// determinePodSandboxIP determines the IP addresses of the given pod sandbox.
func determinePodSandboxIPs(runtime criapi.RuntimeService, podNamespace, podName string, podSandbox *criruntimeapi.PodSandboxStatus) []string {
	podIPs := make([]string, 0)
	if podSandbox.Network == nil {
		klog.Warningf("Pod Sandbox status doesn't have network information, cannot report IPs")
		return podIPs
	}

	// ip could be an empty string if runtime is not responsible for the
	// IP (e.g., host networking).

	// pick primary IP
	if len(podSandbox.Network.Ip) != 0 {
		if net.ParseIP(podSandbox.Network.Ip) == nil {
			klog.Warningf("Pod Sandbox reported an unparseable IP (Primary) %v", podSandbox.Network.Ip)
			return nil
		}
		podIPs = append(podIPs, podSandbox.Network.Ip)
	}

	// pick additional ips, if cri reported them
	for _, podIP := range podSandbox.Network.AdditionalIps {
		if nil == net.ParseIP(podIP.Ip) {
			return nil
		}
		podIPs = append(podIPs, podIP.Ip)
	}

	return podIPs
}

type podSandboxByCreated []*criruntimeapi.PodSandbox

func (p podSandboxByCreated) Len() int           { return len(p) }
func (p podSandboxByCreated) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p podSandboxByCreated) Less(i, j int) bool { return p[i].CreatedAt > p[j].CreatedAt }

// getPodSandboxID gets the sandbox id by podUID and returns ([]sandboxID, error).
// Param state could be nil in order to get all sandboxes belonging to same pod.
func getSandboxIDByPodUID(runtime criapi.RuntimeService, podUID types.UID, state *criruntimeapi.PodSandboxState) ([]string, error) {
	filter := &criruntimeapi.PodSandboxFilter{
		LabelSelector: map[string]string{KubernetesPodUIDLabel: string(podUID)},
	}
	if state != nil {
		filter.State = &criruntimeapi.PodSandboxStateValue{
			State: *state,
		}
	}
	sandboxes, err := runtime.ListPodSandbox(filter)
	if err != nil {
		return nil, err
	}

	if len(sandboxes) == 0 {
		return nil, nil
	}

	// Sort with newest first.
	sandboxIDs := make([]string, len(sandboxes))
	sort.Sort(podSandboxByCreated(sandboxes))
	for i, s := range sandboxes {
		sandboxIDs[i] = s.Id
	}

	return sandboxIDs, nil
}

// getKubeletContainers lists containers managed by kubelet.
// The boolean parameter specifies whether returns all containers including
// those already exited and dead containers (used for garbage collection).
func getKubeletContainers(runtime criapi.RuntimeService, allContainers bool) ([]*criruntimeapi.Container, error) {
	filter := &criruntimeapi.ContainerFilter{}
	if !allContainers {
		filter.State = &criruntimeapi.ContainerStateValue{
			State: criruntimeapi.ContainerState_CONTAINER_RUNNING,
		}
	}

	containers, err := runtime.ListContainers(filter)
	if err != nil {
		return nil, err
	}

	return containers, nil
}

type containerStatusByCreated []*ContainerStatus

func (c containerStatusByCreated) Len() int           { return len(c) }
func (c containerStatusByCreated) Swap(i, j int)      { c[i], c[j] = c[j], c[i] }
func (c containerStatusByCreated) Less(i, j int) bool { return c[i].CreatedAt.After(c[j].CreatedAt) }

// getPodContainerStatuses gets all containers' statuses for the pod.
func getPodContainerStatuses(runtime criapi.RuntimeService, runtimeName string, uid types.UID, name, namespace string) ([]*ContainerStatus, error) {
	// Select all containers of the given pod.
	containers, err := runtime.ListContainers(&criruntimeapi.ContainerFilter{
		LabelSelector: map[string]string{KubernetesPodUIDLabel: string(uid)},
	})
	if err != nil {
		return nil, err
	}

	statuses := make([]*ContainerStatus, len(containers))
	// TODO: optimization: set maximum number of containers per container name to examine.
	for i, c := range containers {
		status, err := runtime.ContainerStatus(c.Id)
		if err != nil {
			// Merely log this here; GetPodStatus will actually report the error out.
			return nil, err
		}
		cStatus := toKubeContainerStatus(status, runtimeName)
		//if status.State == criruntimeapi.ContainerState_CONTAINER_EXITED {
		//	// Populate the termination message if needed.
		//	annotatedInfo := getContainerInfoFromAnnotations(status.Annotations)
		//	fallbackToLogs := annotatedInfo.TerminationMessagePolicy == v1.TerminationMessageFallbackToLogsOnError && cStatus.ExitCode != 0
		//	tMessage, checkLogs := getTerminationMessage(status, annotatedInfo.TerminationMessagePath, fallbackToLogs)
		//	if checkLogs {
		//		// if dockerLegacyService is populated, we're supposed to use it to fetch logs
		//		if m.legacyLogProvider != nil {
		//			tMessage, err = m.legacyLogProvider.GetContainerLogTail(uid, name, namespace, ContainerID{Type: m.runtimeName, ID: c.Id})
		//			if err != nil {
		//				tMessage = fmt.Sprintf("Error reading termination message from logs: %v", err)
		//			}
		//		} else {
		//			tMessage = m.readLastStringFromContainerLogs(status.GetLogPath())
		//		}
		//	}
		//	// Use the termination message written by the application is not empty
		//	if len(tMessage) != 0 {
		//		cStatus.Message = tMessage
		//	}
		//}
		statuses[i] = cStatus
	}

	sort.Sort(containerStatusByCreated(statuses))
	return statuses, nil
}

func toKubeContainerStatus(status *criruntimeapi.ContainerStatus, runtimeName string) *ContainerStatus {
	annotatedInfo := getContainerInfoFromAnnotations(status.Annotations)
	labeledInfo := getContainerInfoFromLabels(status.Labels)
	cStatus := &ContainerStatus{
		ID: ContainerID{
			Type: runtimeName,
			ID:   status.Id,
		},
		Name:         labeledInfo.ContainerName,
		Image:        status.Image.Image,
		ImageID:      status.ImageRef,
		Hash:         annotatedInfo.Hash,
		RestartCount: annotatedInfo.RestartCount,
		State:        toKubeContainerState(status.State),
		CreatedAt:    time.Unix(0, status.CreatedAt),
	}

	if status.State != criruntimeapi.ContainerState_CONTAINER_CREATED {
		// If container is not in the created state, we have tried and
		// started the container. Set the StartedAt time.
		cStatus.StartedAt = time.Unix(0, status.StartedAt)
	}
	if status.State == criruntimeapi.ContainerState_CONTAINER_EXITED {
		cStatus.Reason = status.Reason
		cStatus.Message = status.Message
		cStatus.ExitCode = int(status.ExitCode)
		cStatus.FinishedAt = time.Unix(0, status.FinishedAt)
	}
	return cStatus
}

// toKubeContainerState converts runtimeapi.ContainerState to kubecontainer.ContainerState.
func toKubeContainerState(state criruntimeapi.ContainerState) ContainerState {
	switch state {
	case criruntimeapi.ContainerState_CONTAINER_CREATED:
		return ContainerStateCreated
	case criruntimeapi.ContainerState_CONTAINER_RUNNING:
		return ContainerStateRunning
	case criruntimeapi.ContainerState_CONTAINER_EXITED:
		return ContainerStateExited
	case criruntimeapi.ContainerState_CONTAINER_UNKNOWN:
		return ContainerStateUnknown
	}

	return ContainerStateUnknown
}

// toKubeContainer converts runtimeapi.Container to kubecontainer.Container.
func toKubeContainer(c *criruntimeapi.Container, runtimeName string) (*Container, error) {
	if c == nil || c.Id == "" || c.Image == nil {
		return nil, fmt.Errorf("unable to convert a nil pointer to a runtime container")
	}

	annotatedInfo := getContainerInfoFromAnnotations(c.Annotations)
	return &Container{
		ID:      ContainerID{Type: runtimeName, ID: c.Id},
		Name:    c.GetMetadata().GetName(),
		ImageID: c.ImageRef,
		Image:   c.Image.Image,
		Hash:    annotatedInfo.Hash,
		State:   toKubeContainerState(c.State),
	}, nil
}

// sandboxToKubeContainer converts runtimeapi.PodSandbox to kubecontainer.Container.
// This is only needed because we need to return sandboxes as if they were
// kubecontainer.Containers to avoid substantial changes to PLEG.
// TODO: Remove this once it becomes obsolete.
func sandboxToKubeContainer(s *criruntimeapi.PodSandbox, runtimeName string) (*Container, error) {
	if s == nil || s.Id == "" {
		return nil, fmt.Errorf("unable to convert a nil pointer to a runtime container")
	}

	return &Container{
		ID:    ContainerID{Type: runtimeName, ID: s.Id},
		State: SandboxToContainerState(s.State),
	}, nil
}

// SandboxToContainerState converts runtimeapi.PodSandboxState to
// kubecontainer.ContainerState.
// This is only needed because we need to return sandboxes as if they were
// kubecontainer.Containers to avoid substantial changes to PLEG.
// TODO: Remove this once it becomes obsolete.
func SandboxToContainerState(state criruntimeapi.PodSandboxState) ContainerState {
	switch state {
	case criruntimeapi.PodSandboxState_SANDBOX_READY:
		return ContainerStateRunning
	case criruntimeapi.PodSandboxState_SANDBOX_NOTREADY:
		return ContainerStateExited
	}
	return ContainerStateUnknown
}
