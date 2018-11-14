package kubernetesmonitor

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/policy"
	"go.uber.org/zap"
	api "k8s.io/api/core/v1"
)

// General logic for handling logic fron the DockerMonitor ss the following:
// The only interesting event is the Start and Die event. All the other events are ignored

// Those events are then put together with the Pod events received from the Kubernetes API.
// Once both are received and are consistent, the Pod get activated.

// HandlePUEvent is called by all monitors when a PU event is generated. The implementer
// is responsible to update all components by explicitly adding a new PU.
// Specifically for Kubernetes, The monitor handles the downstream events from Docker.
func (m *KubernetesMonitor) HandlePUEvent(ctx context.Context, puID string, event common.Event, dockerRuntime policy.RuntimeReader) error {
	zap.L().Debug("dockermonitor event", zap.String("puID", puID), zap.String("eventType", string(event)))

	var kubernetesRuntime policy.RuntimeReader

	// If the event coming from DockerMonitor is start or create, we will get a meaningful PURuntime from
	// DockerMonitor. We can use it and combine it with the pod information on Kubernetes API.
	if event == common.EventStart || event == common.EventCreate {
		// We check first if this is a Kubernetes managed container
		podNamespace, podName, err := getKubernetesInformation(dockerRuntime)
		if err != nil {
			return err
		}

		// We get the information for that specific POD from Kubernetes API
		pod, err := m.getPod(podNamespace, podName)
		if err != nil {
			return err
		}

		// The KubernetesMetadataExtractor combines the information coming from Docker (runtime)
		// and from Kube (pod) in order to create a KubernetesRuntime.
		// The managedContainer parameters define if this container should be ignored.
		var managedContainer bool
		kubernetesRuntime, managedContainer, err = m.kubernetesExtractor(dockerRuntime, pod)
		if err != nil {

			return fmt.Errorf("error while processing Kubernetes pod %s/%s for container %s %s", podNamespace, podName, puID, err)
		}

		// UnmanagedContainers are simply ignored. No policy is associated.
		if !managedContainer {
			// for Unmanaged container check if host network and add the process to cgroup.
			zap.L().Debug("unmanaged Kubernetes container on create or start", zap.String("puID", puID), zap.String("podNamespace", podNamespace), zap.String("podName", podName))
			go m.programCgroup(podName, podNamespace, event, dockerRuntime)
			return nil
		}

		// We keep the cache uptoDate for future queries
		m.cache.updatePUIDCache(podNamespace, podName, puID, dockerRuntime, kubernetesRuntime)
	} else {

		// We check if this PUID was previously managed. We only sent the event upstream to the resolver if it was managed on create or start.
		kubernetesRuntime = m.cache.getKubernetesRuntimeByPUID(puID)
		if kubernetesRuntime == nil {
			zap.L().Debug("unmanaged Kubernetes container", zap.String("puID", puID))
			return nil
		}
	}

	if event == common.EventDestroy {
		// Time to kill the cache entry
		m.cache.deletePUIDEntry(puID)
	}

	// The event is then sent to the upstream policyResolver
	if err := m.handlers.Policy.HandlePUEvent(ctx, puID, event, kubernetesRuntime); err != nil {
		zap.L().Error("Unable to resolve policy for puid", zap.String("puID", puID))
		return fmt.Errorf("Unable to resolve policy for puid:%s", puID)
	}

	if dockerRuntime.PUType() == common.LinuxProcessPU {
		zap.L().Debug("Setting up host mode for pod", zap.String("pod", puID))
		return m.setupHostMode(puID, dockerRuntime, event, true)
	}

	return nil
}

// RefreshPUs is used to resend an update event to the Upstream Policy Resolver in case of an update is needed.
func (m *KubernetesMonitor) RefreshPUs(ctx context.Context, pod *api.Pod) error {
	if pod == nil {
		return fmt.Errorf("pod is nil")
	}

	podNamespace := pod.GetNamespace()
	podName := pod.GetName()

	puIDs := m.cache.getPUIDsbyPod(podNamespace, podName)

	for _, puid := range puIDs {
		dockerRuntime := m.cache.getDockerRuntimeByPUID(puid)
		if dockerRuntime == nil {
			continue
		}

		kubernetesRuntime, managedContainer, err := m.kubernetesExtractor(dockerRuntime, pod)
		if err != nil {
			return fmt.Errorf("error while processing Kubernetes pod %s/%s for container %s %s", podNamespace, podName, puid, err)
		}

		// UnmanagedContainers are simply ignored. It should not come this far if it is a non managed container anyways.
		if !managedContainer {
			zap.L().Debug("unmanaged Kubernetes container", zap.String("puID", puid), zap.String("podNamespace", podNamespace), zap.String("podName", podName))
			continue
		}

		// We keep the cache uptoDate for future queries
		m.cache.updatePUIDCache(podNamespace, podName, puid, dockerRuntime, kubernetesRuntime)

		if err := m.handlers.Policy.HandlePUEvent(ctx, puid, common.EventUpdate, kubernetesRuntime); err != nil {
			return err
		}
	}

	return nil
}

// getKubernetesInformation returns the name and namespace from a standard Docker runtime, if the docker container is associated at all with Kubernetes
func getKubernetesInformation(runtime policy.RuntimeReader) (string, string, error) {
	podNamespace, ok := runtime.Tag(KubernetesPodNamespaceIdentifier)
	if !ok {
		return "", "", fmt.Errorf("Error getting Kubernetes Pod namespace")
	}
	podName, ok := runtime.Tag(KubernetesPodNameIdentifier)
	if !ok {
		return "", "", fmt.Errorf("Error getting Kubernetes Pod name")
	}

	return podNamespace, podName, nil
}

func (m *KubernetesMonitor) programCgroup(podName, podNamespace string, event common.Event, runtimeInfo policy.RuntimeReader) {

	if event != common.EventStart {
		return
	}

	// Get puID of the pause container.
	var puID string
	puIDChan := make(chan string, 1)
	go m.findPauseContainer(podName, podNamespace, puIDChan)

	select {
	case <-time.After(500 * time.Millisecond):
		// if we do not find pause container after 500 ms, bail out.
		// This should  never happen.
		zap.L().Debug("Not a host container, timing out")

	case puID = <-puIDChan:
		zap.L().Debug("Found puID of pause container", zap.String("puID", puID))
	}

	// not a host container, ignore.
	if puID == "" {
		zap.L().Debug("Not a host container, so ignoring it", zap.String("podName", podName))
		return
	}

	m.setupHostMode(puID, runtimeInfo, event, false) // nolint
}

// findPauseContainer finds the puid for the pause container. The container events can come out
// of order.
func (m *KubernetesMonitor) findPauseContainer(podName, podNamespace string, puID chan string) {

	for {
		puIDs := m.cache.getPUIDsbyPod(podNamespace, podName)
		// get the puid of the pause container.
		for _, id := range puIDs {
			rtm := m.cache.getDockerRuntimeByPUID(id)

			if isPodInfraContainer(rtm) && rtm.PUType() == common.LinuxProcessPU {
				puID <- id
				return
			}

			// if infra container is found and it is not host container, then pod
			// is not a host pod.
			if isPodInfraContainer(rtm) {
				puID <- ""
				return
			}
		}
	}
}

// setupHostMode sets up the net_cls cgroup for the host net containers.
func (m *KubernetesMonitor) setupHostMode(puID string, runtimeInfo policy.RuntimeReader, event common.Event, pause bool) (err error) {

	// Do nothing on other events apart from start event.
	if event != common.EventStart {
		return nil
	}
	// For pause containers, create the cgroup. Add other containers
	// to the same cgroup as the pause container.
	if pause {
		if err = m.netcls.Creategroup(puID); err != nil {
			return err
		}
		// Clean the cgroup on exit, if we have failed to activate.
		defer func() {
			if err != nil {
				if derr := m.netcls.DeleteCgroup(puID); derr != nil {
					zap.L().Warn("Failed to clean cgroup",
						zap.String("puID", puID),
						zap.Error(derr),
						zap.Error(err),
					)
				}
			}
		}()

		markval := runtimeInfo.Options().CgroupMark
		if markval == "" {
			return errors.New("mark value not found")
		}

		mark, _ := strconv.ParseUint(markval, 10, 32)
		if err := m.netcls.AssignMark(puID, mark); err != nil {
			return err
		}
	}

	if err := m.netcls.AddProcess(puID, runtimeInfo.Pid()); err != nil {
		return fmt.Errorf("Unable to add process %d to cgroup.PUID:%s", runtimeInfo.Pid(), puID)
	}

	return nil
}

// isPodInfraContainer returns true if the runtime represents the infra container for the POD
func isPodInfraContainer(runtime policy.RuntimeReader) bool {
	// The Infra container can be found by checking env. variable.
	tagContent, ok := runtime.Tag(KubernetesContainerNameIdentifier)

	return ok && tagContent == KubernetesInfraContainerName
}
