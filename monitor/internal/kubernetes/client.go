package kubernetesmonitor

import (
	"fmt"

	"go.uber.org/zap"
	api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	kubecache "k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

// NewKubeClient Generate and initialize a Kubernetes client based on the parameter kubeconfig
func NewKubeClient(kubeconfig string) (*kubernetes.Clientset, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("Error Building config from Kubeconfig: %v", err)
	}

	return kubernetes.NewForConfig(config)
}

// CreateResourceController creates a controller for a specific ressource and namespace.
// The parameter function will be called on Add/Delete/Update events
func CreateResourceController(client kubecache.Getter, resource string, namespace string, apiStruct runtime.Object, selector fields.Selector,
	addFunc func(addedApiStruct interface{}), deleteFunc func(deletedApiStruct interface{}), updateFunc func(oldApiStruct, updatedApiStruct interface{})) (kubecache.Store, kubecache.Controller) {

	handlers := kubecache.ResourceEventHandlerFuncs{
		AddFunc:    addFunc,
		DeleteFunc: deleteFunc,
		UpdateFunc: updateFunc,
	}

	listWatch := kubecache.NewListWatchFromClient(client, resource, namespace, selector)
	store, controller := kubecache.NewInformer(listWatch, apiStruct, 0, handlers)
	return store, controller
}

// CreateLocalPodController creates a controller specifically for Pods.
func (m *KubernetesMonitor) CreateLocalPodController(namespace string,
	addFunc func(addedApiStruct *api.Pod) error, deleteFunc func(deletedApiStruct *api.Pod) error, updateFunc func(oldApiStruct, updatedApiStruct *api.Pod) error) (kubecache.Store, kubecache.Controller) {

	return CreateResourceController(m.kubeClient.CoreV1().RESTClient(), "pods", namespace, &api.Pod{}, m.localNodeSelector(),
		func(addedApiStruct interface{}) {
			if err := addFunc(addedApiStruct.(*api.Pod)); err != nil {
				zap.L().Error("Error while handling Add Pod", zap.Error(err))
			}
		},
		func(deletedApiStruct interface{}) {
			if err := deleteFunc(deletedApiStruct.(*api.Pod)); err != nil {
				zap.L().Error("Error while handling Delete Pod", zap.Error(err))
			}
		},
		func(oldApiStruct, updatedApiStruct interface{}) {
			if err := updateFunc(oldApiStruct.(*api.Pod), updatedApiStruct.(*api.Pod)); err != nil {
				zap.L().Error("Error while handling Update Pod", zap.Error(err))
			}
		})
}

func (m *KubernetesMonitor) localNodeSelector() fields.Selector {
	return fields.Set(map[string]string{
		"spec.nodeName": m.localNode,
	}).AsSelector()
}

// Pod returns the full pod object.
func (m *KubernetesMonitor) Pod(podName string, namespace string) (*api.Pod, error) {
	targetPod, err := m.kubeClient.CoreV1().Pods(namespace).Get(podName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("error getting Kubernetes labels & IP for pod %v : %v ", podName, err)
	}
	return targetPod, nil
}
