package kubernetesmonitor

import (
	"fmt"

	"go.uber.org/zap"
	api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

// NewClient Generate and initialize a Kubernetes client
func NewKubeClient(kubeconfig string) (*kubernetes.Clientset, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("Error Building config from Kubeconfig: %v", err)
	}

	return kubernetes.NewForConfig(config)
}

// CreateResourceController creates a controller for a specific ressource and namespace.
// The parameter function will be called on Add/Delete/Update events
func CreateResourceController(client cache.Getter, resource string, namespace string, apiStruct runtime.Object, selector fields.Selector,
	addFunc func(addedApiStruct interface{}), deleteFunc func(deletedApiStruct interface{}), updateFunc func(oldApiStruct, updatedApiStruct interface{})) (cache.Store, cache.Controller) {

	handlers := cache.ResourceEventHandlerFuncs{
		AddFunc:    addFunc,
		DeleteFunc: deleteFunc,
		UpdateFunc: updateFunc,
	}

	listWatch := cache.NewListWatchFromClient(client, resource, namespace, selector)
	store, controller := cache.NewInformer(listWatch, apiStruct, 0, handlers)
	return store, controller
}

// CreateLocalPodController creates a controller specifically for Pods.
func (c *Client) CreateLocalPodController(namespace string,
	addFunc func(addedApiStruct *api.Pod) error, deleteFunc func(deletedApiStruct *api.Pod) error, updateFunc func(oldApiStruct, updatedApiStruct *api.Pod) error) (cache.Store, cache.Controller) {

	return CreateResourceController(c.KubeClient().Core().RESTClient(), "pods", namespace, &api.Pod{}, c.localNodeSelector(),
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
