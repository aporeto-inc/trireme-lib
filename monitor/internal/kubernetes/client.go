package kubernetesmonitor

import (
	"fmt"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// NewClient Generate and initialize a Trireme Client object
func NewClient(kubeconfig string, nodename string) (*Client, error) {
	Client := &Client{}
	Client.localNode = nodename

	if err := Client.InitKubernetesClient(kubeconfig); err != nil {
		return nil, fmt.Errorf("Couldn't initialize Kubernetes Client: %v", err)
	}
	return Client, nil
}

// InitKubernetesClient Initialize the Kubernetes client based on the parameter kubeconfig
// if Kubeconfig is empty, try an in-cluster auth.
func (c *Client) InitKubernetesClient(kubeconfig string) error {

	var config *restclient.Config
	var err error

	if kubeconfig == "" {
		// TODO: Explicit InCluster config call.
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return fmt.Errorf("Error Building InCluster config: %v", err)
		}
	} else {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return fmt.Errorf("Error Building config from Kubeconfig: %v", err)
		}
	}

	myClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("Error creating REST Kube Client: %v", err)
	}
	c.kubeClient = myClient
	return nil
}
