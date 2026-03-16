package kubeconfig

import (
	"context"
	"fmt"

	"github.com/compliance-framework/plugin-k8s/auth"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Provider builds a rest.Config from a kubeconfig file and context.
// This supports local clusters (kind, minikube, k3s) and any provider with a kubeconfig.
type Provider struct{}

// BuildRESTConfig loads a rest.Config from the kubeconfig specified in the cluster config.
func (p *Provider) BuildRESTConfig(_ context.Context, cluster auth.ClusterConfig) (*rest.Config, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if cluster.Kubeconfig != "" {
		rules.ExplicitPath = cluster.Kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{}
	if cluster.Context != "" {
		overrides.CurrentContext = cluster.Context
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to build kubeconfig for cluster %q: %w", cluster.Name, err)
	}
	return cfg, nil
}
