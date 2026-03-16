package auth

import (
	"context"
	"fmt"

	"k8s.io/client-go/rest"
)

// Supported provider types for cluster authentication.
const (
	ProviderEKS        = "eks"
	ProviderKubeconfig = "kubeconfig"
)

// ClusterConfig describes a single Kubernetes cluster to connect to.
// The Provider field determines which authentication method is used.
type ClusterConfig struct {
	Name     string `json:"name"`
	Provider string `json:"provider,omitempty"` // "eks" (default) or "kubeconfig"

	// EKS-specific fields (required when provider is "eks")
	Region      string `json:"region,omitempty"`
	ClusterName string `json:"cluster_name,omitempty"`
	RoleARN     string `json:"role_arn,omitempty"`

	// Kubeconfig-specific fields (used when provider is "kubeconfig")
	Kubeconfig string `json:"kubeconfig,omitempty"` // path to kubeconfig file; empty = default
	Context    string `json:"context,omitempty"`     // kubeconfig context; empty = current-context
}

// EffectiveProvider returns the provider type, defaulting to "eks".
func (c ClusterConfig) EffectiveProvider() string {
	if c.Provider == "" {
		return ProviderEKS
	}
	return c.Provider
}

// AuthProvider builds a rest.Config for a given cluster.
type AuthProvider interface {
	BuildRESTConfig(ctx context.Context, cluster ClusterConfig) (*rest.Config, error)
}

// RegistryAuthProvider routes to the correct AuthProvider based on the cluster's Provider field.
type RegistryAuthProvider struct {
	Providers map[string]AuthProvider
}

// BuildRESTConfig delegates to the appropriate registered provider.
func (r *RegistryAuthProvider) BuildRESTConfig(ctx context.Context, cluster ClusterConfig) (*rest.Config, error) {
	provider, ok := r.Providers[cluster.EffectiveProvider()]
	if !ok {
		return nil, fmt.Errorf("unsupported provider %q for cluster %q", cluster.Provider, cluster.Name)
	}
	return provider.BuildRESTConfig(ctx, cluster)
}
