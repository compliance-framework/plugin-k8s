package auth

import (
	"context"
	"errors"
	"strings"
	"testing"

	"k8s.io/client-go/rest"
)

// fakeAuthProvider implements AuthProvider for testing.
type fakeAuthProvider struct {
	configs map[string]*rest.Config
	err     error
}

func (f *fakeAuthProvider) BuildRESTConfig(_ context.Context, cluster ClusterConfig) (*rest.Config, error) {
	if f.err != nil {
		return nil, f.err
	}
	if cfg, ok := f.configs[cluster.Name]; ok {
		return cfg, nil
	}
	return nil, errors.New("cluster not found in fake")
}

func TestRegistryAuthProvider(t *testing.T) {
	eksProvider := &fakeAuthProvider{
		configs: map[string]*rest.Config{
			"eks-cluster": {Host: "https://eks.example.com", BearerToken: "k8s-aws-v1.token"},
		},
	}
	kubeconfigProvider := &fakeAuthProvider{
		configs: map[string]*rest.Config{
			"local-cluster": {Host: "https://localhost:6443"},
		},
	}
	registry := &RegistryAuthProvider{
		Providers: map[string]AuthProvider{
			ProviderEKS:        eksProvider,
			ProviderKubeconfig: kubeconfigProvider,
		},
	}

	t.Run("routes to EKS for default provider", func(t *testing.T) {
		cfg, err := registry.BuildRESTConfig(context.Background(), ClusterConfig{Name: "eks-cluster"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Host != "https://eks.example.com" {
			t.Fatalf("expected EKS host, got: %s", cfg.Host)
		}
	})

	t.Run("routes to EKS for explicit eks provider", func(t *testing.T) {
		cfg, err := registry.BuildRESTConfig(context.Background(), ClusterConfig{Name: "eks-cluster", Provider: "eks"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Host != "https://eks.example.com" {
			t.Fatalf("expected EKS host, got: %s", cfg.Host)
		}
	})

	t.Run("routes to kubeconfig provider", func(t *testing.T) {
		cfg, err := registry.BuildRESTConfig(context.Background(), ClusterConfig{Name: "local-cluster", Provider: "kubeconfig"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Host != "https://localhost:6443" {
			t.Fatalf("expected local host, got: %s", cfg.Host)
		}
	})

	t.Run("rejects unsupported provider", func(t *testing.T) {
		_, err := registry.BuildRESTConfig(context.Background(), ClusterConfig{Name: "x", Provider: "gke"})
		if err == nil || !strings.Contains(err.Error(), "unsupported provider") {
			t.Fatalf("expected unsupported provider error, got: %v", err)
		}
	})
}
