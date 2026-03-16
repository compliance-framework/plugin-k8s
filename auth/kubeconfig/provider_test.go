package kubeconfig

import (
	"testing"

	"github.com/compliance-framework/plugin-k8s/auth"
)

func TestProviderImplementsInterface(t *testing.T) {
	var _ auth.AuthProvider = (*Provider)(nil)
}
