package main

import (
	"strings"
	"testing"
)

func TestPluginConfigParse(t *testing.T) {
	validClusters := `[{"name":"prod","region":"us-east-1","cluster_name":"my-eks"}]`
	validResources := `["nodes"]`

	t.Run("minimal valid config", func(t *testing.T) {
		cfg := &PluginConfig{
			Clusters:  validClusters,
			Resources: validResources,
		}
		parsed, err := cfg.Parse()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(parsed.Clusters) != 1 {
			t.Fatalf("expected 1 cluster, got %d", len(parsed.Clusters))
		}
		if parsed.Clusters[0].Name != "prod" {
			t.Fatalf("expected cluster name prod, got %s", parsed.Clusters[0].Name)
		}
		if len(parsed.Resources) != 1 || parsed.Resources[0] != "nodes" {
			t.Fatalf("unexpected resources: %v", parsed.Resources)
		}
		if len(parsed.MainResources) != 1 || parsed.MainResources[0] != "nodes" {
			t.Fatalf("expected main_resources to default to resources, got %v", parsed.MainResources)
		}
		if got := parsed.IdentityLabels["app_name"]; len(got) == 0 || got[0] != "app.kubernetes.io/name" {
			t.Fatalf("expected default identity_labels, got %v", parsed.IdentityLabels)
		}
		if len(parsed.PolicyLabels) != 0 {
			t.Fatalf("expected empty policy labels")
		}
		if len(parsed.PolicyInput) != 0 {
			t.Fatalf("expected empty policy input")
		}
	})

	t.Run("full config with all optional fields", func(t *testing.T) {
		cfg := &PluginConfig{
			Clusters:         `[{"name":"prod","region":"us-east-1","cluster_name":"my-eks","role_arn":"arn:aws:iam::role/read"}]`,
			Resources:        `["nodes","pods"]`,
			NamespaceInclude: `["app-ns"]`,
			NamespaceExclude: `["kube-system"]`,
			PolicyLabels:     `{"provider":"aws"}`,
			PolicyInput:      `{"min_azs":3}`,
		}
		parsed, err := cfg.Parse()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(parsed.Clusters) != 1 {
			t.Fatalf("expected 1 cluster")
		}
		if parsed.Clusters[0].RoleARN != "arn:aws:iam::role/read" {
			t.Fatalf("expected role_arn to be set")
		}
		if len(parsed.Resources) != 2 {
			t.Fatalf("expected 2 resources")
		}
		if len(parsed.NamespaceInclude) != 1 || parsed.NamespaceInclude[0] != "app-ns" {
			t.Fatalf("unexpected namespace include: %v", parsed.NamespaceInclude)
		}
		if len(parsed.NamespaceExclude) != 1 || parsed.NamespaceExclude[0] != "kube-system" {
			t.Fatalf("unexpected namespace exclude: %v", parsed.NamespaceExclude)
		}
		if parsed.PolicyLabels["provider"] != "aws" {
			t.Fatalf("unexpected policy labels: %v", parsed.PolicyLabels)
		}
		minAZs, ok := parsed.PolicyInput["min_azs"].(float64)
		if !ok || minAZs != 3 {
			t.Fatalf("unexpected policy input min_azs: %v", parsed.PolicyInput["min_azs"])
		}
	})

	t.Run("missing clusters", func(t *testing.T) {
		_, err := (&PluginConfig{Resources: validResources}).Parse()
		if err == nil || !strings.Contains(err.Error(), "clusters is required") {
			t.Fatalf("expected clusters required error, got: %v", err)
		}
	})

	t.Run("missing resources", func(t *testing.T) {
		_, err := (&PluginConfig{Clusters: validClusters}).Parse()
		if err == nil || !strings.Contains(err.Error(), "resources is required") {
			t.Fatalf("expected resources required error, got: %v", err)
		}
	})

	t.Run("invalid clusters JSON", func(t *testing.T) {
		_, err := (&PluginConfig{Clusters: "{bad", Resources: validResources}).Parse()
		if err == nil || !strings.Contains(err.Error(), "could not parse clusters") {
			t.Fatalf("expected parse error, got: %v", err)
		}
	})

	t.Run("empty clusters array", func(t *testing.T) {
		_, err := (&PluginConfig{Clusters: "[]", Resources: validResources}).Parse()
		if err == nil || !strings.Contains(err.Error(), "must not be empty") {
			t.Fatalf("expected empty error, got: %v", err)
		}
	})

	t.Run("cluster missing name", func(t *testing.T) {
		_, err := (&PluginConfig{
			Clusters:  `[{"region":"us-east-1","cluster_name":"x"}]`,
			Resources: validResources,
		}).Parse()
		if err == nil || !strings.Contains(err.Error(), "missing required name") {
			t.Fatalf("expected missing name error, got: %v", err)
		}
	})

	t.Run("cluster missing region", func(t *testing.T) {
		_, err := (&PluginConfig{
			Clusters:  `[{"name":"prod","cluster_name":"x"}]`,
			Resources: validResources,
		}).Parse()
		if err == nil || !strings.Contains(err.Error(), "missing required region") {
			t.Fatalf("expected missing region error, got: %v", err)
		}
	})

	t.Run("cluster missing cluster_name", func(t *testing.T) {
		_, err := (&PluginConfig{
			Clusters:  `[{"name":"prod","region":"us-east-1"}]`,
			Resources: validResources,
		}).Parse()
		if err == nil || !strings.Contains(err.Error(), "missing required cluster_name") {
			t.Fatalf("expected missing cluster_name error, got: %v", err)
		}
	})

	t.Run("empty resources array", func(t *testing.T) {
		_, err := (&PluginConfig{Clusters: validClusters, Resources: "[]"}).Parse()
		if err == nil || !strings.Contains(err.Error(), "must not be empty") {
			t.Fatalf("expected empty resources error, got: %v", err)
		}
	})

	t.Run("invalid resources JSON", func(t *testing.T) {
		_, err := (&PluginConfig{Clusters: validClusters, Resources: "bad"}).Parse()
		if err == nil || !strings.Contains(err.Error(), "could not parse resources") {
			t.Fatalf("expected parse error, got: %v", err)
		}
	})

	t.Run("empty resource string in array", func(t *testing.T) {
		_, err := (&PluginConfig{Clusters: validClusters, Resources: `["nodes",""]`}).Parse()
		if err == nil || !strings.Contains(err.Error(), "resource at index 1 is empty") {
			t.Fatalf("expected empty resource error, got: %v", err)
		}
	})

	t.Run("invalid namespace_include JSON", func(t *testing.T) {
		_, err := (&PluginConfig{Clusters: validClusters, Resources: validResources, NamespaceInclude: "bad"}).Parse()
		if err == nil || !strings.Contains(err.Error(), "could not parse namespace_include") {
			t.Fatalf("expected parse error, got: %v", err)
		}
	})

	t.Run("invalid namespace_exclude JSON", func(t *testing.T) {
		_, err := (&PluginConfig{Clusters: validClusters, Resources: validResources, NamespaceExclude: "bad"}).Parse()
		if err == nil || !strings.Contains(err.Error(), "could not parse namespace_exclude") {
			t.Fatalf("expected parse error, got: %v", err)
		}
	})

	t.Run("invalid policy_labels JSON", func(t *testing.T) {
		_, err := (&PluginConfig{Clusters: validClusters, Resources: validResources, PolicyLabels: "{"}).Parse()
		if err == nil || !strings.Contains(err.Error(), "could not parse policy_labels") {
			t.Fatalf("expected parse error, got: %v", err)
		}
	})

	t.Run("invalid policy_input JSON", func(t *testing.T) {
		_, err := (&PluginConfig{Clusters: validClusters, Resources: validResources, PolicyInput: "{"}).Parse()
		if err == nil || !strings.Contains(err.Error(), "could not parse policy_input") {
			t.Fatalf("expected parse error, got: %v", err)
		}
	})

	t.Run("reserved key in policy_input rejected", func(t *testing.T) {
		for _, key := range []string{"schema_version", "source", "main", "subject", "context", "fleet"} {
			_, err := (&PluginConfig{
				Clusters:    validClusters,
				Resources:   validResources,
				PolicyInput: `{"` + key + `":"override"}`,
			}).Parse()
			if err == nil || !strings.Contains(err.Error(), "reserved key") {
				t.Fatalf("expected reserved key error for %q, got: %v", key, err)
			}
		}
	})

	t.Run("non-reserved policy_input keys are allowed", func(t *testing.T) {
		cfg := &PluginConfig{
			Clusters:    validClusters,
			Resources:   validResources,
			PolicyInput: `{"min_azs":3,"custom_field":"value"}`,
		}
		parsed, err := cfg.Parse()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(parsed.PolicyInput) != 2 {
			t.Fatalf("expected 2 policy input keys, got %d", len(parsed.PolicyInput))
		}
	})

	t.Run("kubeconfig provider does not require region or cluster_name", func(t *testing.T) {
		cfg := &PluginConfig{
			Clusters:  `[{"name":"local","provider":"kubeconfig"}]`,
			Resources: validResources,
		}
		parsed, err := cfg.Parse()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if parsed.Clusters[0].EffectiveProvider() != "kubeconfig" {
			t.Fatalf("expected kubeconfig provider")
		}
	})

	t.Run("kubeconfig provider with explicit path and context", func(t *testing.T) {
		cfg := &PluginConfig{
			Clusters:  `[{"name":"local","provider":"kubeconfig","kubeconfig":"/tmp/kube.cfg","context":"kind-test"}]`,
			Resources: validResources,
		}
		parsed, err := cfg.Parse()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if parsed.Clusters[0].Kubeconfig != "/tmp/kube.cfg" {
			t.Fatalf("expected kubeconfig path")
		}
		if parsed.Clusters[0].Context != "kind-test" {
			t.Fatalf("expected context")
		}
	})

	t.Run("unsupported provider rejected", func(t *testing.T) {
		_, err := (&PluginConfig{
			Clusters:  `[{"name":"prod","provider":"gke"}]`,
			Resources: validResources,
		}).Parse()
		if err == nil || !strings.Contains(err.Error(), "unsupported provider") {
			t.Fatalf("expected unsupported provider error, got: %v", err)
		}
	})

	t.Run("main_resources subset defaults to resources", func(t *testing.T) {
		cfg := &PluginConfig{Clusters: validClusters, Resources: `["nodes","pods"]`}
		parsed, err := cfg.Parse()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(parsed.MainResources) != 2 {
			t.Fatalf("expected main_resources to default to resources")
		}
	})

	t.Run("main_resources subset honored", func(t *testing.T) {
		cfg := &PluginConfig{Clusters: validClusters, Resources: `["nodes","pods"]`, MainResources: `["pods"]`}
		parsed, err := cfg.Parse()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(parsed.MainResources) != 1 || parsed.MainResources[0] != "pods" {
			t.Fatalf("expected MainResources=[pods], got %v", parsed.MainResources)
		}
	})

	t.Run("main_resources entry not in resources rejected", func(t *testing.T) {
		_, err := (&PluginConfig{Clusters: validClusters, Resources: `["pods"]`, MainResources: `["nodes"]`}).Parse()
		if err == nil || !strings.Contains(err.Error(), "not present in resources") {
			t.Fatalf("expected not-present error, got: %v", err)
		}
	})

	t.Run("identity_labels parsed", func(t *testing.T) {
		cfg := &PluginConfig{
			Clusters:       validClusters,
			Resources:      validResources,
			IdentityLabels: `{"app_name":["custom-label"],"env":["environment"]}`,
		}
		parsed, err := cfg.Parse()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := parsed.IdentityLabels["app_name"]; len(got) != 1 || got[0] != "custom-label" {
			t.Fatalf("expected app_name=[custom-label], got %v", got)
		}
		if _, ok := parsed.IdentityLabels["env"]; !ok {
			t.Fatalf("expected env identity key")
		}
	})

	t.Run("identity_labels with empty candidate list rejected", func(t *testing.T) {
		_, err := (&PluginConfig{Clusters: validClusters, Resources: validResources, IdentityLabels: `{"app_name":[]}`}).Parse()
		if err == nil || !strings.Contains(err.Error(), "at least one candidate") {
			t.Fatalf("expected at-least-one-candidate error, got: %v", err)
		}
	})

	t.Run("empty provider defaults to eks", func(t *testing.T) {
		cfg := &PluginConfig{
			Clusters:  validClusters,
			Resources: validResources,
		}
		parsed, err := cfg.Parse()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if parsed.Clusters[0].EffectiveProvider() != "eks" {
			t.Fatalf("expected default provider to be eks")
		}
	})
}
