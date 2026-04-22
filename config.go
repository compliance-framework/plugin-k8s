package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/compliance-framework/plugin-k8s/auth"
)

// reservedInputKeys are top-level keys managed by the plugin that users cannot
// override via policy_input.
var reservedInputKeys = map[string]bool{
	"schema_version": true,
	"source":         true,
	"main":           true,
	"subject":        true,
	"context":        true,
	"fleet":          true,
}

// defaultIdentityLabels is the fallback identity-label config used when the
// user does not supply one. app_name tries the standard Kubernetes recommended
// label first, then the legacy `app` label.
var defaultIdentityLabels = map[string][]string{
	"app_name": {"app.kubernetes.io/name", "app"},
}

// PluginConfig receives string-only config from the agent gRPC interface.
type PluginConfig struct {
	Clusters         string `mapstructure:"clusters"`
	Resources        string `mapstructure:"resources"`
	MainResources    string `mapstructure:"main_resources"`
	IdentityLabels   string `mapstructure:"identity_labels"`
	NamespaceInclude string `mapstructure:"namespace_include"`
	NamespaceExclude string `mapstructure:"namespace_exclude"`
	PolicyLabels     string `mapstructure:"policy_labels"`
	PolicyInput      string `mapstructure:"policy_input"`
}

// ParsedConfig stores normalized and validated values for runtime use.
type ParsedConfig struct {
	Clusters         []auth.ClusterConfig
	Resources        []string
	MainResources    []string
	IdentityLabels   map[string][]string
	NamespaceInclude []string
	NamespaceExclude []string
	PolicyLabels     map[string]string
	PolicyInput      map[string]interface{}
}

// Parse validates and normalizes the raw string config into ParsedConfig.
func (c *PluginConfig) Parse() (*ParsedConfig, error) {
	// --- clusters (required) ---
	clustersStr := strings.TrimSpace(c.Clusters)
	if clustersStr == "" {
		return nil, errors.New("clusters is required")
	}
	var clusters []auth.ClusterConfig
	if err := json.Unmarshal([]byte(clustersStr), &clusters); err != nil {
		return nil, fmt.Errorf("could not parse clusters: %w", err)
	}
	if len(clusters) == 0 {
		return nil, errors.New("clusters must not be empty")
	}
	for i, cl := range clusters {
		if strings.TrimSpace(cl.Name) == "" {
			return nil, fmt.Errorf("cluster at index %d missing required name", i)
		}
		switch cl.EffectiveProvider() {
		case auth.ProviderEKS:
			if strings.TrimSpace(cl.Region) == "" {
				return nil, fmt.Errorf("cluster %q missing required region", cl.Name)
			}
			if strings.TrimSpace(cl.ClusterName) == "" {
				return nil, fmt.Errorf("cluster %q missing required cluster_name", cl.Name)
			}
		case auth.ProviderKubeconfig:
			// kubeconfig and context are optional (defaults to ~/.kube/config and current-context)
		default:
			return nil, fmt.Errorf("cluster %q has unsupported provider %q", cl.Name, cl.Provider)
		}
	}

	// --- resources (required) ---
	resourcesStr := strings.TrimSpace(c.Resources)
	if resourcesStr == "" {
		return nil, errors.New("resources is required")
	}
	var resources []string
	if err := json.Unmarshal([]byte(resourcesStr), &resources); err != nil {
		return nil, fmt.Errorf("could not parse resources: %w", err)
	}
	if len(resources) == 0 {
		return nil, errors.New("resources must not be empty")
	}
	resourceSet := make(map[string]bool, len(resources))
	for i, r := range resources {
		if strings.TrimSpace(r) == "" {
			return nil, fmt.Errorf("resource at index %d is empty", i)
		}
		resourceSet[strings.ToLower(r)] = true
	}

	// --- main_resources (optional; defaults to all resources) ---
	var mainResources []string
	if strings.TrimSpace(c.MainResources) != "" {
		if err := json.Unmarshal([]byte(c.MainResources), &mainResources); err != nil {
			return nil, fmt.Errorf("could not parse main_resources: %w", err)
		}
		for i, r := range mainResources {
			if strings.TrimSpace(r) == "" {
				return nil, fmt.Errorf("main_resources at index %d is empty", i)
			}
			if !resourceSet[strings.ToLower(r)] {
				return nil, fmt.Errorf("main_resources entry %q is not present in resources", r)
			}
		}
	}
	if len(mainResources) == 0 {
		mainResources = append([]string(nil), resources...)
	}

	// --- identity_labels (optional; defaults to defaultIdentityLabels) ---
	identityLabels := map[string][]string{}
	if strings.TrimSpace(c.IdentityLabels) != "" {
		if err := json.Unmarshal([]byte(c.IdentityLabels), &identityLabels); err != nil {
			return nil, fmt.Errorf("could not parse identity_labels: %w", err)
		}
		for key, candidates := range identityLabels {
			if strings.TrimSpace(key) == "" {
				return nil, errors.New("identity_labels contains an empty key")
			}
			if len(candidates) == 0 {
				return nil, fmt.Errorf("identity_labels key %q must have at least one candidate label", key)
			}
			for i, candidate := range candidates {
				if strings.TrimSpace(candidate) == "" {
					return nil, fmt.Errorf("identity_labels key %q has empty candidate at index %d", key, i)
				}
			}
		}
	}
	if len(identityLabels) == 0 {
		identityLabels = make(map[string][]string, len(defaultIdentityLabels))
		for k, v := range defaultIdentityLabels {
			identityLabels[k] = append([]string(nil), v...)
		}
	}

	// --- namespace_include (optional) ---
	var nsInclude []string
	if strings.TrimSpace(c.NamespaceInclude) != "" {
		if err := json.Unmarshal([]byte(c.NamespaceInclude), &nsInclude); err != nil {
			return nil, fmt.Errorf("could not parse namespace_include: %w", err)
		}
	}

	// --- namespace_exclude (optional) ---
	var nsExclude []string
	if strings.TrimSpace(c.NamespaceExclude) != "" {
		if err := json.Unmarshal([]byte(c.NamespaceExclude), &nsExclude); err != nil {
			return nil, fmt.Errorf("could not parse namespace_exclude: %w", err)
		}
	}

	// --- policy_labels (optional) ---
	policyLabels := map[string]string{}
	if strings.TrimSpace(c.PolicyLabels) != "" {
		if err := json.Unmarshal([]byte(c.PolicyLabels), &policyLabels); err != nil {
			return nil, fmt.Errorf("could not parse policy_labels: %w", err)
		}
	}

	// --- policy_input (optional) ---
	policyInput := map[string]interface{}{}
	if strings.TrimSpace(c.PolicyInput) != "" {
		if err := json.Unmarshal([]byte(c.PolicyInput), &policyInput); err != nil {
			return nil, fmt.Errorf("could not parse policy_input: %w", err)
		}
		for key := range policyInput {
			if reservedInputKeys[key] {
				return nil, fmt.Errorf("policy_input must not contain reserved key %q", key)
			}
		}
	}

	return &ParsedConfig{
		Clusters:         clusters,
		Resources:        resources,
		MainResources:    mainResources,
		IdentityLabels:   identityLabels,
		NamespaceInclude: nsInclude,
		NamespaceExclude: nsExclude,
		PolicyLabels:     policyLabels,
		PolicyInput:      policyInput,
	}, nil
}
