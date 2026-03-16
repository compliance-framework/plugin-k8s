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
	"clusters":       true,
}

// PluginConfig receives string-only config from the agent gRPC interface.
type PluginConfig struct {
	Clusters         string `mapstructure:"clusters"`
	Resources        string `mapstructure:"resources"`
	NamespaceInclude string `mapstructure:"namespace_include"`
	NamespaceExclude string `mapstructure:"namespace_exclude"`
	PolicyLabels     string `mapstructure:"policy_labels"`
	PolicyInput      string `mapstructure:"policy_input"`
}

// ParsedConfig stores normalized and validated values for runtime use.
type ParsedConfig struct {
	Clusters         []auth.ClusterConfig
	Resources        []string
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
	for i, r := range resources {
		if strings.TrimSpace(r) == "" {
			return nil, fmt.Errorf("resource at index %d is empty", i)
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
		NamespaceInclude: nsInclude,
		NamespaceExclude: nsExclude,
		PolicyLabels:     policyLabels,
		PolicyInput:      policyInput,
	}, nil
}
