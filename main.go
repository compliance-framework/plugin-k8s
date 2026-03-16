package main

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/compliance-framework/plugin-k8s/auth"
	"github.com/compliance-framework/plugin-k8s/auth/eks"
	"github.com/compliance-framework/plugin-k8s/auth/kubeconfig"

	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"github.com/mitchellh/mapstructure"
)

const (
	schemaVersionV1 = "v1"
	sourcePluginK8s = "plugin-kubernetes"
)

// PolicyEvaluator wraps OPA policy execution so eval loop behavior can be tested with mocks.
type PolicyEvaluator interface {
	Generate(
		ctx context.Context,
		policyPath string,
		labels map[string]string,
		subjects []*proto.Subject,
		components []*proto.Component,
		inventory []*proto.InventoryItem,
		actors []*proto.OriginActor,
		activities []*proto.Activity,
		data interface{},
	) ([]*proto.Evidence, error)
}

// DefaultPolicyEvaluator uses the agent SDK policy processor.
type DefaultPolicyEvaluator struct {
	Logger hclog.Logger
}

func (e *DefaultPolicyEvaluator) Generate(
	ctx context.Context,
	policyPath string,
	labels map[string]string,
	subjects []*proto.Subject,
	components []*proto.Component,
	inventory []*proto.InventoryItem,
	actors []*proto.OriginActor,
	activities []*proto.Activity,
	data interface{},
) ([]*proto.Evidence, error) {
	e.Logger.Debug("Evaluating OPA policy", "policy_path", policyPath)
	processor := policyManager.NewPolicyProcessor(
		e.Logger,
		labels,
		subjects,
		components,
		inventory,
		actors,
		activities,
	)
	e.Logger.Debug("policy data", "type", fmt.Sprintf("%T", data), "data", data)
	return processor.GenerateResults(ctx, policyPath, data)
}

// Plugin is the CCF plugin for Kubernetes cluster data collection and policy evaluation.
type Plugin struct {
	Logger hclog.Logger

	config       *PluginConfig
	parsedConfig *ParsedConfig

	collector ClusterCollector
	evaluator PolicyEvaluator
}

func (p *Plugin) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	p.Logger.Debug("Received raw plugin configuration", "config_keys", sortedKeys(req.Config))

	config := &PluginConfig{}
	if err := mapstructure.Decode(req.Config, config); err != nil {
		p.Logger.Error("Error decoding config", "error", err)
		return nil, err
	}

	parsed, err := config.Parse()
	if err != nil {
		p.Logger.Error("Error parsing config", "error", err)
		return nil, err
	}

	p.config = config
	p.parsedConfig = parsed

	if p.collector == nil {
		p.collector = &DynamicClusterCollector{
			AuthProvider: &auth.RegistryAuthProvider{
				Providers: map[string]auth.AuthProvider{
					auth.ProviderEKS:        &eks.Provider{},
					auth.ProviderKubeconfig: &kubeconfig.Provider{},
				},
			},
		}
	}
	if p.evaluator == nil {
		p.evaluator = &DefaultPolicyEvaluator{Logger: p.Logger.Named("policy-evaluator")}
	}

	p.Logger.Info("Kubernetes Plugin configured",
		"clusters", len(parsed.Clusters),
		"resources", parsed.Resources,
	)
	return &proto.ConfigureResponse{}, nil
}

func (p *Plugin) Eval(req *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {
	ctx := context.Background()

	if p.parsedConfig == nil {
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, errors.New("plugin not configured")
	}
	if len(req.GetPolicyPaths()) == 0 {
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, errors.New("no policy paths provided")
	}

	// Collect resources from all clusters concurrently.
	clusterData, err := CollectAll(
		ctx,
		p.collector,
		p.parsedConfig.Clusters,
		p.parsedConfig.Resources,
		p.parsedConfig.NamespaceInclude,
		p.parsedConfig.NamespaceExclude,
	)
	if err != nil {
		p.Logger.Error("Collection failed", "error", err)
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, err
	}

	// Build the Rego input document.
	regoInput := buildRegoInput(clusterData, p.parsedConfig.PolicyInput)

	// Build evidence metadata.
	labels := map[string]string{}
	maps.Copy(labels, p.parsedConfig.PolicyLabels)
	labels["source"] = sourcePluginK8s
	labels["tool"] = sourcePluginK8s
	if _, exists := labels["provider"]; !exists {
		labels["provider"] = inferProvider(p.parsedConfig.Clusters)
	}

	actors := []*proto.OriginActor{
		{
			Title: "The Continuous Compliance Framework",
			Type:  "assessment-platform",
			Links: []*proto.Link{
				{
					Href: "https://compliance-framework.github.io/docs/",
					Rel:  policyManager.Pointer("reference"),
					Text: policyManager.Pointer("The Continuous Compliance Framework"),
				},
			},
		},
		{
			Title: "Continuous Compliance Framework - Kubernetes Plugin",
			Type:  "tool",
			Links: []*proto.Link{
				{
					Href: "https://github.com/compliance-framework/plugin-kubernetes",
					Rel:  policyManager.Pointer("reference"),
					Text: policyManager.Pointer("The Continuous Compliance Framework Kubernetes Plugin"),
				},
			},
		},
	}

	var clusterComponents []*proto.Component
	var clusterInventory []*proto.InventoryItem
	var subjects []*proto.Subject

	for _, cl := range p.parsedConfig.Clusters {
		clusterID := fmt.Sprintf("k8s-cluster/%s", sanitizeIdentifier(cl.Name))
		clusterComponents = append(clusterComponents, &proto.Component{
			Identifier:  clusterID,
			Type:        "service",
			Title:       fmt.Sprintf("Kubernetes Cluster: %s", cl.Name),
			Description: fmt.Sprintf("Kubernetes cluster %q in region %s", cl.ClusterName, cl.Region),
			Purpose:     "Kubernetes cluster providing resource data for compliance evaluation.",
		})
		clusterInventory = append(clusterInventory, &proto.InventoryItem{
			Identifier: clusterID,
			Type:       "k8s-cluster",
			Title:      fmt.Sprintf("Kubernetes Cluster %s", cl.Name),
			ImplementedComponents: []*proto.InventoryItemImplementedComponent{
				{Identifier: clusterID},
			},
		})
		subjects = append(subjects, &proto.Subject{
			Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			Identifier: clusterID,
		})
	}

	activities := []*proto.Activity{
		{
			Title: "Collect Kubernetes Cluster Resources",
			Steps: []*proto.Step{
				{Title: "Authenticate", Description: "Authenticate to each Kubernetes cluster using the configured provider."},
				{Title: "Discover Resources", Description: "Resolve resource names to GVRs via the Kubernetes discovery API."},
				{Title: "List Resources", Description: "List resources using the Kubernetes dynamic client with namespace filtering."},
			},
		},
		{
			Title: "Evaluate OPA Policy Bundles",
			Steps: []*proto.Step{
				{Title: "Build Rego Input", Description: "Combine cluster data with user-provided policy input."},
				{Title: "Evaluate Policies", Description: "Run policy bundles against the combined Rego input document."},
			},
		},
	}

	// Evaluate each policy path.
	allEvidences := make([]*proto.Evidence, 0)
	var accumulatedErrors error
	successfulRuns := 0

	for _, policyPath := range req.GetPolicyPaths() {
		evidences, evalErr := p.evaluator.Generate(
			ctx,
			policyPath,
			labels,
			subjects,
			clusterComponents,
			clusterInventory,
			actors,
			activities,
			regoInput,
		)
		allEvidences = append(allEvidences, evidences...)
		if evalErr != nil {
			p.Logger.Warn("Policy evaluation failed", "policy_path", policyPath, "error", evalErr)
			accumulatedErrors = errors.Join(accumulatedErrors, fmt.Errorf("policy %s: %w", policyPath, evalErr))
			continue
		}
		successfulRuns++
	}

	if len(allEvidences) > 0 {
		if err := apiHelper.CreateEvidence(ctx, allEvidences); err != nil {
			p.Logger.Error("Error creating evidence", "error", err)
			return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, err
		}
	}

	if successfulRuns == 0 && len(allEvidences) == 0 {
		if accumulatedErrors == nil {
			accumulatedErrors = errors.New("policy evaluation failed for all paths")
		}
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, accumulatedErrors
	}

	return &proto.EvalResponse{Status: proto.ExecutionStatus_SUCCESS}, nil
}

// buildRegoInput constructs the Rego input document from cluster data and user-provided policy input.
func buildRegoInput(clusters map[string]*ClusterResources, policyInput map[string]interface{}) map[string]interface{} {
	input := map[string]interface{}{
		"schema_version": schemaVersionV1,
		"source":         sourcePluginK8s,
		"clusters":       clusters,
	}
	// Merge user-provided policy_input keys (reserved keys are already rejected at config time).
	for k, v := range policyInput {
		input[k] = v
	}
	return input
}

// inferProvider returns the provider label based on cluster configs.
// If all clusters use the same provider, return that. Otherwise "multi".
func inferProvider(clusters []auth.ClusterConfig) string {
	if len(clusters) == 0 {
		return "kubernetes"
	}
	first := clusters[0].EffectiveProvider()
	for _, cl := range clusters[1:] {
		if cl.EffectiveProvider() != first {
			return "multi"
		}
	}
	switch first {
	case auth.ProviderEKS:
		return "aws"
	case auth.ProviderKubeconfig:
		return "kubernetes"
	default:
		return first
	}
}

func sanitizeIdentifier(in string) string {
	trimmed := strings.TrimSpace(strings.ToLower(in))
	if trimmed == "" {
		return "unknown"
	}
	builder := strings.Builder{}
	prevDash := false
	for _, r := range trimmed {
		isAlphaNum := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if isAlphaNum {
			builder.WriteRune(r)
			prevDash = false
			continue
		}
		if !prevDash {
			builder.WriteRune('-')
			prevDash = true
		}
	}
	out := strings.Trim(builder.String(), "-")
	if out == "" {
		return "unknown"
	}
	return out
}

func sortedKeys(input map[string]string) []string {
	keys := make([]string, 0, len(input))
	for k := range input {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Trace,
		JSONFormat: true,
	})

	plugin := &Plugin{Logger: logger}

	logger.Info("Starting Kubernetes Plugin")
	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: runner.HandshakeConfig,
		Plugins: map[string]goplugin.Plugin{
			"runner": &runner.RunnerGRPCPlugin{Impl: plugin},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}
