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
	schemaVersionV2 = "v2"
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
	processor := policyManager.NewPolicyProcessor(
		e.Logger,
		labels,
		subjects,
		components,
		inventory,
		actors,
		activities,
	)
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
		"main_resources", parsed.MainResources,
	)
	return &proto.ConfigureResponse{}, nil
}

// Init registers one SubjectTemplate per configured main resource type and
// extracts RiskTemplates from the supplied policy bundles.
func (p *Plugin) Init(req *proto.InitRequest, apiHelper runner.ApiHelper) (*proto.InitResponse, error) {
	ctx := context.Background()
	if p.parsedConfig == nil {
		return nil, errors.New("plugin not configured")
	}

	templates := buildSubjectTemplates(p.parsedConfig.MainResources)
	p.Logger.Debug("Init: registering subject templates", "count", len(templates))

	return runner.InitWithSubjectsAndRisksFromPolicies(ctx, p.Logger, req, apiHelper, templates)
}

func (p *Plugin) Eval(req *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {
	ctx := context.Background()

	if p.parsedConfig == nil {
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, errors.New("plugin not configured")
	}
	if len(req.GetPolicyPaths()) == 0 {
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, errors.New("no policy paths provided")
	}

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

	clusterByName := map[string]auth.ClusterConfig{}
	for _, cl := range p.parsedConfig.Clusters {
		clusterByName[cl.Name] = cl
	}

	basePolicyLabels := map[string]string{}
	maps.Copy(basePolicyLabels, p.parsedConfig.PolicyLabels)
	basePolicyLabels["source"] = sourcePluginK8s
	basePolicyLabels["tool"] = sourcePluginK8s
	if _, exists := basePolicyLabels["provider"]; !exists {
		basePolicyLabels["provider"] = inferProvider(p.parsedConfig.Clusters)
	}

	actors := defaultActors()
	activities := defaultActivities()

	totalEvaluatorCalls := 0
	successfulPolicyCalls := 0
	var accumulatedErrors error

	fleetContext := buildFleetContext(clusterByName, clusterData)

	for clusterName, cluster := range clusterData {
		cfg, ok := clusterByName[clusterName]
		if !ok {
			cfg = auth.ClusterConfig{Name: clusterName, Region: cluster.Region}
		}

		clusterComponent := buildClusterComponent(cfg)
		clusterInventory := buildClusterInventory(cfg)
		clusterContext := buildClusterContext(cfg, cluster)

		clusterEvidences := make([]*proto.Evidence, 0)

		for _, resourceType := range p.parsedConfig.MainResources {
			items, hasItems := cluster.Resources[resourceType]
			if !hasItems {
				p.Logger.Debug("Eval: no items collected for main_resource", "cluster", clusterName, "resource_type", resourceType)
				continue
			}

			for _, item := range items {
				instance := newResourceInstance(cfg, resourceType, item, p.parsedConfig.IdentityLabels)

				labels := buildInstanceLabels(basePolicyLabels, instance)
				subjects := buildInstanceSubjects(instance, clusterComponent)
				inventoryItems := append([]*proto.InventoryItem{buildInstanceInventory(instance)}, clusterInventory...)
				components := []*proto.Component{clusterComponent}

				regoInput := buildRegoInput(item, buildInputSubject(instance), clusterContext, fleetContext, p.parsedConfig.PolicyInput)

				for _, policyPath := range req.GetPolicyPaths() {
					totalEvaluatorCalls++
					evidences, evalErr := p.evaluator.Generate(
						ctx,
						policyPath,
						labels,
						subjects,
						components,
						inventoryItems,
						actors,
						activities,
						regoInput,
					)
					clusterEvidences = append(clusterEvidences, evidences...)
					if evalErr != nil {
						p.Logger.Warn("Policy evaluation failed", "policy_path", policyPath, "resource", instance.Name, "namespace", instance.Namespace, "cluster", clusterName, "error", evalErr)
						accumulatedErrors = errors.Join(accumulatedErrors, fmt.Errorf("policy %s [%s/%s/%s]: %w", policyPath, clusterName, instance.Namespace, instance.Name, evalErr))
						continue
					}
					successfulPolicyCalls++
				}
			}
		}

		if len(clusterEvidences) > 0 {
			if sendErr := apiHelper.CreateEvidence(ctx, clusterEvidences); sendErr != nil {
				p.Logger.Error("Error creating evidence", "cluster", clusterName, "error", sendErr)
				return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, sendErr
			}
		}
	}

	if totalEvaluatorCalls > 0 && successfulPolicyCalls == 0 {
		if accumulatedErrors == nil {
			accumulatedErrors = errors.New("policy evaluation failed for all paths")
		}
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, accumulatedErrors
	}

	return &proto.EvalResponse{Status: proto.ExecutionStatus_SUCCESS}, nil
}

// resourceInstance is the per-resource state used to build labels, subjects and inventory.
type resourceInstance struct {
	ClusterName    string
	ResourceType   string
	Namespace      string // empty for cluster-scoped
	Name           string
	IdentityLabels map[string]string // derived from metadata.labels via config
}

func newResourceInstance(cluster auth.ClusterConfig, resourceType string, resource map[string]interface{}, identityCfg map[string][]string) *resourceInstance {
	namespace, name := extractResourceIdentity(resource)
	return &resourceInstance{
		ClusterName:    cluster.Name,
		ResourceType:   resourceType,
		Namespace:      namespace,
		Name:           name,
		IdentityLabels: resolveIdentityLabels(resource, identityCfg),
	}
}

// extractResourceIdentity reads metadata.name and metadata.namespace from an unstructured resource.
func extractResourceIdentity(resource map[string]interface{}) (namespace, name string) {
	meta, ok := resource["metadata"].(map[string]interface{})
	if !ok {
		return "", ""
	}
	if n, ok := meta["name"].(string); ok {
		name = n
	}
	if ns, ok := meta["namespace"].(string); ok {
		namespace = ns
	}
	return namespace, name
}

// resolveIdentityLabels resolves each configured identity key by walking the
// candidate list against metadata.labels on the resource; falls back to
// metadata.name when none match. The resolved value may still be empty if
// metadata.name is missing or empty.
func resolveIdentityLabels(resource map[string]interface{}, config map[string][]string) map[string]string {
	resolved := make(map[string]string, len(config))
	var resourceName string
	labelSources := extractLabelSources(resource)

	if meta, ok := resource["metadata"].(map[string]interface{}); ok {
		if n, ok := meta["name"].(string); ok {
			resourceName = n
		}
	}

	for key, candidates := range config {
		value := ""
		for _, candidate := range candidates {
			for _, labels := range labelSources {
				if v, ok := labels[candidate].(string); ok && v != "" {
					value = v
					break
				}
			}
			if value != "" {
				break
			}
		}
		if value == "" {
			value = resourceName
		}
		resolved[key] = value
	}
	return resolved
}

func extractLabelSources(resource map[string]interface{}) []map[string]interface{} {
	labelSources := make([]map[string]interface{}, 0, 3)

	if meta, ok := resource["metadata"].(map[string]interface{}); ok {
		if labels, ok := meta["labels"].(map[string]interface{}); ok {
			labelSources = append(labelSources, labels)
		}
	}

	if spec, ok := resource["spec"].(map[string]interface{}); ok {
		if template, ok := spec["template"].(map[string]interface{}); ok {
			if templateMeta, ok := template["metadata"].(map[string]interface{}); ok {
				if labels, ok := templateMeta["labels"].(map[string]interface{}); ok {
					labelSources = append(labelSources, labels)
				}
			}
		}
		if selector, ok := spec["selector"].(map[string]interface{}); ok {
			if matchLabels, ok := selector["matchLabels"].(map[string]interface{}); ok {
				labelSources = append(labelSources, matchLabels)
			}
		}
	}

	return labelSources
}

// buildInstanceLabels merges base policy labels with per-instance identity labels.
func buildInstanceLabels(base map[string]string, instance *resourceInstance) map[string]string {
	labels := make(map[string]string, len(base)+len(instance.IdentityLabels)+4)
	maps.Copy(labels, base)
	labels["cluster_name"] = instance.ClusterName
	labels["resource_type"] = instance.ResourceType
	labels["name"] = instance.Name
	labels["namespace"] = instance.Namespace
	// Identity labels (e.g. app_name) may override nothing — but a user-provided
	// policy_labels entry for the same key stays authoritative. Merge them LAST
	// only when not already set.
	for k, v := range instance.IdentityLabels {
		if _, exists := labels[k]; !exists {
			labels[k] = v
		}
	}
	return labels
}

// resourceInstanceIdentifier composes the stable subject identifier for a single resource.
func resourceInstanceIdentifier(instance *resourceInstance) string {
	parts := []string{
		"k8s-" + sanitizeIdentifier(instance.ResourceType),
		sanitizeIdentifier(instance.ClusterName),
	}
	if instance.Namespace != "" {
		parts = append(parts, sanitizeIdentifier(instance.Namespace))
	}
	parts = append(parts, sanitizeIdentifier(instance.Name))
	return strings.Join(parts, "/")
}

func buildInstanceSubjects(instance *resourceInstance, clusterComponent *proto.Component) []*proto.Subject {
	return []*proto.Subject{
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			Identifier: resourceInstanceIdentifier(instance),
		},
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			Identifier: clusterComponent.GetIdentifier(),
		},
	}
}

func buildInstanceInventory(instance *resourceInstance) *proto.InventoryItem {
	props := []*proto.Property{
		{Name: "cluster_name", Value: instance.ClusterName},
		{Name: "resource_type", Value: instance.ResourceType},
		{Name: "name", Value: instance.Name},
	}
	if instance.Namespace != "" {
		props = append(props, &proto.Property{Name: "namespace", Value: instance.Namespace})
	}
	for k, v := range instance.IdentityLabels {
		props = append(props, &proto.Property{Name: k, Value: v})
	}

	title := fmt.Sprintf("Kubernetes %s %s", instance.ResourceType, instance.Name)
	if instance.Namespace != "" {
		title = fmt.Sprintf("Kubernetes %s %s/%s", instance.ResourceType, instance.Namespace, instance.Name)
	}

	return &proto.InventoryItem{
		Identifier: resourceInstanceIdentifier(instance),
		Type:       "k8s-" + strings.ToLower(instance.ResourceType),
		Title:      title,
		Props:      props,
	}
}

func buildClusterComponent(cluster auth.ClusterConfig) *proto.Component {
	clusterID := fmt.Sprintf("k8s-cluster/%s", sanitizeIdentifier(cluster.Name))
	return &proto.Component{
		Identifier:  clusterID,
		Type:        "service",
		Title:       fmt.Sprintf("Kubernetes Cluster: %s", cluster.Name),
		Description: fmt.Sprintf("Kubernetes cluster %q in region %s", cluster.ClusterName, cluster.Region),
		Purpose:     "Kubernetes cluster providing resource data for compliance evaluation.",
	}
}

func buildClusterInventory(cluster auth.ClusterConfig) []*proto.InventoryItem {
	clusterID := fmt.Sprintf("k8s-cluster/%s", sanitizeIdentifier(cluster.Name))
	return []*proto.InventoryItem{
		{
			Identifier: clusterID,
			Type:       "k8s-cluster",
			Title:      fmt.Sprintf("Kubernetes Cluster %s", cluster.Name),
			ImplementedComponents: []*proto.InventoryItemImplementedComponent{
				{Identifier: clusterID},
			},
		},
	}
}

func buildInputSubject(instance *resourceInstance) map[string]interface{} {
	identityLabels := make(map[string]interface{}, len(instance.IdentityLabels))
	for k, v := range instance.IdentityLabels {
		identityLabels[k] = v
	}

	subject := map[string]interface{}{
		"cluster_name":    instance.ClusterName,
		"resource_type":   instance.ResourceType,
		"name":            instance.Name,
		"identifier":      resourceInstanceIdentifier(instance),
		"identity_labels": identityLabels,
	}
	if instance.Namespace != "" {
		subject["namespace"] = instance.Namespace
	}
	return subject
}

// buildClusterContext assembles the cluster metadata + raw resource snapshot
// exposed to policies as input.context.
func buildClusterContext(cluster auth.ClusterConfig, data *ClusterResources) map[string]interface{} {
	return map[string]interface{}{
		"cluster": map[string]interface{}{
			"name":     cluster.Name,
			"region":   cluster.Region,
			"provider": cluster.EffectiveProvider(),
		},
		"resources": data.Resources,
	}
}

func buildFleetContext(
	clusterByName map[string]auth.ClusterConfig,
	clusterData map[string]*ClusterResources,
) map[string]interface{} {
	clusters := make(map[string]interface{}, len(clusterData))

	for clusterName, data := range clusterData {
		cfg, ok := clusterByName[clusterName]
		if !ok {
			cfg = auth.ClusterConfig{Name: clusterName, Region: data.Region}
		}

		clusterInfo := map[string]interface{}{
			"name":     cfg.Name,
			"region":   cfg.Region,
			"provider": cfg.EffectiveProvider(),
		}
		clusters[clusterName] = map[string]interface{}{
			"cluster":   clusterInfo,
			"resources": data.Resources,
		}
	}

	return map[string]interface{}{
		"clusters": clusters,
	}
}

// buildRegoInput shapes the per-resource Rego input document.
func buildRegoInput(main map[string]interface{}, subject map[string]interface{}, clusterContext map[string]interface{}, fleet map[string]interface{}, policyInput map[string]interface{}) map[string]interface{} {
	input := map[string]interface{}{
		"schema_version": schemaVersionV2,
		"source":         sourcePluginK8s,
		"main":           main,
		"subject":        subject,
		"context":        clusterContext,
		"fleet":          fleet,
	}
	for k, v := range policyInput {
		input[k] = v
	}
	return input
}

func isClusterScopedResourceType(resourceType string) bool {
	switch normalizeResourceName(resourceType) {
	case "nodes", "namespaces", "persistentvolumes", "clusterroles", "clusterrolebindings", "customresourcedefinitions", "mutatingwebhookconfigurations", "validatingwebhookconfigurations", "storageclasses", "runtimeclasses", "priorityclasses", "csinodes", "volumeattachments":
		return true
	default:
		return false
	}
}

// buildSubjectTemplates produces one SubjectTemplate per main resource type.
// Namespaced types include namespace and app_name in identity; cluster-scoped
// types omit namespace from template identity and rendering. The agent treats
// the configured IdentityLabelKeys as the unique key.
func buildSubjectTemplates(mainResources []string) []*proto.SubjectTemplate {
	templates := make([]*proto.SubjectTemplate, 0, len(mainResources))
	for _, resourceType := range mainResources {
		templateName := "k8s-" + strings.ToLower(resourceType)
		isClusterScoped := isClusterScopedResourceType(resourceType)
		identityKeys := []string{"cluster_name", "namespace", "app_name", "name"}
		labelSchema := []*proto.SubjectLabelSchema{
			{Key: "cluster_name", Description: "Name of the Kubernetes cluster this resource belongs to"},
			{Key: "namespace", Description: "Namespace of the resource (empty for cluster-scoped resources)"},
			{Key: "app_name", Description: "Application name resolved from metadata.labels via identity_labels config, falling back to metadata.name"},
			{Key: "name", Description: "Value of metadata.name on the Kubernetes resource"},
			{Key: "resource_type", Description: "Kubernetes resource type (e.g. pods, nodes, deployments)"},
		}
		titleTemplate := fmt.Sprintf("Kubernetes %s {{ .namespace }}/{{ .name }} in {{ .cluster_name }}", resourceType)
		descriptionTemplate := fmt.Sprintf("Kubernetes %s %s in cluster {{ .cluster_name }} under namespace {{ .namespace }}", resourceType, "{{ .name }}")

		if isClusterScoped {
			identityKeys = []string{"cluster_name", "app_name", "name"}
			labelSchema = []*proto.SubjectLabelSchema{
				{Key: "cluster_name", Description: "Name of the Kubernetes cluster this resource belongs to"},
				{Key: "app_name", Description: "Application name resolved from metadata.labels via identity_labels config, falling back to metadata.name"},
				{Key: "name", Description: "Value of metadata.name on the Kubernetes resource"},
				{Key: "resource_type", Description: "Kubernetes resource type (e.g. pods, nodes, deployments)"},
			}
			titleTemplate = fmt.Sprintf("Kubernetes %s {{ .name }} in {{ .cluster_name }}", resourceType)
			descriptionTemplate = fmt.Sprintf("Kubernetes %s %s in cluster {{ .cluster_name }}", resourceType, "{{ .name }}")
		}

		templates = append(templates, &proto.SubjectTemplate{
			Name:                templateName,
			Type:                proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			TitleTemplate:       titleTemplate,
			DescriptionTemplate: descriptionTemplate,
			PurposeTemplate:     fmt.Sprintf("Individual Kubernetes %s instance evaluated by the Kubernetes plugin.", resourceType),
			IdentityLabelKeys:   identityKeys,
			LabelSchema:         labelSchema,
		})
	}
	return templates
}

func defaultActors() []*proto.OriginActor {
	return []*proto.OriginActor{
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
}

func defaultActivities() []*proto.Activity {
	return []*proto.Activity{
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
				{Title: "Build Rego Input", Description: "Shape per-resource Rego input with main + cluster context."},
				{Title: "Evaluate Policies", Description: "Run policy bundles against each main resource instance."},
			},
		},
	}
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
			"runner": &runner.RunnerV2GRPCPlugin{Impl: plugin},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}
