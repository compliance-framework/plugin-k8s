package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/compliance-framework/plugin-k8s/auth"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
)

type evalCapture struct {
	policyPath string
	labels     map[string]string
	subjects   []*proto.Subject
	inventory  []*proto.InventoryItem
	data       interface{}
}

type fakePolicyEvaluator struct {
	calls                 []evalCapture
	failPaths             map[string]bool
	failPathsWithEvidence map[string]bool
}

func (f *fakePolicyEvaluator) Generate(
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
	copiedLabels := map[string]string{}
	for k, v := range labels {
		copiedLabels[k] = v
	}
	f.calls = append(f.calls, evalCapture{
		policyPath: policyPath,
		labels:     copiedLabels,
		subjects:   subjects,
		inventory:  inventory,
		data:       data,
	})

	if f.failPaths != nil && f.failPaths[policyPath] {
		return nil, errors.New("forced evaluator error")
	}
	if f.failPathsWithEvidence != nil && f.failPathsWithEvidence[policyPath] {
		return []*proto.Evidence{{UUID: fmt.Sprintf("ev-%s-%d", policyPath, len(f.calls)), Labels: copiedLabels}}, errors.New("forced evaluator error")
	}
	return []*proto.Evidence{{UUID: fmt.Sprintf("ev-%s-%d", policyPath, len(f.calls)), Labels: copiedLabels}}, nil
}

type fakeAPIHelper struct {
	createCalls      int
	evidence         []*proto.Evidence
	createErr        error
	subjectTemplates []*proto.SubjectTemplate
	riskTemplatesBy  map[string][]*proto.RiskTemplate
}

func (f *fakeAPIHelper) CreateEvidence(ctx context.Context, evidence []*proto.Evidence) error {
	f.createCalls++
	f.evidence = append(f.evidence, evidence...)
	return f.createErr
}

func (f *fakeAPIHelper) UpsertSubjectTemplates(ctx context.Context, templates []*proto.SubjectTemplate) error {
	f.subjectTemplates = append(f.subjectTemplates, templates...)
	return nil
}

func (f *fakeAPIHelper) UpsertRiskTemplates(ctx context.Context, packageName string, templates []*proto.RiskTemplate) error {
	if f.riskTemplatesBy == nil {
		f.riskTemplatesBy = map[string][]*proto.RiskTemplate{}
	}
	f.riskTemplatesBy[packageName] = append(f.riskTemplatesBy[packageName], templates...)
	return nil
}

func newPodItem(name, namespace, appLabel string) map[string]interface{} {
	meta := map[string]interface{}{
		"name":      name,
		"namespace": namespace,
	}
	if appLabel != "" {
		meta["labels"] = map[string]interface{}{"app.kubernetes.io/name": appLabel}
	}
	return map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   meta,
	}
}

func newNodeItem(name string) map[string]interface{} {
	return map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Node",
		"metadata":   map[string]interface{}{"name": name},
	}
}

func TestEvalLoopBehavior(t *testing.T) {
	t.Run("per-resource evaluation emits one evidence per (instance, policy)", func(t *testing.T) {
		collector := &fakeCollector{
			results: map[string]*ClusterResources{
				"prod": {
					Name:   "prod",
					Region: "us-east-1",
					Resources: map[string][]map[string]interface{}{
						"pods":  {newPodItem("api-1", "app", "api"), newPodItem("worker-1", "app", "worker")},
						"nodes": {newNodeItem("node-1")},
					},
				},
			},
		}
		evaluator := &fakePolicyEvaluator{}
		apiHelper := &fakeAPIHelper{}

		plugin := &Plugin{
			Logger: hclog.NewNullLogger(),
			parsedConfig: &ParsedConfig{
				Clusters:       []auth.ClusterConfig{{Name: "prod", Region: "us-east-1", ClusterName: "prod-eks"}},
				Resources:      []string{"pods", "nodes"},
				MainResources:  []string{"pods"},
				IdentityLabels: defaultIdentityLabels,
				PolicyLabels:   map[string]string{"team": "platform"},
				PolicyInput:    map[string]interface{}{"min_replicas": float64(3)},
			},
			collector: collector,
			evaluator: evaluator,
		}

		resp, err := plugin.Eval(&proto.EvalRequest{PolicyPaths: []string{"bundle-a", "bundle-b"}}, apiHelper)
		if err != nil {
			t.Fatalf("unexpected eval error: %v", err)
		}
		if resp.GetStatus() != proto.ExecutionStatus_SUCCESS {
			t.Fatalf("expected success, got %s", resp.GetStatus().String())
		}
		// 2 pods × 2 policies
		if len(evaluator.calls) != 4 {
			t.Fatalf("expected 4 evaluator calls, got %d", len(evaluator.calls))
		}
		if apiHelper.createCalls != 1 {
			t.Fatalf("expected 1 batched CreateEvidence call per cluster, got %d", apiHelper.createCalls)
		}
		if len(apiHelper.evidence) != 4 {
			t.Fatalf("expected 4 evidences, got %d", len(apiHelper.evidence))
		}

		// Verify labels and input shape for the first call.
		first := evaluator.calls[0]
		if first.labels["cluster_name"] != "prod" {
			t.Fatalf("expected cluster_name=prod, got %q", first.labels["cluster_name"])
		}
		if first.labels["resource_type"] != "pods" {
			t.Fatalf("expected resource_type=pods, got %q", first.labels["resource_type"])
		}
		if first.labels["namespace"] != "app" {
			t.Fatalf("expected namespace=app, got %q", first.labels["namespace"])
		}
		if first.labels["app_name"] == "" {
			t.Fatalf("expected app_name resolved from label")
		}
		input, ok := first.data.(map[string]interface{})
		if !ok {
			t.Fatalf("expected map input, got %T", first.data)
		}
		if input["schema_version"] != schemaVersionV2 {
			t.Fatalf("expected schema_version v2")
		}
		if _, ok := input["main"].(map[string]interface{}); !ok {
			t.Fatalf("expected input.main to be a map")
		}
		subjectPayload, ok := input["subject"].(map[string]interface{})
		if !ok {
			t.Fatalf("expected input.subject to be a map")
		}
		if subjectPayload["cluster_name"] != "prod" {
			t.Fatalf("expected subject.cluster_name=prod, got %v", subjectPayload["cluster_name"])
		}
		if subjectPayload["resource_type"] != "pods" {
			t.Fatalf("expected subject.resource_type=pods, got %v", subjectPayload["resource_type"])
		}
		ctxPayload, ok := input["context"].(map[string]interface{})
		if !ok {
			t.Fatalf("expected input.context to be a map")
		}
		if _, ok := ctxPayload["cluster"].(map[string]interface{}); !ok {
			t.Fatalf("expected context.cluster map")
		}
		resources, ok := ctxPayload["resources"].(map[string][]map[string]interface{})
		if !ok {
			t.Fatalf("expected context.resources map")
		}
		if len(resources["pods"]) != 2 || len(resources["nodes"]) != 1 {
			t.Fatalf("expected full cluster snapshot in context, got pods=%d nodes=%d", len(resources["pods"]), len(resources["nodes"]))
		}
		fleetPayload, ok := input["fleet"].(map[string]interface{})
		if !ok {
			t.Fatalf("expected input.fleet to be a map")
		}
		fleetClusters, ok := fleetPayload["clusters"].(map[string]interface{})
		if !ok {
			t.Fatalf("expected fleet.clusters map")
		}
		prodCluster, ok := fleetClusters["prod"].(map[string]interface{})
		if !ok {
			t.Fatalf("expected fleet.clusters.prod map")
		}
		prodResources, ok := prodCluster["resources"].(map[string][]map[string]interface{})
		if !ok {
			t.Fatalf("expected fleet cluster resources map")
		}
		if len(prodResources["pods"]) != 2 || len(prodResources["nodes"]) != 1 {
			t.Fatalf("expected fleet cluster snapshot, got pods=%d nodes=%d", len(prodResources["pods"]), len(prodResources["nodes"]))
		}
		if input["min_replicas"].(float64) != 3 {
			t.Fatalf("expected policy_input merged")
		}

		// Each call should have 2 subjects: the resource and the cluster.
		if len(first.subjects) != 2 {
			t.Fatalf("expected 2 subjects per evidence, got %d", len(first.subjects))
		}
		if first.subjects[0].GetType() != proto.SubjectType_SUBJECT_TYPE_COMPONENT {
			t.Fatalf("expected per-resource subject type component, got %v", first.subjects[0].GetType())
		}
	})

	t.Run("cluster-scoped resource has empty namespace label", func(t *testing.T) {
		collector := &fakeCollector{
			results: map[string]*ClusterResources{
				"prod": {
					Name:      "prod",
					Region:    "us-east-1",
					Resources: map[string][]map[string]interface{}{"nodes": {newNodeItem("n1")}},
				},
			},
		}
		evaluator := &fakePolicyEvaluator{}
		plugin := &Plugin{
			Logger: hclog.NewNullLogger(),
			parsedConfig: &ParsedConfig{
				Clusters:       []auth.ClusterConfig{{Name: "prod", Region: "us-east-1", ClusterName: "prod-eks"}},
				Resources:      []string{"nodes"},
				MainResources:  []string{"nodes"},
				IdentityLabels: defaultIdentityLabels,
			},
			collector: collector,
			evaluator: evaluator,
		}
		_, err := plugin.Eval(&proto.EvalRequest{PolicyPaths: []string{"bundle-a"}}, &fakeAPIHelper{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(evaluator.calls) != 1 {
			t.Fatalf("expected 1 call, got %d", len(evaluator.calls))
		}
		if evaluator.calls[0].labels["namespace"] != "" {
			t.Fatalf("cluster-scoped resource should have empty namespace label, got %q", evaluator.calls[0].labels["namespace"])
		}
		// Fallback: app_name should equal the node's name when no label matches.
		if evaluator.calls[0].labels["app_name"] != "n1" {
			t.Fatalf("expected app_name fallback to name 'n1', got %q", evaluator.calls[0].labels["app_name"])
		}
	})

	t.Run("fails when all policy evaluations fail", func(t *testing.T) {
		collector := &fakeCollector{
			results: map[string]*ClusterResources{
				"prod": {
					Name: "prod", Region: "us-east-1",
					Resources: map[string][]map[string]interface{}{"pods": {newPodItem("p1", "app", "api")}},
				},
			},
		}
		evaluator := &fakePolicyEvaluator{failPaths: map[string]bool{"bundle-a": true}}
		apiHelper := &fakeAPIHelper{}

		plugin := &Plugin{
			Logger: hclog.NewNullLogger(),
			parsedConfig: &ParsedConfig{
				Clusters:       []auth.ClusterConfig{{Name: "prod", Region: "us-east-1", ClusterName: "prod-eks"}},
				Resources:      []string{"pods"},
				MainResources:  []string{"pods"},
				IdentityLabels: defaultIdentityLabels,
			},
			collector: collector,
			evaluator: evaluator,
		}

		resp, err := plugin.Eval(&proto.EvalRequest{PolicyPaths: []string{"bundle-a"}}, apiHelper)
		if err == nil {
			t.Fatalf("expected eval failure")
		}
		if resp.GetStatus() != proto.ExecutionStatus_FAILURE {
			t.Fatalf("expected failure status")
		}
		if apiHelper.createCalls != 0 {
			t.Fatalf("expected no CreateEvidence calls, got %d", apiHelper.createCalls)
		}
		if strings.Contains(err.Error(), "prod//") {
			t.Fatalf("expected cluster-scoped resource location without empty namespace, got: %v", err)
		}
	})

	t.Run("does not publish evidence returned alongside evaluator errors", func(t *testing.T) {
		collector := &fakeCollector{
			results: map[string]*ClusterResources{
				"prod": {
					Name: "prod", Region: "us-east-1",
					Resources: map[string][]map[string]interface{}{"pods": {newPodItem("p1", "app", "api")}},
				},
			},
		}
		evaluator := &fakePolicyEvaluator{failPathsWithEvidence: map[string]bool{"bundle-a": true}}
		apiHelper := &fakeAPIHelper{}

		plugin := &Plugin{
			Logger: hclog.NewNullLogger(),
			parsedConfig: &ParsedConfig{
				Clusters:       []auth.ClusterConfig{{Name: "prod", Region: "us-east-1", ClusterName: "prod-eks"}},
				Resources:      []string{"pods"},
				MainResources:  []string{"pods"},
				IdentityLabels: defaultIdentityLabels,
			},
			collector: collector,
			evaluator: evaluator,
		}

		resp, err := plugin.Eval(&proto.EvalRequest{PolicyPaths: []string{"bundle-a"}}, apiHelper)
		if err == nil {
			t.Fatalf("expected eval failure")
		}
		if resp.GetStatus() != proto.ExecutionStatus_FAILURE {
			t.Fatalf("expected failure status")
		}
		if apiHelper.createCalls != 0 {
			t.Fatalf("expected no CreateEvidence calls, got %d", apiHelper.createCalls)
		}
		if len(apiHelper.evidence) != 0 {
			t.Fatalf("expected no published evidence, got %d", len(apiHelper.evidence))
		}
	})

	t.Run("flushes evidence incrementally when batch size is exceeded", func(t *testing.T) {
		pods := make([]map[string]interface{}, 0, evidenceBatchSize+5)
		for i := range evidenceBatchSize + 5 {
			pods = append(pods, newPodItem(fmt.Sprintf("pod-%d", i), "app", fmt.Sprintf("app-%d", i)))
		}
		collector := &fakeCollector{
			results: map[string]*ClusterResources{
				"prod": {
					Name: "prod", Region: "us-east-1",
					Resources: map[string][]map[string]interface{}{"pods": pods},
				},
			},
		}
		evaluator := &fakePolicyEvaluator{}
		apiHelper := &fakeAPIHelper{}
		plugin := &Plugin{
			Logger: hclog.NewNullLogger(),
			parsedConfig: &ParsedConfig{
				Clusters:       []auth.ClusterConfig{{Name: "prod", Region: "us-east-1", ClusterName: "prod-eks"}},
				Resources:      []string{"pods"},
				MainResources:  []string{"pods"},
				IdentityLabels: defaultIdentityLabels,
			},
			collector: collector,
			evaluator: evaluator,
		}

		resp, err := plugin.Eval(&proto.EvalRequest{PolicyPaths: []string{"bundle-a"}}, apiHelper)
		if err != nil {
			t.Fatalf("unexpected eval error: %v", err)
		}
		if resp.GetStatus() != proto.ExecutionStatus_SUCCESS {
			t.Fatalf("expected success, got %s", resp.GetStatus().String())
		}
		if apiHelper.createCalls < 2 {
			t.Fatalf("expected multiple CreateEvidence flushes, got %d", apiHelper.createCalls)
		}
		if len(apiHelper.evidence) != evidenceBatchSize+5 {
			t.Fatalf("expected %d evidences, got %d", evidenceBatchSize+5, len(apiHelper.evidence))
		}
	})

	t.Run("collection failure returns error", func(t *testing.T) {
		collector := &fakeCollector{err: errors.New("auth failure")}
		plugin := &Plugin{
			Logger: hclog.NewNullLogger(),
			parsedConfig: &ParsedConfig{
				Clusters:       []auth.ClusterConfig{{Name: "prod", Region: "us-east-1", ClusterName: "prod-eks"}},
				Resources:      []string{"pods"},
				MainResources:  []string{"pods"},
				IdentityLabels: defaultIdentityLabels,
			},
			collector: collector,
			evaluator: &fakePolicyEvaluator{},
		}

		resp, err := plugin.Eval(&proto.EvalRequest{PolicyPaths: []string{"bundle-a"}}, &fakeAPIHelper{})
		if err == nil {
			t.Fatalf("expected collection error")
		}
		if resp.GetStatus() != proto.ExecutionStatus_FAILURE {
			t.Fatalf("expected failure status")
		}
	})

	t.Run("preserves user provider label", func(t *testing.T) {
		collector := &fakeCollector{
			results: map[string]*ClusterResources{
				"prod": {
					Name: "prod", Region: "us-east-1",
					Resources: map[string][]map[string]interface{}{"pods": {newPodItem("p1", "app", "svc")}},
				},
			},
		}
		evaluator := &fakePolicyEvaluator{}
		plugin := &Plugin{
			Logger: hclog.NewNullLogger(),
			parsedConfig: &ParsedConfig{
				Clusters:       []auth.ClusterConfig{{Name: "prod", Region: "us-east-1", ClusterName: "prod-eks"}},
				Resources:      []string{"pods"},
				MainResources:  []string{"pods"},
				IdentityLabels: defaultIdentityLabels,
				PolicyLabels:   map[string]string{"provider": "custom"},
			},
			collector: collector,
			evaluator: evaluator,
		}

		_, err := plugin.Eval(&proto.EvalRequest{PolicyPaths: []string{"bundle-a"}}, &fakeAPIHelper{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if evaluator.calls[0].labels["provider"] != "custom" {
			t.Fatalf("expected provider=custom, got %q", evaluator.calls[0].labels["provider"])
		}
		if evaluator.calls[0].labels["source"] != sourcePluginK8s {
			t.Fatalf("expected source label")
		}
	})

	t.Run("skips main resource types with no collected items", func(t *testing.T) {
		collector := &fakeCollector{
			results: map[string]*ClusterResources{
				"prod": {
					Name: "prod", Region: "us-east-1",
					Resources: map[string][]map[string]interface{}{"pods": {}},
				},
			},
		}
		evaluator := &fakePolicyEvaluator{}
		plugin := &Plugin{
			Logger: hclog.NewNullLogger(),
			parsedConfig: &ParsedConfig{
				Clusters:       []auth.ClusterConfig{{Name: "prod", Region: "us-east-1", ClusterName: "prod-eks"}},
				Resources:      []string{"pods"},
				MainResources:  []string{"pods"},
				IdentityLabels: defaultIdentityLabels,
			},
			collector: collector,
			evaluator: evaluator,
		}
		resp, err := plugin.Eval(&proto.EvalRequest{PolicyPaths: []string{"bundle-a"}}, &fakeAPIHelper{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.GetStatus() != proto.ExecutionStatus_SUCCESS {
			t.Fatalf("expected success when no main resources exist")
		}
		if len(evaluator.calls) != 0 {
			t.Fatalf("expected 0 evaluator calls, got %d", len(evaluator.calls))
		}
	})

	t.Run("not configured returns error", func(t *testing.T) {
		plugin := &Plugin{Logger: hclog.NewNullLogger()}
		resp, err := plugin.Eval(&proto.EvalRequest{PolicyPaths: []string{"bundle-a"}}, &fakeAPIHelper{})
		if err == nil || !strings.Contains(err.Error(), "not configured") {
			t.Fatalf("expected not configured error, got: %v", err)
		}
		if resp.GetStatus() != proto.ExecutionStatus_FAILURE {
			t.Fatalf("expected failure status")
		}
	})

	t.Run("no policy paths returns error", func(t *testing.T) {
		plugin := &Plugin{
			Logger:       hclog.NewNullLogger(),
			parsedConfig: &ParsedConfig{},
		}
		resp, err := plugin.Eval(&proto.EvalRequest{}, &fakeAPIHelper{})
		if err == nil || !strings.Contains(err.Error(), "no policy paths") {
			t.Fatalf("expected no policy paths error, got: %v", err)
		}
		if resp.GetStatus() != proto.ExecutionStatus_FAILURE {
			t.Fatalf("expected failure status")
		}
	})
}

func TestResolveIdentityLabels(t *testing.T) {
	config := map[string][]string{
		"app_name": {"app.kubernetes.io/name", "app"},
		"team":     {"team"},
	}

	t.Run("picks first candidate present", func(t *testing.T) {
		res := map[string]interface{}{
			"metadata": map[string]interface{}{
				"name":   "pod-1",
				"labels": map[string]interface{}{"app.kubernetes.io/name": "api", "app": "legacy"},
			},
		}
		got := resolveIdentityLabels(res, config)
		if got["app_name"] != "api" {
			t.Fatalf("expected app_name=api, got %q", got["app_name"])
		}
		if got["team"] != "pod-1" {
			t.Fatalf("expected team fallback to name, got %q", got["team"])
		}
	})

	t.Run("falls back to second candidate", func(t *testing.T) {
		res := map[string]interface{}{
			"metadata": map[string]interface{}{
				"name":   "pod-1",
				"labels": map[string]interface{}{"app": "legacy"},
			},
		}
		got := resolveIdentityLabels(res, config)
		if got["app_name"] != "legacy" {
			t.Fatalf("expected app_name=legacy, got %q", got["app_name"])
		}
	})

	t.Run("falls back to metadata.name when no labels", func(t *testing.T) {
		res := map[string]interface{}{
			"metadata": map[string]interface{}{"name": "pod-1"},
		}
		got := resolveIdentityLabels(res, config)
		if got["app_name"] != "pod-1" {
			t.Fatalf("expected app_name fallback to name, got %q", got["app_name"])
		}
	})

	t.Run("uses pod template labels for workload resources", func(t *testing.T) {
		res := map[string]interface{}{
			"metadata": map[string]interface{}{"name": "deploy-1"},
			"spec": map[string]interface{}{
				"template": map[string]interface{}{
					"metadata": map[string]interface{}{
						"labels": map[string]interface{}{"app.kubernetes.io/name": "api"},
					},
				},
			},
		}
		got := resolveIdentityLabels(res, config)
		if got["app_name"] != "api" {
			t.Fatalf("expected app_name from pod template labels, got %q", got["app_name"])
		}
	})

	t.Run("handles missing metadata", func(t *testing.T) {
		got := resolveIdentityLabels(map[string]interface{}{}, config)
		if got["app_name"] != "" {
			t.Fatalf("expected empty app_name when no metadata, got %q", got["app_name"])
		}
	})
}

func TestResourceInstanceIdentifier(t *testing.T) {
	tests := []struct {
		name     string
		instance *resourceInstance
		want     string
	}{
		{
			"namespaced",
			&resourceInstance{ClusterName: "prod", ResourceType: "pods", Namespace: "app-ns", Name: "api-1", IdentityLabels: map[string]string{"app_name": "api"}},
			"k8s-pods/prod/app-ns/api/api-1",
		},
		{
			"cluster-scoped omits namespace segment",
			&resourceInstance{ClusterName: "prod", ResourceType: "nodes", Name: "node-1", IdentityLabels: map[string]string{"app_name": "node-1"}},
			"k8s-nodes/prod/node-1/node-1",
		},
		{
			"sanitizes noisy cluster name",
			&resourceInstance{ClusterName: "Prod East", ResourceType: "pods", Namespace: "Default", Name: "API/1", IdentityLabels: map[string]string{"app_name": "Platform API"}},
			"k8s-pods/prod-east/default/platform-api/api-1",
		},
		{
			"falls back to resource name when app_name is empty",
			&resourceInstance{ClusterName: "prod", ResourceType: "pods", Namespace: "app", Name: "api-1", IdentityLabels: map[string]string{"app_name": ""}},
			"k8s-pods/prod/app/api-1/api-1",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := resourceInstanceIdentifier(tc.instance); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestBuildClusterComponent(t *testing.T) {
	t.Run("kubeconfig cluster omits empty region and cluster_name", func(t *testing.T) {
		component := buildClusterComponent(auth.ClusterConfig{Name: "local", Provider: "kubeconfig"})
		if component.GetDescription() != `Kubernetes cluster "local" using provider kubeconfig` {
			t.Fatalf("unexpected description: %q", component.GetDescription())
		}
	})

	t.Run("eks cluster includes provider cluster_name and region", func(t *testing.T) {
		component := buildClusterComponent(auth.ClusterConfig{Name: "prod", Provider: "eks", ClusterName: "prod-eks", Region: "us-east-1"})
		want := `Kubernetes cluster "prod" using provider eks (cluster name "prod-eks") in region us-east-1`
		if component.GetDescription() != want {
			t.Fatalf("unexpected description: %q", component.GetDescription())
		}
	})
}

func TestBuildSubjectTemplates(t *testing.T) {
	templates := buildSubjectTemplates([]string{"pods", "nodes"})
	if len(templates) != 2 {
		t.Fatalf("expected 2 templates, got %d", len(templates))
	}
	byName := map[string]*proto.SubjectTemplate{}
	for _, tpl := range templates {
		byName[tpl.GetName()] = tpl
	}
	if _, ok := byName["k8s-pods"]; !ok {
		t.Fatalf("missing k8s-pods template")
	}
	if _, ok := byName["k8s-nodes"]; !ok {
		t.Fatalf("missing k8s-nodes template")
	}
	if byName["k8s-pods"].GetType() != proto.SubjectType_SUBJECT_TYPE_COMPONENT {
		t.Fatalf("expected k8s-pods template type component, got %v", byName["k8s-pods"].GetType())
	}
	keys := byName["k8s-pods"].GetIdentityLabelKeys()
	wantKeys := []string{"cluster_name", "namespace", "app_name", "name"}
	if len(keys) != len(wantKeys) {
		t.Fatalf("expected identity keys %v, got %v", wantKeys, keys)
	}
	for i := range wantKeys {
		if keys[i] != wantKeys[i] {
			t.Fatalf("expected pod identity keys %v, got %v", wantKeys, keys)
		}
	}
	nodeKeys := byName["k8s-nodes"].GetIdentityLabelKeys()
	wantNodeKeys := []string{"cluster_name", "namespace", "app_name", "name"}
	if len(nodeKeys) != len(wantNodeKeys) {
		t.Fatalf("expected node identity keys %v, got %v", wantNodeKeys, nodeKeys)
	}
	for i := range wantNodeKeys {
		if nodeKeys[i] != wantNodeKeys[i] {
			t.Fatalf("expected node identity keys %v, got %v", wantNodeKeys, nodeKeys)
		}
	}
	if byName["k8s-nodes"].GetTitleTemplate() != "Kubernetes nodes {{ if .namespace }}{{ .namespace }}/{{ end }}{{ .name }} in {{ .cluster_name }}" {
		t.Fatalf("unexpected node title template: %q", byName["k8s-nodes"].GetTitleTemplate())
	}
	if byName["k8s-nodes"].GetDescriptionTemplate() != "Kubernetes nodes {{ .name }} in cluster {{ .cluster_name }}{{ if .namespace }} under namespace {{ .namespace }}{{ end }}" {
		t.Fatalf("unexpected node description template: %q", byName["k8s-nodes"].GetDescriptionTemplate())
	}
}

func TestInitUpsertsSubjectTemplates(t *testing.T) {
	plugin := &Plugin{
		Logger:       hclog.NewNullLogger(),
		parsedConfig: &ParsedConfig{MainResources: []string{"pods", "nodes"}},
	}
	api := &fakeAPIHelper{}
	_, err := plugin.Init(&proto.InitRequest{}, api)
	if err != nil {
		t.Fatalf("unexpected Init error: %v", err)
	}
	if len(api.subjectTemplates) != 2 {
		t.Fatalf("expected 2 subject templates upserted, got %d", len(api.subjectTemplates))
	}
}

func TestInitBeforeConfigureReturnsError(t *testing.T) {
	plugin := &Plugin{Logger: hclog.NewNullLogger()}
	_, err := plugin.Init(&proto.InitRequest{}, &fakeAPIHelper{})
	if err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("expected not configured error, got: %v", err)
	}
}

func TestBuildRegoInput(t *testing.T) {
	main := map[string]interface{}{"metadata": map[string]interface{}{"name": "pod-1", "namespace": "app"}}
	subject := map[string]interface{}{"cluster_name": "prod", "resource_type": "pods", "name": "pod-1"}
	ctxPayload := map[string]interface{}{
		"cluster":   map[string]interface{}{"name": "prod"},
		"resources": map[string][]map[string]interface{}{"nodes": {{"metadata": map[string]interface{}{"name": "n1"}}}},
	}
	fleetPayload := map[string]interface{}{
		"clusters": map[string]interface{}{
			"prod": map[string]interface{}{
				"cluster":   map[string]interface{}{"name": "prod"},
				"resources": map[string][]map[string]interface{}{"nodes": {{"metadata": map[string]interface{}{"name": "n1"}}}},
			},
		},
	}
	userInput := map[string]interface{}{"min_replicas": 3}

	input := buildRegoInput(main, subject, ctxPayload, fleetPayload, userInput)

	if input["schema_version"] != schemaVersionV2 {
		t.Fatalf("expected schema_version v2")
	}
	if input["source"] != sourcePluginK8s {
		t.Fatalf("expected source")
	}
	if input["main"] == nil {
		t.Fatalf("expected main populated")
	}
	if input["subject"] == nil {
		t.Fatalf("expected subject populated")
	}
	if input["context"] == nil {
		t.Fatalf("expected context populated")
	}
	if input["fleet"] == nil {
		t.Fatalf("expected fleet populated")
	}
	if input["min_replicas"] != 3 {
		t.Fatalf("expected user policy_input merged")
	}
}

func TestConfigureSuccess(t *testing.T) {
	plugin := &Plugin{Logger: hclog.NewNullLogger()}
	resp, err := plugin.Configure(&proto.ConfigureRequest{Config: map[string]string{
		"clusters":      `[{"name":"prod","region":"us-east-1","cluster_name":"my-eks"}]`,
		"resources":     `["nodes"]`,
		"policy_labels": `{"team":"platform"}`,
	}})
	if err != nil {
		t.Fatalf("unexpected configure error: %v", err)
	}
	if resp == nil {
		t.Fatalf("expected configure response")
	}
	if len(plugin.parsedConfig.Clusters) != 1 {
		t.Fatalf("expected 1 cluster")
	}
	if plugin.parsedConfig.PolicyLabels["team"] != "platform" {
		t.Fatalf("expected parsed policy label")
	}
}

func TestSanitizeIdentifier(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"prod-east", "prod-east"},
		{"Prod East!", "prod-east"},
		{"", "unknown"},
		{"   ", "unknown"},
		{"a--b", "a-b"},
	}
	for _, tt := range tests {
		got := sanitizeIdentifier(tt.in)
		if got != tt.want {
			t.Errorf("sanitizeIdentifier(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
