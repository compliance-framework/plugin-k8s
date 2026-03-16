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

type fakePolicyEvaluator struct {
	calls      []string
	failPaths  map[string]bool
	labelsSeen []map[string]string
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
	f.calls = append(f.calls, policyPath)
	copiedLabels := map[string]string{}
	for k, v := range labels {
		copiedLabels[k] = v
	}
	f.labelsSeen = append(f.labelsSeen, copiedLabels)

	if f.failPaths != nil && f.failPaths[policyPath] {
		return nil, errors.New("forced evaluator error")
	}
	return []*proto.Evidence{{UUID: fmt.Sprintf("ev-%s", policyPath), Labels: labels}}, nil
}

type fakeAPIHelper struct {
	calls    int
	evidence []*proto.Evidence
	err      error
}

func (f *fakeAPIHelper) CreateEvidence(ctx context.Context, evidence []*proto.Evidence) error {
	f.calls++
	f.evidence = append(f.evidence, evidence...)
	return f.err
}

func TestEvalLoopBehavior(t *testing.T) {
	t.Run("successful collection and evaluation", func(t *testing.T) {
		collector := &fakeCollector{
			results: map[string]*ClusterResources{
				"prod": {
					Name:   "prod",
					Region: "us-east-1",
					Resources: map[string][]map[string]interface{}{
						"nodes": {{"metadata": map[string]interface{}{"name": "node-1"}}},
					},
				},
			},
		}
		evaluator := &fakePolicyEvaluator{}
		apiHelper := &fakeAPIHelper{}

		plugin := &Plugin{
			Logger: hclog.NewNullLogger(),
			parsedConfig: &ParsedConfig{
				Clusters:     []auth.ClusterConfig{{Name: "prod", Region: "us-east-1", ClusterName: "prod-eks"}},
				Resources:    []string{"nodes"},
				PolicyLabels: map[string]string{"team": "platform"},
				PolicyInput:  map[string]interface{}{"expected_azs": []interface{}{"us-east-1a", "us-east-1b", "us-east-1c"}},
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
		if len(evaluator.calls) != 2 {
			t.Fatalf("expected 2 evaluator calls, got %d", len(evaluator.calls))
		}
		if apiHelper.calls != 1 {
			t.Fatalf("expected 1 CreateEvidence call, got %d", apiHelper.calls)
		}
		if len(apiHelper.evidence) != 2 {
			t.Fatalf("expected 2 evidences, got %d", len(apiHelper.evidence))
		}
	})

	t.Run("fails when all policy evaluations fail", func(t *testing.T) {
		collector := &fakeCollector{
			results: map[string]*ClusterResources{
				"prod": {Name: "prod", Region: "us-east-1", Resources: map[string][]map[string]interface{}{"nodes": {}}},
			},
		}
		evaluator := &fakePolicyEvaluator{failPaths: map[string]bool{"bundle-a": true}}
		apiHelper := &fakeAPIHelper{}

		plugin := &Plugin{
			Logger: hclog.NewNullLogger(),
			parsedConfig: &ParsedConfig{
				Clusters:     []auth.ClusterConfig{{Name: "prod", Region: "us-east-1", ClusterName: "prod-eks"}},
				Resources:    []string{"nodes"},
				PolicyLabels: map[string]string{},
				PolicyInput:  map[string]interface{}{},
			},
			collector: collector,
			evaluator: evaluator,
		}

		resp, err := plugin.Eval(&proto.EvalRequest{PolicyPaths: []string{"bundle-a"}}, apiHelper)
		if err == nil {
			t.Fatalf("expected eval failure")
		}
		if resp.GetStatus() != proto.ExecutionStatus_FAILURE {
			t.Fatalf("expected failure status, got %s", resp.GetStatus().String())
		}
		if apiHelper.calls != 0 {
			t.Fatalf("expected no CreateEvidence calls, got %d", apiHelper.calls)
		}
	})

	t.Run("collection failure returns error", func(t *testing.T) {
		collector := &fakeCollector{err: errors.New("auth failure")}
		evaluator := &fakePolicyEvaluator{}
		apiHelper := &fakeAPIHelper{}

		plugin := &Plugin{
			Logger: hclog.NewNullLogger(),
			parsedConfig: &ParsedConfig{
				Clusters:     []auth.ClusterConfig{{Name: "prod", Region: "us-east-1", ClusterName: "prod-eks"}},
				Resources:    []string{"nodes"},
				PolicyLabels: map[string]string{},
				PolicyInput:  map[string]interface{}{},
			},
			collector: collector,
			evaluator: evaluator,
		}

		resp, err := plugin.Eval(&proto.EvalRequest{PolicyPaths: []string{"bundle-a"}}, apiHelper)
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
				"prod": {Name: "prod", Region: "us-east-1", Resources: map[string][]map[string]interface{}{"nodes": {}}},
			},
		}
		evaluator := &fakePolicyEvaluator{}
		apiHelper := &fakeAPIHelper{}

		plugin := &Plugin{
			Logger: hclog.NewNullLogger(),
			parsedConfig: &ParsedConfig{
				Clusters:     []auth.ClusterConfig{{Name: "prod", Region: "us-east-1", ClusterName: "prod-eks"}},
				Resources:    []string{"nodes"},
				PolicyLabels: map[string]string{"provider": "custom"},
				PolicyInput:  map[string]interface{}{},
			},
			collector: collector,
			evaluator: evaluator,
		}

		resp, err := plugin.Eval(&proto.EvalRequest{PolicyPaths: []string{"bundle-a"}}, apiHelper)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.GetStatus() != proto.ExecutionStatus_SUCCESS {
			t.Fatalf("expected success")
		}
		if len(evaluator.labelsSeen) == 0 {
			t.Fatalf("expected labels to be captured")
		}
		if evaluator.labelsSeen[0]["provider"] != "custom" {
			t.Fatalf("expected provider=custom, got: %s", evaluator.labelsSeen[0]["provider"])
		}
		if evaluator.labelsSeen[0]["source"] != sourcePluginK8s {
			t.Fatalf("expected source label")
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

func TestBuildRegoInput(t *testing.T) {
	clusters := map[string]*ClusterResources{
		"prod": {
			Name:   "prod",
			Region: "us-east-1",
			Resources: map[string][]map[string]interface{}{
				"nodes": {{"metadata": map[string]interface{}{"name": "n1"}}},
			},
		},
	}
	policyInput := map[string]interface{}{"expected_azs": []interface{}{"us-east-1a", "us-east-1b", "us-east-1c"}}

	input := buildRegoInput(clusters, policyInput)

	if input["schema_version"] != schemaVersionV1 {
		t.Fatalf("expected schema_version %s", schemaVersionV1)
	}
	if input["source"] != sourcePluginK8s {
		t.Fatalf("expected source %s", sourcePluginK8s)
	}
	azs, ok := input["expected_azs"].([]interface{})
	if !ok || len(azs) != 3 {
		t.Fatalf("expected expected_azs merged from policy_input")
	}
	if _, ok := input["clusters"]; !ok {
		t.Fatalf("expected clusters key")
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
