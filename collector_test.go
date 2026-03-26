package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/compliance-framework/plugin-k8s/auth"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fakediscovery "k8s.io/client-go/discovery/fake"
	fakedynamic "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

func newFakeDiscovery(resources []*metav1.APIResourceList) *fakediscovery.FakeDiscovery {
	fakeClient := &k8stesting.Fake{}
	fakeClient.Resources = resources
	return &fakediscovery.FakeDiscovery{Fake: fakeClient}
}

func TestResolveGVRs(t *testing.T) {
	apiResources := []*metav1.APIResourceList{
		{
			GroupVersion: "v1",
			APIResources: []metav1.APIResource{
				{Name: "nodes", Namespaced: false, Kind: "Node"},
				{Name: "pods", Namespaced: true, Kind: "Pod"},
				{Name: "pods/status", Namespaced: true, Kind: "Pod"},
				{Name: "services", Namespaced: true, Kind: "Service"},
			},
		},
		{
			GroupVersion: "apps/v1",
			APIResources: []metav1.APIResource{
				{Name: "deployments", Namespaced: true, Kind: "Deployment"},
			},
		},
	}

	disco := newFakeDiscovery(apiResources)

	t.Run("resolves known resources", func(t *testing.T) {
		gvrMap, clusterScoped, err := resolveGVRs(disco, []string{"nodes", "pods"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(gvrMap) != 2 {
			t.Fatalf("expected 2 GVRs, got %d", len(gvrMap))
		}
		nodesGVR := gvrMap["nodes"]
		if nodesGVR.Resource != "nodes" || nodesGVR.Version != "v1" {
			t.Fatalf("unexpected nodes GVR: %v", nodesGVR)
		}
		if !clusterScoped["nodes"] {
			t.Fatalf("expected nodes to be cluster-scoped")
		}
		if clusterScoped["pods"] {
			t.Fatalf("expected pods to be namespaced")
		}
	})

	t.Run("skips sub-resources", func(t *testing.T) {
		gvrMap, _, err := resolveGVRs(disco, []string{"pods"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := gvrMap["pods/status"]; ok {
			t.Fatalf("should not resolve sub-resources")
		}
	})

	t.Run("errors on unknown resource", func(t *testing.T) {
		_, _, err := resolveGVRs(disco, []string{"widgets"})
		if err == nil || !strings.Contains(err.Error(), "could not resolve") {
			t.Fatalf("expected resolve error, got: %v", err)
		}
	})

	t.Run("prefers core API group over extensions", func(t *testing.T) {
		// Simulate metrics.k8s.io appearing before core v1 (as seen on EKS with metrics-server)
		metricsFirst := []*metav1.APIResourceList{
			{
				GroupVersion: "metrics.k8s.io/v1beta1",
				APIResources: []metav1.APIResource{
					{Name: "nodes", Namespaced: false, Kind: "NodeMetrics"},
					{Name: "pods", Namespaced: true, Kind: "PodMetrics"},
				},
			},
			{
				GroupVersion: "v1",
				APIResources: []metav1.APIResource{
					{Name: "nodes", Namespaced: false, Kind: "Node"},
					{Name: "pods", Namespaced: true, Kind: "Pod"},
				},
			},
		}
		metricsFirstDisco := newFakeDiscovery(metricsFirst)
		gvrMap, _, err := resolveGVRs(metricsFirstDisco, []string{"nodes", "pods"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if gvrMap["nodes"].Group != "" {
			t.Fatalf("expected core group for nodes, got %q", gvrMap["nodes"].Group)
		}
		if gvrMap["pods"].Group != "" {
			t.Fatalf("expected core group for pods, got %q", gvrMap["pods"].Group)
		}
	})

	t.Run("case insensitive", func(t *testing.T) {
		gvrMap, _, err := resolveGVRs(disco, []string{"Nodes"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := gvrMap["nodes"]; !ok {
			t.Fatalf("expected case-insensitive resolution")
		}
	})
}

func TestEffectiveNamespaces(t *testing.T) {
	t.Run("no filters returns nil", func(t *testing.T) {
		ns := effectiveNamespaces(nil, nil)
		if ns != nil {
			t.Fatalf("expected nil, got: %v", ns)
		}
	})

	t.Run("include only", func(t *testing.T) {
		ns := effectiveNamespaces([]string{"app", "web"}, nil)
		if len(ns) != 2 {
			t.Fatalf("expected 2 namespaces, got: %v", ns)
		}
	})

	t.Run("include minus exclude", func(t *testing.T) {
		ns := effectiveNamespaces([]string{"app", "kube-system"}, []string{"kube-system"})
		if len(ns) != 1 || ns[0] != "app" {
			t.Fatalf("expected [app], got: %v", ns)
		}
	})

	t.Run("exclude only returns nil (all minus excluded)", func(t *testing.T) {
		ns := effectiveNamespaces(nil, []string{"kube-system"})
		if ns != nil {
			t.Fatalf("expected nil (handled at list time), got: %v", ns)
		}
	})
}

func TestListClusterScopedResources(t *testing.T) {
	gvr := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "nodes"}
	scheme := runtime.NewScheme()
	dynClient := fakedynamic.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{
			gvr: "NodeList",
		},
		&unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "Node",
				"metadata":   map[string]interface{}{"name": "node-1"},
				"spec":       map[string]interface{}{"providerID": "aws:///us-east-1a/i-123"},
			},
		},
	)

	items, err := listClusterScopedResources(context.Background(), dynClient, gvr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	meta, ok := items[0]["metadata"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected metadata map")
	}
	if meta["name"] != "node-1" {
		t.Fatalf("unexpected name: %v", meta["name"])
	}
}

func TestListNamespacedResourcesWithExclude(t *testing.T) {
	gvr := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	scheme := runtime.NewScheme()
	dynClient := fakedynamic.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{
			gvr: "PodList",
		},
		&unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "Pod",
				"metadata":   map[string]interface{}{"name": "app-pod", "namespace": "app-ns"},
			},
		},
		&unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "Pod",
				"metadata":   map[string]interface{}{"name": "system-pod", "namespace": "kube-system"},
			},
		},
	)

	t.Run("no filter lists all", func(t *testing.T) {
		items, err := listNamespacedResources(context.Background(), dynClient, gvr, nil, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(items) != 2 {
			t.Fatalf("expected 2 items, got %d", len(items))
		}
	})

	t.Run("exclude filters out namespaces", func(t *testing.T) {
		items, err := listNamespacedResources(context.Background(), dynClient, gvr, nil, toSet([]string{"kube-system"}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(items) != 1 {
			t.Fatalf("expected 1 item after exclude, got %d", len(items))
		}
	})
}

// fakeCollector implements ClusterCollector for testing.
type fakeCollector struct {
	results map[string]*ClusterResources
	err     error
}

func (f *fakeCollector) Collect(ctx context.Context, cluster auth.ClusterConfig, resources []string, nsInclude, nsExclude []string) (*ClusterResources, error) {
	if f.err != nil {
		return nil, f.err
	}
	if result, ok := f.results[cluster.Name]; ok {
		return result, nil
	}
	return nil, errors.New("cluster not in fake")
}

func TestCollectAll(t *testing.T) {
	t.Run("collects from multiple clusters", func(t *testing.T) {
		collector := &fakeCollector{
			results: map[string]*ClusterResources{
				"prod":    {Name: "prod", Region: "us-east-1", Resources: map[string][]map[string]interface{}{"nodes": {{"name": "n1"}}}},
				"staging": {Name: "staging", Region: "us-west-2", Resources: map[string][]map[string]interface{}{"nodes": {{"name": "n2"}}}},
			},
		}
		clusters := []auth.ClusterConfig{
			{Name: "prod", Region: "us-east-1", ClusterName: "prod-eks"},
			{Name: "staging", Region: "us-west-2", ClusterName: "staging-eks"},
		}
		result, err := CollectAll(context.Background(), collector, clusters, []string{"nodes"}, nil, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result) != 2 {
			t.Fatalf("expected 2 clusters, got %d", len(result))
		}
	})

	t.Run("partial failure still returns successful clusters", func(t *testing.T) {
		collector := &fakeCollector{
			results: map[string]*ClusterResources{
				"prod": {Name: "prod", Region: "us-east-1", Resources: map[string][]map[string]interface{}{"nodes": {}}},
			},
		}
		clusters := []auth.ClusterConfig{
			{Name: "prod", Region: "us-east-1", ClusterName: "prod-eks"},
			{Name: "bad", Region: "us-west-2", ClusterName: "bad-eks"},
		}
		result, err := CollectAll(context.Background(), collector, clusters, []string{"nodes"}, nil, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result) != 1 {
			t.Fatalf("expected 1 successful cluster, got %d", len(result))
		}
	})

	t.Run("all failures returns error", func(t *testing.T) {
		collector := &fakeCollector{err: errors.New("all fail")}
		clusters := []auth.ClusterConfig{
			{Name: "prod", Region: "us-east-1", ClusterName: "prod-eks"},
		}
		_, err := CollectAll(context.Background(), collector, clusters, []string{"nodes"}, nil, nil)
		if err == nil || !strings.Contains(err.Error(), "all clusters failed") {
			t.Fatalf("expected all-clusters-failed error, got: %v", err)
		}
	})
}
