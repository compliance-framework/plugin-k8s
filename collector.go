package main

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/compliance-framework/plugin-k8s/auth"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
)

// ClusterResources holds the collected resources for a single cluster.
type ClusterResources struct {
	Name      string                              `json:"name"`
	Region    string                              `json:"region"`
	Resources map[string][]map[string]interface{} `json:"resources"`
}

// ClusterCollector collects Kubernetes resources from a cluster.
type ClusterCollector interface {
	Collect(ctx context.Context, cluster auth.ClusterConfig, resources []string, nsInclude, nsExclude []string) (*ClusterResources, error)
}

// DynamicClusterCollector uses the Kubernetes dynamic client to collect resources.
type DynamicClusterCollector struct {
	AuthProvider auth.AuthProvider
}

// Collect connects to the cluster, resolves resource names to GVRs, and lists resources.
func (c *DynamicClusterCollector) Collect(ctx context.Context, cluster auth.ClusterConfig, resources []string, nsInclude, nsExclude []string) (*ClusterResources, error) {
	restConfig, err := c.AuthProvider.BuildRESTConfig(ctx, cluster)
	if err != nil {
		return nil, fmt.Errorf("auth failed for cluster %q: %w", cluster.Name, err)
	}

	dynClient, err := dynamic.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic client for cluster %q: %w", cluster.Name, err)
	}

	discoveryClient, err := discovery.NewDiscoveryClientForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create discovery client for cluster %q: %w", cluster.Name, err)
	}

	gvrMap, clusterScoped, err := resolveGVRs(discoveryClient, resources)
	if err != nil {
		return nil, fmt.Errorf("GVR resolution failed for cluster %q: %w", cluster.Name, err)
	}

	result := &ClusterResources{
		Name:      cluster.Name,
		Region:    cluster.Region,
		Resources: make(map[string][]map[string]interface{}),
	}

	excludeSet := toSet(nsExclude)

	for _, resName := range resources {
		gvr, ok := gvrMap[strings.ToLower(resName)]
		if !ok {
			continue
		}

		var items []map[string]interface{}
		var listErr error

		if clusterScoped[strings.ToLower(resName)] {
			items, listErr = listClusterScopedResources(ctx, dynClient, gvr)
		} else {
			namespaces := effectiveNamespaces(nsInclude, nsExclude)
			items, listErr = listNamespacedResources(ctx, dynClient, gvr, namespaces, excludeSet)
		}

		if listErr != nil {
			return nil, fmt.Errorf("failed to list %q in cluster %q: %w", resName, cluster.Name, listErr)
		}
		result.Resources[resName] = items
	}

	return result, nil
}

// resolveGVRs uses the discovery API to map resource names to GVRs.
func resolveGVRs(client discovery.DiscoveryInterface, resourceNames []string) (map[string]schema.GroupVersionResource, map[string]bool, error) {
	_, apiResourceLists, err := client.ServerGroupsAndResources()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to discover server resources: %w", err)
	}

	gvrMap := make(map[string]schema.GroupVersionResource)
	clusterScoped := make(map[string]bool)

	needed := make(map[string]bool, len(resourceNames))
	for _, name := range resourceNames {
		needed[strings.ToLower(name)] = true
	}

	for _, apiResourceList := range apiResourceLists {
		gv, parseErr := schema.ParseGroupVersion(apiResourceList.GroupVersion)
		if parseErr != nil {
			continue
		}
		for _, apiResource := range apiResourceList.APIResources {
			lowName := strings.ToLower(apiResource.Name)
			if !needed[lowName] {
				continue
			}
			// Skip sub-resources like pods/status
			if strings.Contains(apiResource.Name, "/") {
				continue
			}
			existing, exists := gvrMap[lowName]
			// Prefer the core API group (empty group, i.e. v1) over
			// extension APIs (e.g. metrics.k8s.io) that reuse the same
			// resource names such as "nodes" and "pods".
			if !exists || (existing.Group != "" && gv.Group == "") {
				gvrMap[lowName] = gv.WithResource(apiResource.Name)
				clusterScoped[lowName] = !apiResource.Namespaced
			}
		}
	}

	var missing []string
	for _, name := range resourceNames {
		if _, ok := gvrMap[strings.ToLower(name)]; !ok {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return nil, nil, fmt.Errorf("could not resolve resources: %v", missing)
	}

	return gvrMap, clusterScoped, nil
}

// effectiveNamespaces returns the list of namespaces to query.
// If include is set, only those namespaces are used (minus excluded). Otherwise nil means "all".
func effectiveNamespaces(include, exclude []string) []string {
	if len(include) > 0 {
		excludeSet := toSet(exclude)
		var filtered []string
		for _, ns := range include {
			if !excludeSet[ns] {
				filtered = append(filtered, ns)
			}
		}
		return filtered
	}
	return nil
}

func listClusterScopedResources(ctx context.Context, client dynamic.Interface, gvr schema.GroupVersionResource) ([]map[string]interface{}, error) {
	list, err := client.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return unstructuredListToMaps(list), nil
}

func listNamespacedResources(ctx context.Context, client dynamic.Interface, gvr schema.GroupVersionResource, namespaces []string, excludeSet map[string]bool) ([]map[string]interface{}, error) {
	if len(namespaces) > 0 {
		var allItems []map[string]interface{}
		for _, ns := range namespaces {
			list, err := client.Resource(gvr).Namespace(ns).List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, fmt.Errorf("namespace %q: %w", ns, err)
			}
			allItems = append(allItems, unstructuredListToMaps(list)...)
		}
		return allItems, nil
	}

	// No include filter: list all namespaces, then filter out excluded.
	list, err := client.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	if len(excludeSet) == 0 {
		return unstructuredListToMaps(list), nil
	}

	var filtered []map[string]interface{}
	for _, item := range list.Items {
		if !excludeSet[item.GetNamespace()] {
			filtered = append(filtered, item.Object)
		}
	}
	return filtered, nil
}

func unstructuredListToMaps(list *unstructured.UnstructuredList) []map[string]interface{} {
	items := make([]map[string]interface{}, 0, len(list.Items))
	for _, item := range list.Items {
		items = append(items, item.Object)
	}
	return items
}

func toSet(items []string) map[string]bool {
	s := make(map[string]bool, len(items))
	for _, item := range items {
		s[item] = true
	}
	return s
}

// CollectAll collects resources from multiple clusters concurrently.
func CollectAll(ctx context.Context, collector ClusterCollector, clusters []auth.ClusterConfig, resources []string, nsInclude, nsExclude []string) (map[string]*ClusterResources, error) {
	type result struct {
		name string
		data *ClusterResources
		err  error
	}

	results := make(chan result, len(clusters))
	var wg sync.WaitGroup

	for _, cluster := range clusters {
		wg.Add(1)
		go func(cl auth.ClusterConfig) {
			defer wg.Done()
			data, err := collector.Collect(ctx, cl, resources, nsInclude, nsExclude)
			results <- result{name: cl.Name, data: data, err: err}
		}(cluster)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	collected := make(map[string]*ClusterResources)
	var errs []error
	for r := range results {
		if r.err != nil {
			errs = append(errs, fmt.Errorf("cluster %q: %w", r.name, r.err))
			continue
		}
		collected[r.name] = r.data
	}

	if len(errs) > 0 && len(collected) == 0 {
		return nil, fmt.Errorf("all clusters failed: %v", errs)
	}

	return collected, nil
}
