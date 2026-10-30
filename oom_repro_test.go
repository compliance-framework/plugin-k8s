//go:build oomrepro

package main

// Reproduces the OOM reported in issue #33: a fleet of realistic-sized resources is fed
// through the real Eval loop and the real policy evaluator, and a heap profile is written
// at each evidence flush, where the batch is at its largest.
//
//	REPRO_BUNDLE=../_ref/plugin-k8s-opres-policies/policies REPRO_OUT=/tmp/oom \
//	  go test -tags oomrepro -run TestOOMRepro -v -timeout 60m .
//
// Size knobs (per cluster): REPRO_PODS (1500), REPRO_NODES (60), REPRO_DEPLOYMENTS (150).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/plugin-k8s/auth"
	"github.com/hashicorp/go-hclog"
)

type syntheticCollector struct {
	pods, nodes, deployments int
}

func (s *syntheticCollector) Collect(ctx context.Context, cluster auth.ClusterConfig, resources []string, nsInclude, nsExclude []string) (*ClusterResources, error) {
	zones := []string{cluster.Region + "a", cluster.Region + "b", cluster.Region + "c"}

	nodes := make([]map[string]interface{}, 0, s.nodes)
	for i := 0; i < s.nodes; i++ {
		nodes = append(nodes, syntheticNode(fmt.Sprintf("ip-10-0-%d-%d.%s.compute.internal", i/250, i%250, cluster.Region), cluster.Region, zones[i%len(zones)]))
	}

	deployments := make([]map[string]interface{}, 0, s.deployments)
	for i := 0; i < s.deployments; i++ {
		deployments = append(deployments, syntheticDeployment(fmt.Sprintf("app-%d", i), fmt.Sprintf("team-%d", i%20)))
	}

	pods := make([]map[string]interface{}, 0, s.pods)
	for i := 0; i < s.pods; i++ {
		d := i % s.deployments
		pods = append(pods, syntheticPod(fmt.Sprintf("app-%d-7d9f8c6b5-%05d", d, i), fmt.Sprintf("team-%d", d%20), fmt.Sprintf("app-%d", d), nodes[i%s.nodes]["metadata"].(map[string]interface{})["name"].(string)))
	}

	return &ClusterResources{
		Name:   cluster.Name,
		Region: cluster.Region,
		Resources: map[string][]map[string]interface{}{
			"nodes":       nodes,
			"pods":        pods,
			"deployments": deployments,
		},
	}, nil
}

// managedFields entries are where most of a real object's bytes go; mimic their nesting.
func syntheticManagedFields(managers ...string) []interface{} {
	out := make([]interface{}, 0, len(managers))
	for _, m := range managers {
		fields := map[string]interface{}{}
		for i := 0; i < 25; i++ {
			fields[fmt.Sprintf("f:field%02d", i)] = map[string]interface{}{
				".": map[string]interface{}{},
				"f:nested": map[string]interface{}{
					"f:a": map[string]interface{}{}, "f:b": map[string]interface{}{}, "f:c": map[string]interface{}{},
				},
			}
		}
		out = append(out, map[string]interface{}{
			"manager": m, "operation": "Update", "apiVersion": "v1",
			"time": "2026-10-01T06:00:00Z", "fieldsType": "FieldsV1", "fieldsV1": fields,
		})
	}
	return out
}

func syntheticContainer(name string) map[string]interface{} {
	env := make([]interface{}, 0, 15)
	for i := 0; i < 15; i++ {
		env = append(env, map[string]interface{}{"name": fmt.Sprintf("ENV_VAR_%02d", i), "value": strings.Repeat("v", 24)})
	}
	return map[string]interface{}{
		"name":  name,
		"image": "123456789012.dkr.ecr.eu-west-1.amazonaws.com/" + name + ":1.2.3",
		"env":   env,
		"ports": []interface{}{map[string]interface{}{"containerPort": int64(8080), "protocol": "TCP"}},
		"resources": map[string]interface{}{
			"limits":   map[string]interface{}{"cpu": "500m", "memory": "512Mi"},
			"requests": map[string]interface{}{"cpu": "100m", "memory": "128Mi"},
		},
		"volumeMounts": []interface{}{
			map[string]interface{}{"name": "kube-api-access", "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount", "readOnly": true},
		},
	}
}

func syntheticPod(name, namespace, app, nodeName string) map[string]interface{} {
	labels := map[string]interface{}{"app.kubernetes.io/name": app, "pod-template-hash": "7d9f8c6b5"}
	return map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]interface{}{
			"name": name, "namespace": namespace, "uid": "6f1c2a7e-0000-4000-8000-" + fmt.Sprintf("%012d", len(name)),
			"labels":        labels,
			"annotations":   map[string]interface{}{"kubectl.kubernetes.io/restartedAt": "2026-10-01T06:00:00Z"},
			"managedFields": syntheticManagedFields("kube-controller-manager", "kubelet"),
		},
		"spec": map[string]interface{}{
			"nodeName":   nodeName,
			"containers": []interface{}{syntheticContainer(app), syntheticContainer("sidecar")},
		},
		"status": map[string]interface{}{
			"phase": "Running",
			"conditions": []interface{}{
				map[string]interface{}{"type": "Ready", "status": "True"},
				map[string]interface{}{"type": "PodScheduled", "status": "True"},
			},
		},
	}
}

func syntheticDeployment(name, namespace string) map[string]interface{} {
	match := map[string]interface{}{"app.kubernetes.io/name": name}
	spec := map[string]interface{}{"containers": []interface{}{syntheticContainer(name), syntheticContainer("sidecar")}}
	lastApplied, _ := json.Marshal(map[string]interface{}{"spec": spec})
	return map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]interface{}{
			"name": name, "namespace": namespace,
			"labels":        match,
			"annotations":   map[string]interface{}{"kubectl.kubernetes.io/last-applied-configuration": string(lastApplied)},
			"managedFields": syntheticManagedFields("kubectl-client-side-apply", "kube-controller-manager"),
		},
		"spec": map[string]interface{}{
			"replicas": int64(3),
			"selector": map[string]interface{}{"matchLabels": match},
			"template": map[string]interface{}{"metadata": map[string]interface{}{"labels": match}, "spec": spec},
		},
	}
}

func syntheticNode(name, region, zone string) map[string]interface{} {
	images := make([]interface{}, 0, 60)
	for i := 0; i < 60; i++ {
		images = append(images, map[string]interface{}{
			"names": []interface{}{
				fmt.Sprintf("123456789012.dkr.ecr.eu-west-1.amazonaws.com/image-%02d@sha256:%064d", i, i),
				fmt.Sprintf("123456789012.dkr.ecr.eu-west-1.amazonaws.com/image-%02d:1.2.%d", i, i),
			},
			"sizeBytes": int64(100000000 + i),
		})
	}
	return map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Node",
		"metadata": map[string]interface{}{
			"name": name,
			"labels": map[string]interface{}{
				"topology.kubernetes.io/zone": zone, "topology.kubernetes.io/region": region,
				"kubernetes.io/hostname": name, "node.kubernetes.io/instance-type": "m6i.2xlarge",
			},
			"managedFields": syntheticManagedFields("kubelet", "kube-controller-manager", "aws-node"),
		},
		"status": map[string]interface{}{"images": images},
	}
}

// profilingAPIHelper records the heap at every flush and keeps nothing, so the only live
// evidence is whatever Eval itself is still holding.
type profilingAPIHelper struct {
	t      *testing.T
	outDir string
	flush  int
}

func (h *profilingAPIHelper) CreateEvidence(ctx context.Context, evidence []*proto.Evidence) error {
	h.flush++

	seen := map[*proto.PolicyEvaluation]bool{}
	var inputBytes int
	for _, e := range evidence {
		if ev := e.GetPolicyEvaluation(); ev != nil && !seen[ev] {
			seen[ev] = true
			inputBytes += len(ev.GetInput()) + len(ev.GetPolicyData())
		}
	}

	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	h.t.Logf("flush %d: %d evidences, %d distinct evaluations, %s of input JSON, live heap after GC %s, total heap obtained from OS %s",
		h.flush, len(evidence), len(seen), mib(inputBytes), mib(int(ms.HeapAlloc)), mib(int(ms.HeapSys)))

	f, err := os.Create(filepath.Join(h.outDir, fmt.Sprintf("heap-flush-%02d.pprof", h.flush)))
	if err != nil {
		return err
	}
	defer f.Close()
	return pprof.WriteHeapProfile(f)
}

func (h *profilingAPIHelper) UpsertSubjectTemplates(ctx context.Context, templates []*proto.SubjectTemplate) error {
	return nil
}

func (h *profilingAPIHelper) UpsertRiskTemplates(ctx context.Context, packageName string, templates []*proto.RiskTemplate) error {
	return nil
}

func mib(n int) string { return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20)) }

func envInt(t *testing.T, key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		t.Fatalf("%s: %v", key, err)
	}
	return n
}

func TestOOMRepro(t *testing.T) {
	bundle := os.Getenv("REPRO_BUNDLE")
	if bundle == "" {
		t.Fatal("REPRO_BUNDLE must point at the policy bundle directory")
	}
	outDir := os.Getenv("REPRO_OUT")
	if outDir == "" {
		outDir = t.TempDir()
	}

	collector := &syntheticCollector{
		pods:        envInt(t, "REPRO_PODS", 1500),
		nodes:       envInt(t, "REPRO_NODES", 60),
		deployments: envInt(t, "REPRO_DEPLOYMENTS", 150),
	}

	// Same logger setup as main(): Trace level, JSON. Output is discarded but still formatted.
	logger := hclog.New(&hclog.LoggerOptions{Level: hclog.Trace, JSONFormat: true, Output: io.Discard})

	plugin := &Plugin{Logger: logger, collector: collector}
	_, err := plugin.Configure(&proto.ConfigureRequest{Config: map[string]string{
		"clusters":       `[{"name":"eks-eu-west-1-tooling-test","region":"eu-west-1","cluster_name":"tooling"},{"name":"eks-eu-west-1-pre-dev-test","region":"eu-west-1","cluster_name":"pre-dev"}]`,
		"resources":      `["nodes","pods","deployments"]`,
		"main_resources": `["deployments"]`,
		"policy_input":   `{"min_azs": 1, "min_regions": 1}`,
	}})
	if err != nil {
		t.Fatal(err)
	}

	// Size of one Rego input, for comparison with the per-flush numbers.
	sample, _ := collector.Collect(context.Background(), plugin.parsedConfig.Clusters[0], nil, nil, nil)
	sampleJSON, _ := json.Marshal(sample.Resources)
	t.Logf("one cluster's resources as JSON: %s (each input carries this cluster twice plus the other cluster, ~3x)", mib(len(sampleJSON)))

	start := time.Now()
	resp, err := plugin.Eval(&proto.EvalRequest{PolicyPaths: []string{bundle}}, &profilingAPIHelper{t: t, outDir: outDir})
	if err != nil {
		t.Fatalf("eval failed: %v", err)
	}

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	t.Logf("eval %s in %s; peak heap obtained from OS %s; profiles in %s", resp.GetStatus(), time.Since(start).Round(time.Second), mib(int(ms.HeapSys)), outDir)
}
