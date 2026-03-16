# plugin-kubernetes

A [Continuous Compliance Framework](https://compliance-framework.github.io/docs/) plugin that collects Kubernetes resources and evaluates OPA/Rego policies against them.

Supports multiple authentication methods (EKS via AWS STS, kubeconfig for any cluster) and concurrent multi-cluster collection.

## Plugin Configuration

The plugin receives configuration as flat string fields from the CCF agent. All structured values are JSON-encoded strings.

| Field | Required | Description |
|---|---|---|
| `clusters` | Yes | JSON array of cluster connection configs |
| `resources` | Yes | JSON array of Kubernetes resource types to collect (e.g. `"nodes"`, `"pods"`, `"deployments"`) |
| `namespace_include` | No | JSON array of namespaces to include (empty = all) |
| `namespace_exclude` | No | JSON array of namespaces to exclude |
| `policy_labels` | No | JSON object of key-value labels added to evidence metadata |
| `policy_input` | No | JSON object of custom fields merged into the Rego input document |

### Cluster Configuration

Each entry in `clusters` has:

| Field | Required | Provider | Description |
|---|---|---|---|
| `name` | Yes | all | Unique display name for this cluster |
| `provider` | No | all | `"eks"` (default) or `"kubeconfig"` |
| `region` | Yes | eks | AWS region |
| `cluster_name` | Yes | eks | EKS cluster name |
| `role_arn` | No | eks | IAM role ARN to assume before authenticating |
| `kubeconfig` | No | kubeconfig | Path to kubeconfig file (default: `~/.kube/config`) |
| `context` | No | kubeconfig | Kubeconfig context to use (default: current-context) |

## Configuration Examples

### Single EKS Cluster

```json
{
  "clusters": "[{\"name\":\"prod\",\"region\":\"us-east-1\",\"cluster_name\":\"prod-eks\"}]",
  "resources": "[\"nodes\",\"pods\",\"deployments\"]",
  "namespace_exclude": "[\"kube-system\",\"kube-public\"]",
  "policy_labels": "{\"team\":\"platform\",\"environment\":\"production\"}",
  "policy_input": "{\"expected_azs\":[\"us-east-1a\",\"us-east-1b\",\"us-east-1c\"]}"
}
```

### EKS with Cross-Account Role Assumption

```json
{
  "clusters": "[{\"name\":\"prod\",\"region\":\"us-east-1\",\"cluster_name\":\"prod-eks\",\"role_arn\":\"arn:aws:iam::123456789012:role/eks-readonly\"}]",
  "resources": "[\"nodes\",\"pods\"]",
  "policy_input": "{\"expected_azs\":[\"us-east-1a\",\"us-east-1b\"]}"
}
```

### Local Cluster via Kubeconfig (kind, minikube, k3s)

```json
{
  "clusters": "[{\"name\":\"local-dev\",\"provider\":\"kubeconfig\"}]",
  "resources": "[\"pods\",\"services\",\"deployments\"]",
  "namespace_include": "[\"default\",\"app\"]"
}
```

### Kubeconfig with Explicit Path and Context

```json
{
  "clusters": "[{\"name\":\"staging\",\"provider\":\"kubeconfig\",\"kubeconfig\":\"/etc/kube/staging.yaml\",\"context\":\"staging-admin\"}]",
  "resources": "[\"pods\",\"nodes\",\"networkpolicies\"]"
}
```

### Multi-Cluster (Mixed Providers)

```json
{
  "clusters": "[{\"name\":\"prod-east\",\"region\":\"us-east-1\",\"cluster_name\":\"prod-east-eks\"},{\"name\":\"prod-west\",\"region\":\"us-west-2\",\"cluster_name\":\"prod-west-eks\"},{\"name\":\"dev\",\"provider\":\"kubeconfig\",\"context\":\"kind-dev\"}]",
  "resources": "[\"nodes\",\"pods\"]",
  "namespace_exclude": "[\"kube-system\"]",
  "policy_input": "{\"expected_azs\":[\"us-east-1a\",\"us-east-1b\",\"us-west-2a\",\"us-west-2b\"]}"
}
```

## Policy Input Schema

The plugin builds a Rego input document from collected data and passes it to each policy bundle. Policies access it via `input`.

### Schema

```json
{
  "schema_version": "v1",
  "source": "plugin-kubernetes",
  "clusters": {
    "<cluster-name>": {
      "name": "string",
      "region": "string",
      "resources": {
        "<resource-type>": [
          { "apiVersion": "...", "kind": "...", "metadata": {...}, "spec": {...}, ... }
        ]
      }
    }
  }
}
```

Any fields from `policy_input` config are merged at the top level. Reserved keys (`schema_version`, `source`, `clusters`) cannot be overridden.

### Field Reference

| Path | Type | Source | Description |
|---|---|---|---|
| `input.schema_version` | string | Plugin | Always `"v1"` |
| `input.source` | string | Plugin | Always `"plugin-kubernetes"` |
| `input.clusters` | object | Plugin | Map of cluster name to collected data |
| `input.clusters[name].name` | string | Plugin | Cluster display name |
| `input.clusters[name].region` | string | Plugin | AWS region (empty for kubeconfig clusters) |
| `input.clusters[name].resources` | object | Plugin | Map of resource type to array of Kubernetes objects |
| `input.clusters[name].resources[type][]` | object | Plugin | Full unstructured Kubernetes resource objects |
| `input.<custom_key>` | any | `policy_input` | User-defined fields for policy logic |

### Example: Full Rego Input

Given this config:

```json
{
  "clusters": "[{\"name\":\"prod\",\"region\":\"us-east-1\",\"cluster_name\":\"prod-eks\"}]",
  "resources": "[\"nodes\",\"pods\"]",
  "policy_input": "{\"expected_azs\":[\"us-east-1a\",\"us-east-1b\",\"us-east-1c\"],\"app_label\":\"app.kubernetes.io/name\"}"
}
```

The Rego input document will look like:

```json
{
  "schema_version": "v1",
  "source": "plugin-kubernetes",
  "expected_azs": ["us-east-1a", "us-east-1b", "us-east-1c"],
  "app_label": "app.kubernetes.io/name",
  "clusters": {
    "prod": {
      "name": "prod",
      "region": "us-east-1",
      "resources": {
        "nodes": [
          {
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {
              "name": "ip-10-0-1-100.ec2.internal",
              "labels": {
                "topology.kubernetes.io/zone": "us-east-1a",
                "node.kubernetes.io/instance-type": "m5.xlarge"
              }
            },
            "spec": {
              "providerID": "aws:///us-east-1a/i-0abc123"
            }
          }
        ],
        "pods": [
          {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
              "name": "web-abc123",
              "namespace": "default",
              "labels": {
                "app.kubernetes.io/name": "web"
              }
            },
            "spec": {
              "nodeName": "ip-10-0-1-100.ec2.internal",
              "containers": [
                { "name": "web", "image": "nginx:1.25" }
              ]
            }
          }
        ]
      }
    }
  }
}
```

### Writing Policies Against This Input

Policies are Rego files that produce `violation` and metadata. Example pattern:

```rego
package compliance_framework.my_policy

import rego.v1

# Access custom policy_input fields
_expected_azs := object.get(input, "expected_azs", [])

# Iterate over clusters and their resources
violation contains {"remarks": msg} if {
    some cluster_name, cluster in input.clusters
    some pod in object.get(object.get(cluster, "resources", {}), "pods", [])
    not pod.spec.nodeName
    msg := sprintf("Cluster %q: pod %q has no nodeName assigned", [cluster_name, pod.metadata.name])
}

title := "My Compliance Check"

description := sprintf("Evaluated %d cluster(s)", [count(input.clusters)])
```

Key patterns:
- Use `object.get(obj, key, default)` for safe field access
- Iterate clusters with `some cluster_name, cluster in input.clusters`
- Access resources via `cluster.resources.<type>` (e.g. `cluster.resources.nodes`, `cluster.resources.pods`)
- Custom `policy_input` fields are available directly on `input` (e.g. `input.expected_azs`)
