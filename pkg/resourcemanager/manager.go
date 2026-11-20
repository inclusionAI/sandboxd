// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package resourcemanager

import (
	"fmt"
	"os"
	"strings"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	tokenPath = "/etc/k8s_secrets/token"
	caPath    = "/etc/k8s_secrets/ca.crt"

	ProviderKubernetes   = "kubernetes"
	ProviderCgroup       = "cgroup"
	ProviderOnlineCgroup = "online_cgroup"
)

// ProviderConfig carries provider-specific configuration without coupling the
// common resource socket and refresh loop to a particular policy.
type ProviderConfig struct {
	OnlineConfigPath string
}

type NodeResourceManager interface {
	GetAvailableResource() (int64, int64, error)
	Stop()
}

func buildConfigFromCustomSA() (*rest.Config, error) {
	k8sServiceHost := os.Getenv("KUBERNETES_SERVICE_HOST")
	if k8sServiceHost == "" {
		return nil, fmt.Errorf("need KUBERNETES_SERVICE_HOST")
	}
	k8sServicePort := os.Getenv("KUBERNETES_SERVICE_PORT")
	if k8sServicePort == "" {
		return nil, fmt.Errorf("need KUBERNETES_SERVICE_PORT")
	}

	token, err := os.ReadFile(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read token from %s: %w", tokenPath, err)
	}
	caData, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate from %s: %w", caPath, err)
	}

	return &rest.Config{
		Host:        "https://" + k8sServiceHost + ":" + k8sServicePort,
		BearerToken: strings.TrimSpace(string(token)),
		TLSClientConfig: rest.TLSClientConfig{
			CAData: caData,
		},
		UserAgent: "SandboxdNode",
	}, nil
}

// nodeClient contains the Kubernetes client and the node assigned to this
// sandboxd process.
type nodeClient struct {
	client        *kubernetes.Clientset
	localNodeName string
}

func newNodeK8sClient() (*nodeClient, error) {
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		return nil, fmt.Errorf("need NODE_NAME")
	}
	cfg, err := buildConfigFromCustomSA()
	if err != nil {
		return nil, fmt.Errorf("failed to build client config: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to build client: %w", err)
	}
	return &nodeClient{client: clientset, localNodeName: nodeName}, nil
}

func normalizeProvider(provider string) (string, error) {
	switch normalized := strings.ToLower(strings.TrimSpace(provider)); normalized {
	case "", ProviderKubernetes:
		return ProviderKubernetes, nil
	case ProviderCgroup:
		return ProviderCgroup, nil
	case ProviderOnlineCgroup:
		return ProviderOnlineCgroup, nil
	default:
		return "", fmt.Errorf(
			"unsupported node-resource provider %q (supported: %s, %s, %s)",
			provider,
			ProviderKubernetes,
			ProviderCgroup,
			ProviderOnlineCgroup,
		)
	}
}

// NewNodeResourceManager constructs the configured CPU and memory capacity
// source. Kubernetes remains the default for backward compatibility; cgroup
// is the read-only provider used by standalone deployments; online_cgroup is
// an opt-in cgroup v1 policy for Alibaba Cloud node resources.
func NewNodeResourceManager(
	provider string,
	configs ...ProviderConfig,
) (NodeResourceManager, error) {
	if len(configs) > 1 {
		return nil, fmt.Errorf("at most one node-resource provider config is allowed")
	}
	var providerConfig ProviderConfig
	if len(configs) == 1 {
		providerConfig = configs[0]
	}

	normalized, err := normalizeProvider(provider)
	if err != nil {
		return nil, err
	}
	switch normalized {
	case ProviderCgroup:
		mgr, cgroupErr := newCgroupResourceManager()
		if cgroupErr != nil {
			return nil, fmt.Errorf("failed to create cgroup resource manager: %w", cgroupErr)
		}
		return mgr, nil
	case ProviderOnlineCgroup:
		return newOnlineCgroupResourceManager(providerConfig.OnlineConfigPath)
	}

	mgr, err := newK8sWatchResourceManager()
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes resource manager: %w", err)
	}
	return mgr, nil
}
