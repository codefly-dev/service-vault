package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	agenttesting "github.com/codefly-dev/core/agents/testing"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	builderv0 "github.com/codefly-dev/core/generated/go/codefly/services/builder/v0"
	"github.com/codefly-dev/core/resources"
	"github.com/stretchr/testify/require"
)

func TestDeploymentTemplates(t *testing.T) {
	agenttesting.AssertKustomizeTemplates(t, deploymentFS, nil)
}

func TestDeploymentProfiles(t *testing.T) {
	ctx := context.Background()
	builder := NewBuilder()
	identity := &basev0.ServiceIdentity{
		Workspace: "workspace",
		Module:    "module",
		Name:      "vault",
		Version:   "1.2.3",
	}
	require.NoError(t, builder.HeadlessLoad(ctx, identity))
	builder.Information.Service = resources.ToServiceWithCase(builder.Identity)
	builder.Information.Module = resources.ToModuleWithCase(builder.Identity)
	builder.HttpEndpoint = &basev0.Endpoint{
		Name:    "http",
		Module:  identity.Module,
		Service: identity.Name,
		Api:     "http",
	}
	networkMappings := []*basev0.NetworkMapping{{
		Endpoint: builder.HttpEndpoint,
		Instances: []*basev0.NetworkInstance{{
			Access:   resources.NewPublicNetworkAccess(),
			Hostname: "vault.example.com",
			Host:     "vault.example.com:8200",
			Port:     8200,
			Address:  "https://vault.example.com",
		}},
	}}

	const secret = "must-stay-ephemeral"
	ephemeralDestination := t.TempDir()
	ephemeral, err := builder.Deploy(ctx, deploymentRequest(
		ephemeralDestination,
		builderv0.KubernetesOutputProfile_KUBERNETES_OUTPUT_PROFILE_EPHEMERAL_LOCAL_APPLY_V1,
		networkMappings,
		&basev0.Configuration{
			Origin: "module/vault",
			Infos: []*basev0.ConfigurationInformation{{
				Name: "vault",
				ConfigurationValues: []*basev0.ConfigurationValue{{
					Key:    "VAULT_TOKEN",
					Value:  secret,
					Secret: true,
				}},
			}},
		},
		nil,
	))
	require.NoError(t, err)
	require.Equal(t, builderv0.DeploymentStatus_SUCCESS, ephemeral.GetState().GetState())
	require.Equal(
		t,
		builderv0.KubernetesOutputProfile_KUBERNETES_OUTPUT_PROFILE_EPHEMERAL_LOCAL_APPLY_V1,
		ephemeral.GetDeployment().GetKubernetes().GetProfile(),
	)
	ephemeralTree := readManifestTree(t, ephemeralDestination)
	require.Contains(t, ephemeralTree, "kind: Namespace")
	require.Contains(t, ephemeralTree, "kind: Secret")
	require.Contains(t, ephemeralTree, base64.StdEncoding.EncodeToString([]byte(secret)))
	ephemeralStatefulSet, err := os.ReadFile(filepath.Join(ephemeralDestination, "base", "stateful-set.yaml"))
	require.NoError(t, err)
	require.Contains(t, string(ephemeralStatefulSet), "name: VAULT_DEV_ROOT_TOKEN_ID")
	require.Contains(t, string(ephemeralStatefulSet), "key: CODEFLY__SERVICE_SECRET_CONFIGURATION__MODULE__VAULT__VAULT__TOKEN")

	gitOpsDestination := t.TempDir()
	gitOps, err := builder.Deploy(ctx, deploymentRequest(
		gitOpsDestination,
		builderv0.KubernetesOutputProfile_KUBERNETES_OUTPUT_PROFILE_PROMOTABLE_GITOPS_V1,
		networkMappings,
		nil,
		map[string]*builderv0.KubernetesSecretKeyReference{
			"VAULT_DEV_ROOT_TOKEN_ID": {
				Name: "vault-credentials",
				Key:  "root-token",
			},
		},
	))
	require.NoError(t, err)
	require.Equal(t, builderv0.DeploymentStatus_SUCCESS, gitOps.GetState().GetState())
	output := gitOps.GetDeployment().GetKubernetes()
	require.Equal(t, builderv0.KubernetesOutputProfile_KUBERNETES_OUTPUT_PROFILE_PROMOTABLE_GITOPS_V1, output.GetProfile())
	require.Equal(t, builderv0.KubernetesManifestValidation_STATUS_PASSED, output.GetValidation().GetStaticValidation())
	require.True(t, output.GetValidation().GetPromotable())
	gitOpsTree := readManifestTree(t, gitOpsDestination)
	require.NotContains(t, gitOpsTree, secret)
	require.NotContains(t, gitOpsTree, base64.StdEncoding.EncodeToString([]byte(secret)))
	require.NotContains(t, gitOpsTree, "kind: Namespace")
	require.NotContains(t, gitOpsTree, "kind: Secret")
	require.NotContains(t, gitOpsTree, "\ndata:")
	require.NotContains(t, gitOpsTree, "\nstringData:")
	require.Contains(t, gitOpsTree, "name: VAULT_DEV_ROOT_TOKEN_ID")
	require.Contains(t, gitOpsTree, "name: vault-credentials")
	require.Contains(t, gitOpsTree, "key: root-token")
	require.Contains(t, gitOpsTree, image.FullName())
}

func TestConcurrentEphemeralDeploymentsKeepTokensRequestScoped(t *testing.T) {
	ctx := context.Background()
	builder, networkMappings := deploymentBuilder(t)

	const deploymentCount = 24
	type result struct {
		index    int
		response *builderv0.DeploymentResponse
		err      error
	}
	results := make(chan result, deploymentCount)
	destinations := make([]string, deploymentCount)
	for i := range destinations {
		destinations[i] = t.TempDir()
	}

	start := make(chan struct{})
	var deployments sync.WaitGroup
	deployments.Add(deploymentCount)
	for i := range deploymentCount {
		go func() {
			defer deployments.Done()
			<-start
			token := fmt.Sprintf("request-token-%d", i)
			response, err := builder.Deploy(ctx, deploymentRequest(
				destinations[i],
				builderv0.KubernetesOutputProfile_KUBERNETES_OUTPUT_PROFILE_EPHEMERAL_LOCAL_APPLY_V1,
				networkMappings,
				vaultConfiguration(token),
				nil,
			))
			results <- result{index: i, response: response, err: err}
		}()
	}
	close(start)
	deployments.Wait()
	close(results)

	for deployment := range results {
		require.NoError(t, deployment.err)
		require.Equal(t, builderv0.DeploymentStatus_SUCCESS, deployment.response.GetState().GetState())
		token, err := resources.GetConfigurationValue(ctx, deployment.response.GetConfiguration(), "vault", "token")
		require.NoError(t, err)
		require.Equal(t, fmt.Sprintf("request-token-%d", deployment.index), token)
	}
}

func TestGitOpsDeploymentRequiresVaultTokenReference(t *testing.T) {
	ctx := context.Background()
	builder, networkMappings := deploymentBuilder(t)

	tests := []struct {
		name       string
		references map[string]*builderv0.KubernetesSecretKeyReference
		message    string
	}{
		{
			name:    "missing",
			message: `requires secret reference "VAULT_DEV_ROOT_TOKEN_ID"`,
		},
		{
			name: "misnamed",
			references: map[string]*builderv0.KubernetesSecretKeyReference{
				"VAULT_TOKEN": {
					Name: "vault-credentials",
					Key:  "root-token",
				},
			},
			message: `requires secret reference "VAULT_DEV_ROOT_TOKEN_ID"`,
		},
		{
			name: "optional",
			references: map[string]*builderv0.KubernetesSecretKeyReference{
				"VAULT_DEV_ROOT_TOKEN_ID": {
					Name:     "vault-credentials",
					Key:      "root-token",
					Optional: true,
				},
			},
			message: `secret reference "VAULT_DEV_ROOT_TOKEN_ID" must not be optional`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response, err := builder.Deploy(ctx, deploymentRequest(
				t.TempDir(),
				builderv0.KubernetesOutputProfile_KUBERNETES_OUTPUT_PROFILE_PROMOTABLE_GITOPS_V1,
				networkMappings,
				nil,
				test.references,
			))
			require.NoError(t, err)
			require.Equal(t, builderv0.DeploymentStatus_ERROR, response.GetState().GetState())
			require.Contains(t, response.GetState().GetMessage(), test.message)
		})
	}
}

func deploymentBuilder(t *testing.T) (*Builder, []*basev0.NetworkMapping) {
	t.Helper()
	ctx := context.Background()
	builder := NewBuilder()
	identity := &basev0.ServiceIdentity{
		Workspace: "workspace",
		Module:    "module",
		Name:      "vault",
		Version:   "1.2.3",
	}
	require.NoError(t, builder.HeadlessLoad(ctx, identity))
	builder.Information.Service = resources.ToServiceWithCase(builder.Identity)
	builder.Information.Module = resources.ToModuleWithCase(builder.Identity)
	builder.HttpEndpoint = &basev0.Endpoint{
		Name:    "http",
		Module:  identity.Module,
		Service: identity.Name,
		Api:     "http",
	}
	return builder, []*basev0.NetworkMapping{{
		Endpoint: builder.HttpEndpoint,
		Instances: []*basev0.NetworkInstance{{
			Access:   resources.NewPublicNetworkAccess(),
			Hostname: "vault.example.com",
			Host:     "vault.example.com:8200",
			Port:     8200,
			Address:  "https://vault.example.com",
		}},
	}}
}

func vaultConfiguration(token string) *basev0.Configuration {
	return &basev0.Configuration{
		Origin: "module/vault",
		Infos: []*basev0.ConfigurationInformation{{
			Name: "vault",
			ConfigurationValues: []*basev0.ConfigurationValue{{
				Key:    "VAULT_TOKEN",
				Value:  token,
				Secret: true,
			}},
		}},
	}
}

func deploymentRequest(
	destination string,
	profile builderv0.KubernetesOutputProfile,
	networkMappings []*basev0.NetworkMapping,
	configuration *basev0.Configuration,
	secretReferences map[string]*builderv0.KubernetesSecretKeyReference,
) *builderv0.DeploymentRequest {
	return &builderv0.DeploymentRequest{
		Environment:     &basev0.Environment{Name: "test"},
		NetworkMappings: networkMappings,
		Configuration:   configuration,
		Deployment: &builderv0.Deployment{Kind: &builderv0.Deployment_Kubernetes{
			Kubernetes: &builderv0.KubernetesDeployment{
				Namespace:        "codefly-test",
				Destination:      destination,
				Profile:          profile,
				SecretReferences: secretReferences,
			},
		}},
	}
}

func readManifestTree(t *testing.T, root string) string {
	t.Helper()
	var manifests strings.Builder
	require.NoError(t, filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		manifests.Write(content)
		return nil
	}))
	return manifests.String()
}
