package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
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
	// A visibility: module endpoint has no DNS, so the remote network manager
	// emits a container-only mapping in every deploy profile — no public instance.
	networkMappings := []*basev0.NetworkMapping{{
		Endpoint:  builder.HttpEndpoint,
		Instances: []*basev0.NetworkInstance{containerVaultInstance()},
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

	restrictedDestination := t.TempDir()
	restricted, err := builder.Deploy(ctx, deploymentRequest(
		restrictedDestination,
		builderv0.KubernetesOutputProfile_KUBERNETES_OUTPUT_PROFILE_RESTRICTED_PORTABLE_V1,
		networkMappings,
		nil,
		map[string]*builderv0.KubernetesSecretKeyReference{
			"CODEFLY__SERVICE_SECRET_CONFIGURATION__MODULE__VAULT__VAULT__VAULT_TOKEN": {
				Name: "vault-credentials",
				Key:  "CODEFLY__SERVICE_SECRET_CONFIGURATION__MODULE__VAULT__VAULT__VAULT_TOKEN",
			},
		},
	))
	require.NoError(t, err)
	require.Equal(t, builderv0.DeploymentStatus_SUCCESS, restricted.GetState().GetState(), restricted.GetState().GetMessage())
	output := restricted.GetDeployment().GetKubernetes()
	require.Equal(t, builderv0.KubernetesOutputProfile_KUBERNETES_OUTPUT_PROFILE_RESTRICTED_PORTABLE_V1, output.GetProfile())
	require.Equal(t, builderv0.KubernetesManifestValidation_STATUS_PASSED, output.GetValidation().GetStaticValidation())
	require.True(t, output.GetValidation().GetRestricted())
	// Token handoff: the restricted deployment's connection configuration
	// advertises an empty, secret token capability the promotion driver fills;
	// the plugin never receives or serializes the value.
	require.Len(t, restricted.GetConfiguration().GetInfos()[0].GetConfigurationValues(), 2)
	tokenCapability := restricted.GetConfiguration().GetInfos()[0].GetConfigurationValues()[1]
	require.Equal(t, "token", tokenCapability.GetKey())
	require.Empty(t, tokenCapability.GetValue())
	require.True(t, tokenCapability.GetSecret())
	restrictedTree := readManifestTree(t, restrictedDestination)
	require.NotContains(t, restrictedTree, secret)
	require.NotContains(t, restrictedTree, base64.StdEncoding.EncodeToString([]byte(secret)))
	require.NotContains(t, restrictedTree, "kind: Namespace")
	require.NotContains(t, restrictedTree, "kind: Secret")
	require.NotContains(t, restrictedTree, "\ndata:")
	require.NotContains(t, restrictedTree, "\nstringData:")
	require.Contains(t, restrictedTree, "name: VAULT_DEV_ROOT_TOKEN_ID")
	require.Contains(t, restrictedTree, "name: vault-credentials")
	require.Contains(t, restrictedTree, "key: CODEFLY__SERVICE_SECRET_CONFIGURATION__MODULE__VAULT__VAULT__VAULT_TOKEN")
	require.Contains(t, restrictedTree, image.FullName())

	// Boundary: plugin-owned output stays a pure manifest producer. It may not
	// carry reconciliation control-plane objects or repository source bindings —
	// that responsibility belongs to the separate promotion driver, not here.
	for _, forbidden := range []string{
		"argoproj.io", "kind: Application", "kind: AppProject",
		"fluxcd.io", "repoURL", "targetRevision",
	} {
		require.NotContains(t, restrictedTree, forbidden)
	}

	// The bundle is the transport-neutral hand-off: canonical inventory,
	// entry point, digest, contract version, and validation evidence — all a
	// promotion driver needs to consume the output without any plugin-specific
	// publication code.
	bundle := output.GetBundle()
	require.Equal(t, builderv0.KubernetesOutputProfile_KUBERNETES_OUTPUT_PROFILE_RESTRICTED_PORTABLE_V1, bundle.GetProfile())
	require.Equal(t, output.GetContractVersion(), bundle.GetContractVersion())
	require.NotEmpty(t, bundle.GetContractVersion())
	require.Equal(t, []string{"overlays/test"}, bundle.GetEntryPoints())
	require.NotEmpty(t, bundle.GetFiles())
	require.True(t, sort.SliceIsSorted(bundle.GetFiles(), func(i, j int) bool {
		return bundle.GetFiles()[i].GetPath() < bundle.GetFiles()[j].GetPath()
	}), "bundle inventory must be canonically sorted")
	for _, file := range bundle.GetFiles() {
		require.Regexp(t, `^sha256:[0-9a-f]{64}$`, file.GetDigest())
	}
	require.Regexp(t, `^sha256:[0-9a-f]{64}$`, bundle.GetDigest())
	// The bundle carries the same validation evidence the output reports — the
	// observable contract, asserted on content rather than pointer identity so
	// it holds whether core shares or copies the validation into the bundle.
	require.Equal(t, output.GetValidation().GetStaticValidation(), bundle.GetValidation().GetStaticValidation())
	require.True(t, bundle.GetValidation().GetRestricted())
	require.Equal(t, "vault-credentials", bundle.GetSecretReferences()["VAULT_DEV_ROOT_TOKEN_ID"].GetName())
}

// TestRestrictedProfilesRenderIdenticalBundle locks the migration-window
// contract at the plugin's public Deploy boundary: the deprecated
// PROMOTABLE_GITOPS_V1 profile is still accepted and renders byte-for-byte
// identically to its transport-neutral RESTRICTED_PORTABLE_V1 successor,
// differing only in the profile label the output records.
func TestRestrictedProfilesRenderIdenticalBundle(t *testing.T) {
	ctx := context.Background()
	builder, networkMappings := deploymentBuilder(t)

	references := map[string]*builderv0.KubernetesSecretKeyReference{
		"CODEFLY__SERVICE_SECRET_CONFIGURATION__MODULE__VAULT__VAULT__VAULT_TOKEN": {
			Name: "vault-credentials",
			Key:  "CODEFLY__SERVICE_SECRET_CONFIGURATION__MODULE__VAULT__VAULT__VAULT_TOKEN",
		},
	}
	deploy := func(profile builderv0.KubernetesOutputProfile) (*builderv0.KubernetesDeploymentOutput, string) {
		destination := t.TempDir()
		response, err := builder.Deploy(ctx, deploymentRequest(destination, profile, networkMappings, nil, references))
		require.NoError(t, err)
		require.Equal(t, builderv0.DeploymentStatus_SUCCESS, response.GetState().GetState())
		return response.GetDeployment().GetKubernetes(), readManifestTree(t, destination)
	}

	neutral, neutralTree := deploy(builderv0.KubernetesOutputProfile_KUBERNETES_OUTPUT_PROFILE_RESTRICTED_PORTABLE_V1)
	deprecated, deprecatedTree := deploy(builderv0.KubernetesOutputProfile_KUBERNETES_OUTPUT_PROFILE_PROMOTABLE_GITOPS_V1) //nolint:staticcheck // migration compatibility

	require.Equal(t, neutralTree, deprecatedTree, "deprecated profile must render an identical manifest tree")
	require.Equal(t, neutral.GetBundle().GetDigest(), deprecated.GetBundle().GetDigest(), "identical trees must yield an identical bundle digest")
	require.True(t, deprecated.GetValidation().GetRestricted())
	require.Equal(t, builderv0.KubernetesOutputProfile_KUBERNETES_OUTPUT_PROFILE_PROMOTABLE_GITOPS_V1, deprecated.GetProfile()) //nolint:staticcheck // migration compatibility
}

func TestEphemeralDeploymentFailsClosedWithoutVaultToken(t *testing.T) {
	ctx := context.Background()
	builder, networkMappings := deploymentBuilder(t)

	tests := []struct {
		name          string
		configuration *basev0.Configuration
	}{
		{name: "nil configuration"},
		{name: "missing token", configuration: &basev0.Configuration{}},
		{name: "empty token", configuration: vaultConfiguration("")},
		{name: "blank token", configuration: vaultConfiguration(" \t")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response, err := builder.Deploy(ctx, deploymentRequest(
				t.TempDir(),
				builderv0.KubernetesOutputProfile_KUBERNETES_OUTPUT_PROFILE_EPHEMERAL_LOCAL_APPLY_V1,
				networkMappings,
				test.configuration,
				nil,
			))

			require.NoError(t, err)
			require.Equal(t, builderv0.DeploymentStatus_ERROR, response.GetState().GetState())
			require.Contains(t, response.GetState().GetMessage(), "cannot get vault token")
		})
	}
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

func TestRestrictedDeploymentRequiresVaultTokenReference(t *testing.T) {
	ctx := context.Background()
	builder, networkMappings := deploymentBuilder(t)

	tests := []struct {
		name       string
		references map[string]*builderv0.KubernetesSecretKeyReference
		message    string
	}{
		{
			name:    "missing",
			message: `requires exactly one canonical Vault token secret reference`,
		},
		{
			name: "misnamed",
			references: map[string]*builderv0.KubernetesSecretKeyReference{
				"VAULT_TOKEN": {
					Name: "vault-credentials",
					Key:  "root-token",
				},
			},
			message: `requires the canonical Vault token secret reference`,
		},
		{
			name: "optional",
			references: map[string]*builderv0.KubernetesSecretKeyReference{
				"CODEFLY__SERVICE_SECRET_CONFIGURATION__MODULE__VAULT__VAULT__VAULT_TOKEN": {
					Name:     "vault-credentials",
					Key:      "CODEFLY__SERVICE_SECRET_CONFIGURATION__MODULE__VAULT__VAULT__VAULT_TOKEN",
					Optional: true,
				},
			},
			message: `Vault token secret reference must not be optional`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response, err := builder.Deploy(ctx, deploymentRequest(
				t.TempDir(),
				builderv0.KubernetesOutputProfile_KUBERNETES_OUTPUT_PROFILE_RESTRICTED_PORTABLE_V1,
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

// A visibility: module endpoint has no public instance, so the remote network
// manager emits a container-only mapping. The restricted profile must resolve
// that container instance and advertise its in-cluster Service address, not
// demand a public one that will never exist.
func TestRestrictedDeploymentAdvertisesContainerAddress(t *testing.T) {
	ctx := context.Background()
	builder, _ := deploymentBuilder(t)
	containerOnly := []*basev0.NetworkMapping{{
		Endpoint:  builder.HttpEndpoint,
		Instances: []*basev0.NetworkInstance{containerVaultInstance()},
	}}
	references := map[string]*builderv0.KubernetesSecretKeyReference{
		"CODEFLY__SERVICE_SECRET_CONFIGURATION__MODULE__VAULT__VAULT__VAULT_TOKEN": {
			Name: "vault-credentials",
			Key:  "CODEFLY__SERVICE_SECRET_CONFIGURATION__MODULE__VAULT__VAULT__VAULT_TOKEN",
		},
	}

	response, err := builder.Deploy(ctx, deploymentRequest(
		t.TempDir(),
		builderv0.KubernetesOutputProfile_KUBERNETES_OUTPUT_PROFILE_PROMOTABLE_GITOPS_V1, //nolint:staticcheck // migration compatibility
		containerOnly,
		nil,
		references,
	))
	require.NoError(t, err)
	require.Equal(t, builderv0.DeploymentStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())

	address, err := resources.GetConfigurationValue(ctx, response.GetConfiguration(), "vault", "address")
	require.NoError(t, err)
	require.Equal(t, containerVaultInstance().GetAddress(), address)
}

// Local apply is served the same container-only mapping: the CLI generates
// remote-network-manager mappings for every deploy profile, so a module-visibility
// vault has no public instance under EPHEMERAL_LOCAL_APPLY either. The ephemeral
// profile must resolve the container instance and advertise its in-cluster Service
// address — the workload and its dependants run inside the cluster here too.
func TestEphemeralDeploymentResolvesContainerAddress(t *testing.T) {
	ctx := context.Background()
	builder, _ := deploymentBuilder(t)
	containerOnly := []*basev0.NetworkMapping{{
		Endpoint:  builder.HttpEndpoint,
		Instances: []*basev0.NetworkInstance{containerVaultInstance()},
	}}

	response, err := builder.Deploy(ctx, deploymentRequest(
		t.TempDir(),
		builderv0.KubernetesOutputProfile_KUBERNETES_OUTPUT_PROFILE_EPHEMERAL_LOCAL_APPLY_V1,
		containerOnly,
		vaultConfiguration("must-stay-ephemeral"),
		nil,
	))
	require.NoError(t, err)
	require.Equal(t, builderv0.DeploymentStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())

	address, err := resources.GetConfigurationValue(ctx, response.GetConfiguration(), "vault", "address")
	require.NoError(t, err)
	require.Equal(t, containerVaultInstance().GetAddress(), address)
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
		Endpoint:  builder.HttpEndpoint,
		Instances: []*basev0.NetworkInstance{containerVaultInstance()},
	}}
}

func containerVaultInstance() *basev0.NetworkInstance {
	return &basev0.NetworkInstance{
		Access:   resources.NewContainerNetworkAccess(),
		Hostname: "vault",
		Host:     "vault:8200",
		Port:     8200,
		Address:  "http://vault:8200",
	}
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
