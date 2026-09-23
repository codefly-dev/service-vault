package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	builderv0 "github.com/codefly-dev/core/generated/go/codefly/services/builder/v0"
	"github.com/stretchr/testify/require"
)

// The binding the tests' "test" environment uses: an operator-run Vault over
// TLS, its CA and a Kubernetes-auth token maintained inside consumer pods.
func tokenFileBinding() ExternalInstance {
	return ExternalInstance{
		Address:   "https://vault.platform.svc.cluster.local:8200",
		CAFile:    "/var/run/vault/ca.crt",
		TokenFile: "/var/run/vault/token",
	}
}

func deployExternal(
	t *testing.T,
	bindings map[string]ExternalInstance,
	profile builderv0.KubernetesOutputProfile,
	configuration *basev0.Configuration,
	references map[string]*builderv0.KubernetesSecretKeyReference,
) (*builderv0.DeploymentResponse, string) {
	t.Helper()
	builder, networkMappings := deploymentBuilder(t)
	builder.ExternalInstances = bindings
	destination := t.TempDir()
	response, err := builder.Deploy(context.Background(), deploymentRequest(destination, profile, networkMappings, configuration, references))
	require.NoError(t, err)
	return response, destination
}

func vaultValues(t *testing.T, response *builderv0.DeploymentResponse) map[string]*basev0.ConfigurationValue {
	t.Helper()
	infos := response.GetConfiguration().GetInfos()
	require.Len(t, infos, 1)
	require.Equal(t, "vault", infos[0].GetName())
	values := map[string]*basev0.ConfigurationValue{}
	for _, value := range infos[0].GetConfigurationValues() {
		values[value.GetKey()] = value
	}
	return values
}

// A bound environment renders no Vault at all and hands consumers the external
// coordinates: HTTPS address, CA file and token file. With a token file there
// is no static token capability, so no root-like credential reaches consumers.
func TestExternalInstanceRendersNoVault(t *testing.T) {
	for _, test := range []struct {
		name       string
		references map[string]*builderv0.KubernetesSecretKeyReference
	}{
		{name: "no token reference"},
		// The module still declares the vault/token secret, so the CLI still
		// passes its reference; nothing here consumes it.
		{name: "unused token reference", references: restrictedVaultTokenReference},
	} {
		t.Run(test.name, func(t *testing.T) {
			response, destination := deployExternal(t,
				map[string]ExternalInstance{"test": tokenFileBinding()},
				builderv0.KubernetesOutputProfile_KUBERNETES_OUTPUT_PROFILE_RESTRICTED_PORTABLE_V1,
				nil, test.references)
			require.Equal(t, builderv0.DeploymentStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())
			output := response.GetDeployment().GetKubernetes()
			require.Equal(t, builderv0.KubernetesManifestValidation_STATUS_PASSED, output.GetValidation().GetStaticValidation())
			require.True(t, output.GetValidation().GetRestricted())
			require.Empty(t, output.GetBundle().GetSecretReferences(), "no rendered manifest consumes a secret")

			tree := readManifestTree(t, destination)
			for _, kind := range []string{"kind: StatefulSet", "kind: Service", "kind: Secret", "kind: Namespace", "kind: Job", "PersistentVolumeClaim"} {
				require.NotContains(t, tree, kind)
			}
			for _, absent := range []string{"stateful-set.yaml", "service.yaml"} {
				_, err := os.Stat(filepath.Join(destination, "base", absent))
				require.True(t, os.IsNotExist(err), "%s must not be rendered", absent)
			}

			values := vaultValues(t, response)
			require.Equal(t, "https://vault.platform.svc.cluster.local:8200", values["address"].GetValue())
			require.Equal(t, "/var/run/vault/ca.crt", values["ca-file"].GetValue())
			require.Equal(t, "/var/run/vault/token", values["token-file"].GetValue())
			require.NotContains(t, values, "token")
			for _, value := range values {
				require.False(t, value.GetSecret(), "%s is a coordinate, not a secret", value.GetKey())
			}
		})
	}
}

// Without a token file consumers present the static token: the restricted
// render then requires the canonical reference and advertises the empty token
// capability the promotion driver fills, as for a rendered Vault.
func TestExternalInstanceWithStaticToken(t *testing.T) {
	binding := tokenFileBinding()
	binding.TokenFile = ""
	bindings := map[string]ExternalInstance{"test": binding}

	response, _ := deployExternal(t, bindings,
		builderv0.KubernetesOutputProfile_KUBERNETES_OUTPUT_PROFILE_RESTRICTED_PORTABLE_V1, nil, restrictedVaultTokenReference)
	require.Equal(t, builderv0.DeploymentStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())
	values := vaultValues(t, response)
	require.Equal(t, "https://vault.platform.svc.cluster.local:8200", values["address"].GetValue())
	require.True(t, values["token"].GetSecret())
	require.Empty(t, values["token"].GetValue())
	require.NotContains(t, values, "token-file")

	response, _ = deployExternal(t, bindings,
		builderv0.KubernetesOutputProfile_KUBERNETES_OUTPUT_PROFILE_RESTRICTED_PORTABLE_V1, nil, nil)
	require.Equal(t, builderv0.DeploymentStatus_ERROR, response.GetState().GetState())
	require.Contains(t, response.GetState().GetMessage(), "external instance without token-file")

	// Local apply hands over the configured token itself.
	response, destination := deployExternal(t, bindings,
		builderv0.KubernetesOutputProfile_KUBERNETES_OUTPUT_PROFILE_EPHEMERAL_LOCAL_APPLY_V1, vaultConfiguration("local-token"), nil)
	require.Equal(t, builderv0.DeploymentStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())
	values = vaultValues(t, response)
	require.Equal(t, "local-token", values["token"].GetValue())
	tree := readManifestTree(t, destination)
	require.NotContains(t, tree, "kind: StatefulSet")
	require.NotContains(t, tree, "kind: Secret")
	require.NotContains(t, tree, "local-token")
}

// Bindings are per environment, and once any is declared every deployed
// environment must be bound: a typo must not fall back to a Vault of our own.
func TestExternalInstanceBindingIsValidated(t *testing.T) {
	restricted := builderv0.KubernetesOutputProfile_KUBERNETES_OUTPUT_PROFILE_RESTRICTED_PORTABLE_V1
	valid := tokenFileBinding()
	for _, test := range []struct {
		name     string
		bindings map[string]ExternalInstance
		message  string
	}{
		{name: "unbound environment", bindings: map[string]ExternalInstance{"production": valid}, message: `external-instances binds production but not environment "test"`},
		{name: "plaintext address", bindings: map[string]ExternalInstance{"test": {Address: "http://vault:8200", TokenFile: valid.TokenFile}}, message: "must be an https://host[:port] base URL"},
		{name: "address with a path", bindings: map[string]ExternalInstance{"test": {Address: "https://vault:8200/v1", TokenFile: valid.TokenFile}}, message: "must be an https://host[:port] base URL"},
		{name: "address with credentials", bindings: map[string]ExternalInstance{"test": {Address: "https://user:pass@vault:8200", TokenFile: valid.TokenFile}}, message: "must be an https://host[:port] base URL"},
		{name: "no address", bindings: map[string]ExternalInstance{"test": {TokenFile: valid.TokenFile}}, message: "must be an https://host[:port] base URL"},
		{name: "relative ca-file", bindings: map[string]ExternalInstance{"test": {Address: valid.Address, CAFile: "ca.crt"}}, message: `ca-file "ca.crt" must be a clean absolute path`},
		{name: "unclean token-file", bindings: map[string]ExternalInstance{"test": {Address: valid.Address, TokenFile: "/var/run/../token"}}, message: `token-file "/var/run/../token" must be a clean absolute path`},
		// Every binding is checked, not only the one in use.
		{name: "invalid other binding", bindings: map[string]ExternalInstance{"test": valid, "production": {Address: "http://vault"}}, message: "external-instances.production"},
	} {
		t.Run(test.name, func(t *testing.T) {
			response, destination := deployExternal(t, test.bindings, restricted, nil, restrictedVaultTokenReference)
			require.Equal(t, builderv0.DeploymentStatus_ERROR, response.GetState().GetState())
			require.Contains(t, response.GetState().GetMessage(), test.message)
			entries, err := os.ReadDir(destination)
			require.NoError(t, err)
			require.Empty(t, entries, "a refused binding renders nothing")
		})
	}
}

// Without external-instances nothing changes: the render owns its Vault.
func TestNoExternalInstancesKeepsTheRenderedVault(t *testing.T) {
	response, destination := deployExternal(t, nil,
		builderv0.KubernetesOutputProfile_KUBERNETES_OUTPUT_PROFILE_RESTRICTED_PORTABLE_V1, nil, restrictedVaultTokenReference)
	require.Equal(t, builderv0.DeploymentStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())
	require.True(t, strings.Contains(readManifestTree(t, destination), "kind: StatefulSet"))
	require.Equal(t, "http://vault:8200", vaultValues(t, response)["address"].GetValue())
}
