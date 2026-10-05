package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	builderv0 "github.com/codefly-dev/core/generated/go/codefly/services/builder/v0"
	"github.com/stretchr/testify/require"
)

// scriptConsumerPolicy is the policy text provision/provision.sh installs, read
// out of the shell heredoc with the transit key name substituted as the script
// substitutes it.
func scriptConsumerPolicy(t *testing.T, transitKey string) string {
	t.Helper()
	const opening = "consumer_policy() {\n\tcat <<EOF\n"
	start := strings.Index(provisionScript, opening)
	require.GreaterOrEqual(t, start, 0, "provision.sh no longer declares consumer_policy() as a heredoc")
	body := provisionScript[start+len(opening):]
	end := strings.Index(body, "\nEOF\n")
	require.GreaterOrEqual(t, end, 0, "provision.sh's consumer_policy() heredoc is unterminated")
	return strings.ReplaceAll(body[:end+1], "$key", transitKey)
}

// A consumer's credential grants one scope, whichever Vault issued it: the
// deployed renders install it from a shell heredoc and the local runtime from
// consumerPolicy(). Two copies that drift would leave a consumer holding
// different capabilities locally and on a cell, and only one of them audited.
func TestConsumerPolicyIsOneScope(t *testing.T) {
	for _, key := range []string{"api-keys", "tenant-keys"} {
		t.Run(key, func(t *testing.T) {
			require.Equal(t, consumerPolicy(key), scriptConsumerPolicy(t, key))
		})
	}
}

// SP-SEC-04. The policy a consumer's token carries names only that consumer's
// own paths. Nothing under sys/ (no mount, no policy, no audit device, no seal),
// no token creation, and no capability that could create, rotate, retype or
// delete a transit key: the credential cannot widen itself or destroy what
// other ciphertexts depend on.
func TestConsumerPolicyGrantsOnlyItsOwnPaths(t *testing.T) {
	policy := consumerPolicy("api-keys")
	var paths []string
	for _, line := range strings.Split(policy, "\n") {
		if strings.HasPrefix(line, "path ") {
			paths = append(paths, strings.Trim(strings.TrimSuffix(strings.TrimPrefix(line, "path "), " {"), `"`))
		}
	}
	require.NotEmpty(t, paths)
	for _, path := range paths {
		require.False(t, strings.HasPrefix(path, "sys/"), "policy grants %q", path)
		require.False(t, strings.HasPrefix(path, "auth/"), "policy grants %q", path)
		require.False(t, strings.HasPrefix(path, "identity/"), "policy grants %q", path)
		require.NotEqual(t, "*", path, "policy grants every path")
		// transit/keys/<key> is readable (its type and version), never writable:
		// a write there rotates or retypes the key every ciphertext depends on.
		if strings.HasPrefix(path, "transit/keys/") {
			require.Equal(t, "transit/keys/api-keys", path)
		}
	}
	require.Contains(t, paths, "secret/data/*")
	require.Contains(t, paths, "transit/encrypt/api-keys")
	require.Contains(t, paths, "transit/decrypt/api-keys")
	require.Contains(t, paths, "transit/hmac/api-keys")

	// The one transit path a consumer may read is read-only; every other
	// transit path it holds is an operation on that key, not on the key store.
	for _, line := range strings.Split(policy, "\n") {
		if strings.Contains(line, "capabilities") {
			require.NotContains(t, line, `"sudo"`, "policy grants sudo: %s", line)
			require.NotContains(t, line, `"deny"`, "a deny rule hides what the grants are: %s", line)
		}
	}
}

// The audit catalogue's SP-SEC-04 check, run here so it cannot regress between
// audits: no credential this agent installs carries the root policy.
func TestNoRootPolicyCredentialIsInstalled(t *testing.T) {
	for name, script := range map[string]string{
		"provision/provision.sh": provisionScript,
		"provision/server.sh":    serverScript,
		"provision/dev.sh":       devScript,
	} {
		require.NotContains(t, script, `"policies":["root"]`, "%s installs a root-policy token", name)
		require.NotContains(t, script, `"policies": ["root"]`, "%s installs a root-policy token", name)
	}
	for _, source := range []string{"localstate.go", "runtime.go", "builder.go", "provision.go", "main.go"} {
		content, err := os.ReadFile(source)
		require.NoError(t, err)
		require.NotContains(t, string(content), `[]string{"root"}`, "%s installs a root-policy token", source)
	}
	require.Equal(t, "codefly-access", consumerPolicyName)
}

// SP-SEC-03 on what this agent's own scripts say: a message names the variable
// a credential arrives in, never its value. Every one of these scripts runs in
// a container whose output a cell retains.
func TestScriptsNeverPrintACredentialValue(t *testing.T) {
	credentials := []string{
		`$token"`, `$root"`, `$bootstrap"`, `$policies"`,
		"$VAULT_ACCESS_TOKEN", "$VAULT_DEV_ROOT_TOKEN_ID",
		"$VAULT_RECOVERY_PGP_KEY", "$recovery_pgp_key", "$VAULT_TOKEN",
	}
	for name, script := range map[string]string{
		"provision/provision.sh": provisionScript,
		"provision/server.sh":    serverScript,
		"provision/dev.sh":       devScript,
	} {
		for number, line := range strings.Split(script, "\n") {
			statement := strings.TrimLeft(line, " \t")
			if !strings.HasPrefix(statement, "echo ") && !strings.HasPrefix(statement, "fail ") {
				continue
			}
			for _, credential := range credentials {
				require.NotContains(t, statement, credential,
					"%s:%d prints a credential value: %s", name, number+1, statement)
			}
		}
	}
}

// SP-SEC-03, the mechanism: `vault server -dev` announces its unseal key and
// its root token on standard output, so the in-memory server is started with
// that stream discarded. Standard error, which carries every log line, is kept.
// TestEphemeralRenderKeepsStartupCredentialsOutOfOutput proves the effect
// against the real image; this holds the mechanism in place.
func TestDevServerDiscardsTheBannerStream(t *testing.T) {
	require.Contains(t, devScript, "exec vault server -dev -dev-listen-address=0.0.0.0:8200 >/dev/null")
	require.NotContains(t, devScript, "2>&1", "standard error is the log stream and is kept")
}

// SP-SEC-01 and the security posture's rule 3: an in-memory store is a
// local-development shape and refuses to start in a deployed runtime context,
// naming the context it found. The declaration is absent from a hand-written or
// copied manifest, which is the shape this guard exists for, so absence refuses
// too.
func TestDevServerRefusesADeployedRuntimeContext(t *testing.T) {
	for _, test := range []struct {
		name    string
		profile string
		want    string
	}{
		{name: "no declared context", want: `VAULT_CODEFLY_RENDER_PROFILE is "", not "ephemeral-local-apply"`},
		{name: "another context", profile: "restricted-portable", want: `VAULT_CODEFLY_RENDER_PROFILE is "restricted-portable", not "ephemeral-local-apply"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			// A PATH holding only what reads the declaration: no vault binary,
			// so the refusal is proven to come before any attempt to start one.
			printenv, err := exec.LookPath("printenv")
			require.NoError(t, err)
			bin := t.TempDir()
			require.NoError(t, os.Symlink(printenv, filepath.Join(bin, "printenv")))

			cmd := exec.Command("/bin/sh", "-c", devScript, "vault-dev")
			cmd.Env = []string{"PATH=" + bin}
			if test.profile != "" {
				cmd.Env = append(cmd.Env, renderProfileEnvironmentName+"="+test.profile)
			}
			out, err := cmd.CombinedOutput()
			var exitErr *exec.ExitError
			require.ErrorAs(t, err, &exitErr)
			require.Equal(t, 78, exitErr.ExitCode())
			require.Contains(t, string(out), "refuses to start in a deployed runtime context")
			require.Contains(t, string(out), test.want)
		})
	}
}

// The local-apply render is the one render that may run an in-memory store, and
// it is an allow-list: a profile this agent does not recognise as local fails
// closed instead of inheriting the dev server by default.
func TestDeployRefusesAnInMemoryStoreOutsideLocalApply(t *testing.T) {
	builder, networkMappings := deploymentBuilder(t)
	// A profile number outside the ones this agent knows: what a new, deployed
	// profile added to the contract would look like here.
	response, err := builder.Deploy(context.Background(), deploymentRequest(
		t.TempDir(),
		builderv0.KubernetesOutputProfile(99),
		networkMappings,
		vaultConfiguration("must-stay-ephemeral"),
		nil,
	))
	require.NoError(t, err)
	require.Equal(t, builderv0.DeploymentStatus_ERROR, response.GetState().GetState())
	require.Contains(t, response.GetState().GetMessage(), "an in-memory Vault is a local-development shape and is not rendered for")
}

// The local-apply render declares the context provision/dev.sh demands, runs it
// as the container's command, and hands the container the consumer's token —
// not a root token for the store.
func TestEphemeralRenderDeclaresItsLocalContext(t *testing.T) {
	_, destination := deployEphemeral(t)
	container := renderedVaultContainer(t, destination)
	require.Equal(t,
		[]string{"/usr/bin/dumb-init", "--", "/bin/sh", "-c", devScript, "vault-dev"},
		container.Command, "the in-memory server is started by provision/dev.sh")
	require.Empty(t, container.Args, "no bare `server -dev` arguments the guard cannot reach")

	values := map[string]string{}
	references := map[string]string{}
	for _, variable := range container.Env {
		values[variable.Name] = variable.Value
		if variable.ValueFrom != nil {
			references[variable.Name] = variable.ValueFrom.SecretKeyRef.Key
		}
	}
	require.Equal(t, localApplyRenderProfile, values[renderProfileEnvironmentName])
	require.Contains(t, references, vaultAccessTokenEnvironmentVariable,
		"the composition's token arrives as the access token, which the hook scopes")
	require.NotContains(t, values, vaultTokenEnvironmentVariable,
		"no render carries the store's own root token")
	require.NotContains(t, references, vaultTokenEnvironmentVariable)
}

// The declaration only has meaning if exactly one render makes it.
func TestNoDeployedRenderDeclaresTheLocalContext(t *testing.T) {
	_, destination := deployRestricted(t, "")
	require.NotContains(t, readManifestTree(t, destination), renderProfileEnvironmentName)

	builder, networkMappings := deploymentBuilder(t)
	builder.ExternalInstances = map[string]ExternalInstance{
		"test": {Address: "https://vault.example.internal:8200"},
	}
	external := t.TempDir()
	response, err := builder.Deploy(context.Background(), deploymentRequest(
		external,
		builderv0.KubernetesOutputProfile_KUBERNETES_OUTPUT_PROFILE_EPHEMERAL_LOCAL_APPLY_V1,
		networkMappings,
		vaultConfiguration("external"),
		nil,
	))
	require.NoError(t, err)
	require.Equal(t, builderv0.DeploymentStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())
	require.NotContains(t, readManifestTree(t, external), renderProfileEnvironmentName)
}
