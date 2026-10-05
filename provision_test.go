package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	builderv0 "github.com/codefly-dev/core/generated/go/codefly/services/builder/v0"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

var restrictedVaultTokenReference = map[string]*builderv0.KubernetesSecretKeyReference{
	"CODEFLY__SERVICE_SECRET_CONFIGURATION__MODULE__VAULT__VAULT__VAULT_TOKEN": {
		Name: "vault-credentials",
		Key:  "CODEFLY__SERVICE_SECRET_CONFIGURATION__MODULE__VAULT__VAULT__VAULT_TOKEN",
	},
}

type renderedVolumeMount struct {
	Name      string `yaml:"name"`
	MountPath string `yaml:"mountPath"`
}

type renderedContainer struct {
	Name         string                `yaml:"name"`
	Command      []string              `yaml:"command"`
	Args         []string              `yaml:"args"`
	VolumeMounts []renderedVolumeMount `yaml:"volumeMounts"`
	Lifecycle    struct {
		PostStart struct {
			Exec struct {
				Command []string `yaml:"command"`
			} `yaml:"exec"`
		} `yaml:"postStart"`
	} `yaml:"lifecycle"`
	Env []struct {
		Name      string `yaml:"name"`
		Value     string `yaml:"value"`
		ValueFrom *struct {
			SecretKeyRef struct {
				Name string `yaml:"name"`
				Key  string `yaml:"key"`
			} `yaml:"secretKeyRef"`
		} `yaml:"valueFrom"`
	} `yaml:"env"`
}

type renderedStatefulSet struct {
	Spec struct {
		PersistentVolumeClaimRetentionPolicy struct {
			WhenDeleted string `yaml:"whenDeleted"`
			WhenScaled  string `yaml:"whenScaled"`
		} `yaml:"persistentVolumeClaimRetentionPolicy"`
		VolumeClaimTemplates []struct {
			Metadata struct {
				Name string `yaml:"name"`
			} `yaml:"metadata"`
			Spec struct {
				AccessModes      []string `yaml:"accessModes"`
				StorageClassName string   `yaml:"storageClassName"`
				Resources        struct {
					Requests map[string]string `yaml:"requests"`
				} `yaml:"resources"`
			} `yaml:"spec"`
		} `yaml:"volumeClaimTemplates"`
		Template struct {
			Spec struct {
				Containers []renderedContainer `yaml:"containers"`
			} `yaml:"spec"`
		} `yaml:"template"`
	} `yaml:"spec"`
}

func renderedVaultStatefulSet(t *testing.T, destination string) renderedStatefulSet {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(destination, "base", "stateful-set.yaml"))
	require.NoError(t, err)
	var statefulSet renderedStatefulSet
	require.NoError(t, yaml.Unmarshal(content, &statefulSet))
	return statefulSet
}

func renderedVaultContainer(t *testing.T, destination string) renderedContainer {
	t.Helper()
	statefulSet := renderedVaultStatefulSet(t, destination)
	require.Len(t, statefulSet.Spec.Template.Spec.Containers, 1)
	return statefulSet.Spec.Template.Spec.Containers[0]
}

// deployEphemeral renders the local-apply profile, the one that still runs the
// in-memory dev server.
func deployEphemeral(t *testing.T) (*builderv0.DeploymentResponse, string) {
	t.Helper()
	builder, networkMappings := deploymentBuilder(t)
	destination := t.TempDir()
	response, err := builder.Deploy(context.Background(), deploymentRequest(
		destination,
		builderv0.KubernetesOutputProfile_KUBERNETES_OUTPUT_PROFILE_EPHEMERAL_LOCAL_APPLY_V1,
		networkMappings,
		vaultConfiguration("must-stay-ephemeral"),
		nil,
	))
	require.NoError(t, err)
	return response, destination
}

// deployRestricted renders the restricted (GitOps) profile and returns the
// vault container's postStart command.
func deployRestricted(t *testing.T, transitKey string) (*builderv0.DeploymentResponse, string) {
	t.Helper()
	builder, networkMappings := deploymentBuilder(t)
	builder.TransitKey = transitKey
	destination := t.TempDir()
	response, err := builder.Deploy(context.Background(), deploymentRequest(
		destination,
		builderv0.KubernetesOutputProfile_KUBERNETES_OUTPUT_PROFILE_RESTRICTED_PORTABLE_V1,
		networkMappings,
		nil,
		restrictedVaultTokenReference,
	))
	require.NoError(t, err)
	return response, destination
}

// The restricted render is what a deployed cell runs. It must be a durable
// Vault — state on a persistent volume, unsealed by the environment's seal — and
// its start hook must provision transit with the configured key, or every
// consumer's /v1/transit/encrypt|hmac/<key> answers 404.
func TestRestrictedRenderRunsADurableVault(t *testing.T) {
	for _, test := range []struct {
		setting string
		want    string
	}{
		{setting: "", want: "api-keys"},
		{setting: "api-keys", want: "api-keys"},
		{setting: "tenant-keys", want: "tenant-keys"},
	} {
		t.Run("transit-key="+test.setting, func(t *testing.T) {
			response, destination := deployRestricted(t, test.setting)
			require.Equal(t, builderv0.DeploymentStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())
			output := response.GetDeployment().GetKubernetes()
			require.Equal(t, builderv0.KubernetesManifestValidation_STATUS_PASSED, output.GetValidation().GetStaticValidation())
			require.True(t, output.GetValidation().GetRestricted())

			statefulSet := renderedVaultStatefulSet(t, destination)
			container := renderedVaultContainer(t, destination)
			require.Equal(t, "vault", container.Name)
			require.Equal(t,
				[]string{"/usr/bin/dumb-init", "--", "/bin/sh", "-c", serverScript, "vault-server"},
				container.Command, "the durable server script is the container's command")
			require.Empty(t, container.Args, "no `server -dev` arguments")
			require.Equal(t,
				[]string{"/bin/sh", "-c", provisionScript, "vault-provision", "durable", test.want},
				container.Lifecycle.PostStart.Exec.Command,
				"the hook runs the embedded script verbatim, durable mode, key name as $2")

			// Storage: one claim, mounted where raft and the init record live,
			// on the environment's default StorageClass, retained when the
			// StatefulSet is deleted or scaled.
			require.Len(t, statefulSet.Spec.VolumeClaimTemplates, 1)
			claim := statefulSet.Spec.VolumeClaimTemplates[0]
			require.Equal(t, "data", claim.Metadata.Name)
			require.Equal(t, []string{"ReadWriteOnce"}, claim.Spec.AccessModes)
			require.Equal(t, "1Gi", claim.Spec.Resources.Requests["storage"])
			require.Empty(t, claim.Spec.StorageClassName, "the StorageClass is the environment's choice")
			require.Equal(t, "Retain", statefulSet.Spec.PersistentVolumeClaimRetentionPolicy.WhenDeleted)
			require.Equal(t, "Retain", statefulSet.Spec.PersistentVolumeClaimRetentionPolicy.WhenScaled)
			require.Contains(t, container.VolumeMounts, renderedVolumeMount{Name: "data", MountPath: "/vault/data"})

			// Credentials: the access token comes only from the canonical
			// secret reference; the container declares its service so the
			// environment's configuration (the seal) is projected into it.
			env := map[string]string{}
			var token []string
			for _, variable := range container.Env {
				env[variable.Name] = variable.Value
				if variable.ValueFrom != nil {
					token = append(token, variable.Name+"="+variable.ValueFrom.SecretKeyRef.Name+"/"+variable.ValueFrom.SecretKeyRef.Key)
				}
			}
			require.Equal(t, []string{"VAULT_ACCESS_TOKEN=vault-credentials/CODEFLY__SERVICE_SECRET_CONFIGURATION__MODULE__VAULT__VAULT__VAULT_TOKEN"}, token)
			require.Equal(t, "vault", env["CODEFLY__SERVICE"])
			require.NotContains(t, env, vaultTokenEnvironmentVariable, "a durable server has no dev root token")

			tree := readManifestTree(t, destination)
			require.NotContains(t, tree, "- -dev", "no dev-mode server argument in a deployed render")
			// The seal is environment configuration: the render sets no seal
			// variable and the server configuration it writes has no seal stanza.
			for name := range env {
				require.NotRegexp(t, `^(VAULT_SEAL_TYPE|VAULT_GCPCKMS_|GOOGLE_|VAULT_RECOVERY_PGP_KEY)`, name)
			}
			require.NotContains(t, serverScript, "seal \"")
			require.NotContains(t, tree, "kind: Job")
			require.NotContains(t, tree, "kind: Namespace")
			require.NotContains(t, tree, "kind: Secret")
			require.Equal(t, "vault-credentials", output.GetBundle().GetSecretReferences()[vaultAccessTokenEnvironmentVariable].GetName())
		})
	}
}

// Local apply keeps the in-memory dev server and re-provisions it on every start.
// A restart there mints a new transit key; that is acceptable only for this
// disposable local profile, which is why no deployed profile renders it.
func TestEphemeralRenderProvisionsTransitOnVaultStart(t *testing.T) {
	builder, networkMappings := deploymentBuilder(t)
	destination := t.TempDir()
	response, err := builder.Deploy(context.Background(), deploymentRequest(
		destination,
		builderv0.KubernetesOutputProfile_KUBERNETES_OUTPUT_PROFILE_EPHEMERAL_LOCAL_APPLY_V1,
		networkMappings,
		vaultConfiguration("must-stay-ephemeral"),
		nil,
	))
	require.NoError(t, err)
	require.Equal(t, builderv0.DeploymentStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())
	container := renderedVaultContainer(t, destination)
	require.Equal(t,
		[]string{"/bin/sh", "-c", provisionScript, "vault-provision", "dev", "api-keys"},
		container.Lifecycle.PostStart.Exec.Command)
	statefulSet, err := os.ReadFile(filepath.Join(destination, "base", "stateful-set.yaml"))
	require.NoError(t, err)
	require.NotContains(t, string(statefulSet), "must-stay-ephemeral")
}

// A key name that is not one plain path segment would provision one Vault path
// while consumers call another; the render refuses it rather than ship that.
func TestDeployRefusesAnInvalidTransitKeyName(t *testing.T) {
	for _, key := range []string{"../sys", "a/b", ".hidden", "with space", "semi;colon", "$(id)", strings.Repeat("k", 129)} {
		t.Run(key, func(t *testing.T) {
			response, _ := deployRestricted(t, key)
			require.Equal(t, builderv0.DeploymentStatus_ERROR, response.GetState().GetState())
			require.Contains(t, response.GetState().GetMessage(), "is not a valid Vault transit key name")
		})
	}
}

// fakeVault is a `vault` CLI double for exercising the provisioning script's
// dev-mode control flow (durable mode runs against the real image in
// durable_test.go). It models only the invocations dev mode makes, keeps Vault's
// state as files, and appends every call to a log. It does not enforce
// policies — what a scoped token may actually reach is asserted against the
// real Vault in durable_test.go and in TestEphemeralRenderIssuesAScopedToken.
const fakeVault = `#!/bin/sh
state="$FAKE_VAULT_STATE"
echo "$VAULT_ADDR $VAULT_TOKEN $*" >> "$state/calls"
if [ -e "$state/down" ]; then echo "connection refused" >&2; exit 1; fi
case "$*" in
status) exit 0 ;;
"read -field=type sys/mounts/secret")
	if [ -e "$state/kv" ]; then cat "$state/kv"; exit 0; fi
	echo kv ;;
"read -field=options sys/mounts/secret")
	if [ -e "$state/kv-options" ]; then cat "$state/kv-options"; exit 0; fi
	echo "map[version:2]" ;;
"read -field=type sys/mounts/transit")
	if [ -e "$state/mount" ]; then cat "$state/mount"; exit 0; fi
	echo "No secret engine mount at transit/" >&2; exit 2 ;;
"secrets enable -path=transit transit")
	if [ -e "$state/race" ]; then echo transit > "$state/mount"; echo "path is already in use at transit/" >&2; exit 2; fi
	if [ -e "$state/mount" ]; then echo "path is already in use at transit/" >&2; exit 2; fi
	if [ -e "$state/deny" ]; then echo "permission denied" >&2; exit 2; fi
	echo transit > "$state/mount"; echo "Success! Enabled the transit secrets engine at: transit/" ;;
"read -field=type transit/keys/"*)
	name="$(echo "$*" | sed 's|^read -field=type transit/keys/||')"
	if [ -e "$state/key-$name" ]; then cat "$state/key-$name"; exit 0; fi
	echo "no value found at transit/keys/$name" >&2; exit 2 ;;
"write -f transit/keys/"*" type=aes256-gcm96")
	name="$(echo "$*" | sed 's|^write -f transit/keys/||; s| type=aes256-gcm96$||')"
	echo aes256-gcm96 > "$state/key-$name"; echo "Success! Data written to: transit/keys/$name" ;;
"write sys/auth/token/tune max_lease_ttl="*)
	echo "$*" | sed 's|^write sys/auth/token/tune max_lease_ttl=||' > "$state/token-store-max-ttl"
	echo "Success! Data written to: sys/auth/token/tune" ;;
"policy write "*" -")
	name="$(echo "$*" | sed 's|^policy write ||; s| -$||')"
	if [ -e "$state/policy-deny" ]; then cat > /dev/null; echo "permission denied" >&2; exit 2; fi
	cat > "$state/policy-$name"; echo "Success! Uploaded policy: $name" ;;
"policy read "*)
	name="$(echo "$*" | sed 's|^policy read ||')"
	if [ -e "$state/policy-$name" ]; then cat "$state/policy-$name"; exit 0; fi
	echo "No policy named: $name" >&2; exit 2 ;;
"token lookup")
	if [ -e "$state/token-$VAULT_TOKEN" ]; then exit 0; fi
	echo "bad token" >&2; exit 2 ;;
"read -field=policies auth/token/lookup-self")
	if [ -e "$state/token-$VAULT_TOKEN" ]; then cat "$state/token-$VAULT_TOKEN"; exit 0; fi
	echo "bad token" >&2; exit 2 ;;
"write auth/token/create-orphan -")
	body="$(cat)"
	id="$(echo "$body" | sed 's|.*"id":"\([^"]*\)".*|\1|')"
	policies="$(echo "$body" | sed 's|.*"policies":\["\([^"]*\)"\].*|\1|')"
	echo "[$policies default]" > "$state/token-$id"
	echo "Success! Data written to: auth/token/create-orphan" ;;
"token revoke "*)
	id="$(echo "$*" | sed 's|^token revoke ||')"
	rm -f "$state/token-$id"; echo "Success! Revoked token" ;;
*) echo "fake vault: unexpected invocation: $*" >&2; exit 99 ;;
esac
`

type provisionRun struct {
	state string
	bin   string
	// root stands in for the bootstrap token provision/dev.sh mints into the
	// container's tmpfs: the credential the privileged steps run under, which
	// never leaves the container and is never published.
	root string
}

func newProvisionRun(t *testing.T) *provisionRun {
	t.Helper()
	run := &provisionRun{state: t.TempDir(), bin: t.TempDir(), root: "dev-bootstrap-root"}
	require.NoError(t, os.WriteFile(filepath.Join(run.bin, "vault"), []byte(fakeVault), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(run.state, "dev-root"), []byte(run.root), 0o600))
	return run
}

func (run *provisionRun) mark(t *testing.T, name, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(run.state, name), []byte(content), 0o644))
}

// exec runs the script exactly as the dev-mode hook does:
// `sh -c <script> <$0> dev <key>`.
func (run *provisionRun) exec(t *testing.T, token string, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command("/bin/sh", append([]string{"-c", provisionScript, "vault-provision", "dev"}, args...)...)
	cmd.Env = []string{
		"PATH=" + run.bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"FAKE_VAULT_STATE=" + run.state,
		"VAULT_PROVISION_ATTEMPTS=2",
		"VAULT_DEV_ROOT_FILE=" + filepath.Join(run.state, "dev-root"),
	}
	if token != "" {
		cmd.Env = append(cmd.Env, vaultAccessTokenEnvironmentVariable+"="+token)
	}
	out, err := cmd.CombinedOutput()
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode(), string(out)
	}
	require.NoError(t, err)
	return 0, string(out)
}

func (run *provisionRun) calls(t *testing.T) []string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(run.state, "calls"))
	if os.IsNotExist(err) {
		return nil
	}
	require.NoError(t, err)
	return strings.Split(strings.TrimSpace(string(content)), "\n")
}

func (run *provisionRun) writes(t *testing.T) []string {
	var writes []string
	for _, call := range run.calls(t) {
		if strings.Contains(call, " secrets enable ") || strings.Contains(call, " write ") {
			writes = append(writes, call)
		}
	}
	return writes
}

func TestTransitProvisionScriptIsIdempotent(t *testing.T) {
	run := newProvisionRun(t)

	code, out := run.exec(t, "consumer-token", "api-keys")
	require.Equal(t, 0, code, out)
	require.Equal(t, []string{
		"http://127.0.0.1:8200 " + run.root + " secrets enable -path=transit transit",
		"http://127.0.0.1:8200 " + run.root + " write -f transit/keys/api-keys type=aes256-gcm96",
		"http://127.0.0.1:8200 " + run.root + " policy write codefly-access -",
		"http://127.0.0.1:8200 " + run.root + " write sys/auth/token/tune max_lease_ttl=" + consumerTokenTTL,
		"http://127.0.0.1:8200 " + run.root + " write auth/token/create-orphan -",
	}, run.writes(t),
		"a fresh Vault gets the engine, the key and the consumer policy over loopback under the container's bootstrap token, never under the token consumers hold")

	// Every later start of the same process finds all of it and writes nothing.
	for range 2 {
		code, out = run.exec(t, "consumer-token", "api-keys")
		require.Equal(t, 0, code, out)
	}
	require.Len(t, run.writes(t), 5, "re-running must not re-enable the engine, rewrite the key or reissue the token")
}

// SP-SEC-04: the token the script installs for consumers carries the consumer
// policy and nothing else — the body it sends names no root policy.
func TestProvisionScriptInstallsAScopedAccessToken(t *testing.T) {
	run := newProvisionRun(t)
	code, out := run.exec(t, "consumer-token", "api-keys")
	require.Equal(t, 0, code, out)
	require.Contains(t, out, "installed the access token")

	policies, err := os.ReadFile(filepath.Join(run.state, "token-consumer-token"))
	require.NoError(t, err)
	require.Equal(t, "[codefly-access default]\n", string(policies),
		"the installed access token carries only the consumer policy")

	policy, err := os.ReadFile(filepath.Join(run.state, "policy-codefly-access"))
	require.NoError(t, err)
	require.Equal(t, consumerPolicy("api-keys"), string(policy))
}

// A Vault provisioned before the access token was scoped holds it with the root
// policy. With a bootstrap token in hand the script replaces it; without one it
// refuses rather than keep publishing it.
func TestProvisionScriptReplacesARootPolicyAccessToken(t *testing.T) {
	t.Run("replaced while a bootstrap token is held", func(t *testing.T) {
		run := newProvisionRun(t)
		run.mark(t, "token-consumer-token", "[root]\n")
		code, out := run.exec(t, "consumer-token", "api-keys")
		require.Equal(t, 0, code, out)
		require.Contains(t, out, `revoked an access token that was not scoped to "codefly-access"`)
		policies, err := os.ReadFile(filepath.Join(run.state, "token-consumer-token"))
		require.NoError(t, err)
		require.Equal(t, "[codefly-access default]\n", string(policies))
	})
	t.Run("refused with no bootstrap token", func(t *testing.T) {
		run := newProvisionRun(t)
		run.mark(t, "token-consumer-token", "[root]\n")
		require.NoError(t, os.Remove(filepath.Join(run.state, "dev-root")))
		code, out := run.exec(t, "consumer-token", "api-keys")
		require.Equal(t, 1, code)
		require.Contains(t, out, `holds VAULT_ACCESS_TOKEN with more than the "codefly-access" policy`)
		policies, err := os.ReadFile(filepath.Join(run.state, "token-consumer-token"))
		require.NoError(t, err)
		require.Equal(t, "[root]\n", string(policies), "an over-privileged token is reported, never silently served")
	})
}

func TestTransitProvisionScriptAcceptsExistingState(t *testing.T) {
	run := newProvisionRun(t)
	run.mark(t, "mount", "transit\n")
	run.mark(t, "key-api-keys", "chacha20-poly1305\n")
	run.mark(t, "policy-codefly-access", consumerPolicy("api-keys"))
	run.mark(t, "token-consumer-token", "[codefly-access default]\n")

	code, out := run.exec(t, "consumer-token", "api-keys")
	require.Equal(t, 0, code, out)
	require.Empty(t, run.writes(t), "an existing engine, key, policy and scoped token are success and are left as they are")
}

func TestTransitProvisionScriptConvergesOnALostRace(t *testing.T) {
	run := newProvisionRun(t)
	run.mark(t, "race", "")

	code, out := run.exec(t, "consumer-token", "api-keys")
	require.Equal(t, 0, code, out)
	content, err := os.ReadFile(filepath.Join(run.state, "key-api-keys"))
	require.NoError(t, err)
	require.Equal(t, "aes256-gcm96\n", string(content))
}

func TestTransitProvisionScriptFailsClosed(t *testing.T) {
	t.Run("transit/ holds another engine", func(t *testing.T) {
		run := newProvisionRun(t)
		run.mark(t, "mount", "kv\n")
		code, out := run.exec(t, "consumer-token", "api-keys")
		require.Equal(t, 1, code)
		require.Contains(t, out, `transit/ is mounted as "kv", not a transit engine`)
		require.Empty(t, run.writes(t))
	})
	t.Run("engine cannot be enabled", func(t *testing.T) {
		run := newProvisionRun(t)
		run.mark(t, "deny", "")
		code, out := run.exec(t, "consumer-token", "api-keys")
		require.Equal(t, 1, code)
		require.Contains(t, out, "cannot enable the transit engine: permission denied")
	})
	t.Run("the consumer policy cannot be written", func(t *testing.T) {
		run := newProvisionRun(t)
		run.mark(t, "policy-deny", "")
		code, out := run.exec(t, "consumer-token", "api-keys")
		require.Equal(t, 1, code)
		require.Contains(t, out, `cannot write the "codefly-access" policy`)
		require.NoFileExists(t, filepath.Join(run.state, "token-consumer-token"),
			"no access token is installed without the policy that scopes it")
	})
	t.Run("vault never answers", func(t *testing.T) {
		run := newProvisionRun(t)
		run.mark(t, "down", "")
		code, out := run.exec(t, "consumer-token", "api-keys")
		require.Equal(t, 1, code)
		require.Contains(t, out, "did not become ready")
	})
	t.Run("no token", func(t *testing.T) {
		run := newProvisionRun(t)
		code, out := run.exec(t, "", "api-keys")
		require.Equal(t, 64, code)
		require.Contains(t, out, "VAULT_ACCESS_TOKEN is not set")
		require.Empty(t, run.calls(t))
	})
	t.Run("no key name", func(t *testing.T) {
		run := newProvisionRun(t)
		code, out := run.exec(t, "consumer-token")
		require.Equal(t, 64, code)
		require.Contains(t, out, "usage: provision.sh <dev|durable> <transit-key-name>")
		require.Empty(t, run.calls(t))
	})
	t.Run("the in-memory server's bootstrap credential is missing", func(t *testing.T) {
		run := newProvisionRun(t)
		require.NoError(t, os.Remove(filepath.Join(run.state, "dev-root")))
		code, out := run.exec(t, "consumer-token", "api-keys")
		require.Equal(t, 1, code)
		require.Contains(t, out, "provision/dev.sh did not start this container")
	})
}

// ephemeralHarness runs the pinned image exactly as the ephemeral local-apply
// render does: the rendered container command (provision/dev.sh) on a read-only
// root filesystem with the consumer's token in VAULT_ACCESS_TOKEN, and the
// rendered postStart hook executed inside it.
type ephemeralHarness struct {
	t         *testing.T
	ctx       context.Context
	container string
	address   string
	hook      []string
	token     string
}

func newEphemeralHarness(t *testing.T, token string) *ephemeralHarness {
	t.Helper()
	response, destination := deployEphemeral(t)
	require.Equal(t, builderv0.DeploymentStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())
	container := renderedVaultContainer(t, destination)
	require.NotEmpty(t, container.Command)
	require.NotEmpty(t, container.Lifecycle.PostStart.Exec.Command)

	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	t.Cleanup(cancel)
	h := &ephemeralHarness{t: t, ctx: ctx, hook: container.Lifecycle.PostStart.Exec.Command, token: token}

	args := []string{"run", "-d", "--read-only",
		"--tmpfs", "/tmp:mode=1777", "--tmpfs", "/home/vault:mode=1777",
		"-e", vaultAccessTokenEnvironmentVariable + "=" + token,
		"-e", renderProfileEnvironmentName + "=" + localApplyRenderProfile,
		"-p", "127.0.0.1::8200",
		"--entrypoint", container.Command[0], image.FullName(),
	}
	args = append(args, container.Command[1:]...)
	h.container = h.docker(args...)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-fv", h.container).Run() })
	h.address = "http://" + h.docker("port", h.container, "8200/tcp")
	return h
}

func (h *ephemeralHarness) docker(args ...string) string {
	h.t.Helper()
	var stderr strings.Builder
	cmd := exec.CommandContext(h.ctx, "docker", args...)
	cmd.Stderr = &stderr
	raw, err := cmd.Output()
	if err != nil {
		h.t.Fatalf("docker %s failed: %v (%s%s)", args[0], err, raw, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(raw))
}

// provision runs the rendered hook in the container, as the kubelet does.
func (h *ephemeralHarness) provision() string {
	h.t.Helper()
	return h.docker(append([]string{"exec", h.container}, h.hook...)...)
}

// output is everything the container has written to either stream — what a cell
// retains for the workload.
func (h *ephemeralHarness) output() string {
	h.t.Helper()
	var combined strings.Builder
	cmd := exec.CommandContext(h.ctx, "docker", "logs", h.container)
	cmd.Stdout, cmd.Stderr = &combined, &combined
	require.NoError(h.t, cmd.Run())
	return combined.String()
}

func (h *ephemeralHarness) call(token, method, path, body string) (int, map[string]any) {
	h.t.Helper()
	request, err := http.NewRequestWithContext(h.ctx, method, h.address+path, strings.NewReader(body))
	require.NoError(h.t, err)
	request.Header.Set("X-Vault-Token", token)
	response, err := http.DefaultClient.Do(request)
	require.NoError(h.t, err)
	defer func() { _ = response.Body.Close() }()
	raw, err := io.ReadAll(response.Body)
	require.NoError(h.t, err)
	var decoded struct {
		Data map[string]any `json:"data"`
	}
	if len(raw) > 0 && json.Valid(raw) {
		require.NoError(h.t, json.Unmarshal(raw, &decoded))
	}
	return response.StatusCode, decoded.Data
}

// TestRenderedHookProvisionsThePinnedVault runs the rendered postStart command
// inside the rendered container, twice, and calls transit the way a consumer
// does — with the token the composition supplied, which the hook installed
// scoped to the consumer policy.
func TestRenderedHookProvisionsThePinnedVault(t *testing.T) {
	h := newEphemeralHarness(t, "provision-test-access-token")

	// The hook starts with the server, so the first run also covers the wait.
	for range 2 {
		require.Contains(t, h.provision(), `transit engine and key "api-keys" ready`)
	}

	plaintext := base64.StdEncoding.EncodeToString([]byte("credential"))
	status, encrypted := h.call(h.token, http.MethodPost, "/v1/transit/encrypt/api-keys", fmt.Sprintf(`{"plaintext":%q}`, plaintext))
	require.Equal(t, http.StatusOK, status)
	require.Regexp(t, `^vault:v1:`, encrypted["ciphertext"], "re-running the hook must not rotate the key")
	status, decrypted := h.call(h.token, http.MethodPost, "/v1/transit/decrypt/api-keys", fmt.Sprintf(`{"ciphertext":%q}`, encrypted["ciphertext"]))
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, plaintext, decrypted["plaintext"])
	status, hmac := h.call(h.token, http.MethodPost, "/v1/transit/hmac/api-keys", fmt.Sprintf(`{"input":%q}`, plaintext))
	require.Equal(t, http.StatusOK, status)
	require.NotEmpty(t, hmac["hmac"])
	status, _ = h.call(h.token, http.MethodPost, "/v1/secret/data/example", `{"data":{"value":"seed"}}`)
	require.Equal(t, http.StatusOK, status)
	status, stored := h.call(h.token, http.MethodGet, "/v1/secret/data/example", "")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, map[string]any{"value": "seed"}, stored["data"])
}

// SP-SEC-04 against the real server: the token consumers present reaches its
// own paths and nothing else. It is not the store's root token — the store's
// root token exists only inside the container and is not this value.
func TestEphemeralRenderIssuesAScopedToken(t *testing.T) {
	h := newEphemeralHarness(t, "ephemeral-scope-access-token")
	require.Contains(t, h.provision(), "installed the access token")

	status, lookup := h.call(h.token, http.MethodGet, "/v1/auth/token/lookup-self", "")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, []any{consumerPolicyName, "default"}, lookup["policies"])
	require.Equal(t, true, lookup["orphan"])
	require.Greater(t, lookup["ttl"], float64(9*365*24*time.Hour/time.Second),
		"scope must not have cost the token its lifetime")

	bootstrapRoot := h.docker("exec", h.container, "cat", "/tmp/vault-dev-root")
	require.Len(t, bootstrapRoot, 64)
	require.NotEqual(t, h.token, bootstrapRoot, "the consumer's token is not the store's root token")

	for _, denied := range []struct {
		method, path, body string
	}{
		{http.MethodGet, "/v1/sys/mounts", ""},
		{http.MethodPost, "/v1/sys/mounts/another", `{"type":"kv"}`},
		{http.MethodGet, "/v1/sys/policies/acl/" + consumerPolicyName, ""},
		{http.MethodPost, "/v1/sys/policies/acl/widen", `{"policy":"path \"*\" { capabilities = [\"sudo\"] }"}`},
		{http.MethodPost, "/v1/auth/token/create-orphan", `{"policies":["root"]}`},
		{http.MethodPost, "/v1/transit/keys/another-key", `{"type":"aes256-gcm96"}`},
		{http.MethodPost, "/v1/transit/keys/api-keys/rotate", ""},
		{http.MethodPost, "/v1/transit/keys/api-keys/config", `{"deletion_allowed":true}`},
	} {
		status, _ = h.call(h.token, denied.method, denied.path, denied.body)
		require.Equal(t, http.StatusForbidden, status, "%s %s was permitted", denied.method, denied.path)
	}
}

// SP-SEC-03: no start-up credential appears in the workload's output, in
// development mode either. `vault server -dev` announces its unseal key and its
// root token on standard output; provision/dev.sh keeps that stream out of the
// container's output and leaves the log stream untouched.
func TestEphemeralRenderKeepsStartupCredentialsOutOfOutput(t *testing.T) {
	h := newEphemeralHarness(t, "ephemeral-log-access-token")
	require.Contains(t, h.provision(), `transit engine and key "api-keys" ready`)

	output := h.output()
	// The server really did start and really is logging into this stream.
	require.Contains(t, output, "core: vault is unsealed")
	require.Contains(t, output, "successful mount: namespace=\"\" path=transit/")

	bootstrapRoot := h.docker("exec", h.container, "cat", "/tmp/vault-dev-root")
	require.Len(t, bootstrapRoot, 64)
	require.NotContains(t, output, bootstrapRoot, "the store's root token is in the workload's output")
	require.NotContains(t, output, h.token, "the consumer's token is in the workload's output")
	for _, label := range []string{"Unseal Key:", "Root Token:"} {
		require.NotContains(t, output, label, "the dev banner's %q line is in the workload's output", label)
	}
}

// The local runtime keeps provisioning through the HTTP API on Start, exactly
// as before this agent learned to provision a deployed Vault.
func TestRuntimeEnableTransitIsUnchanged(t *testing.T) {
	type request struct{ method, path, body, token string }
	for _, test := range []struct {
		name       string
		transitKey string
		wantKey    string
		answer     func(path string) (int, string)
		wantErr    string
	}{
		{name: "fresh", wantKey: "api-keys", answer: func(string) (int, string) { return http.StatusNoContent, "" }},
		{name: "configured key", transitKey: "tenant-keys", wantKey: "tenant-keys", answer: func(string) (int, string) { return http.StatusNoContent, "" }},
		{name: "already provisioned", wantKey: "api-keys", answer: func(path string) (int, string) {
			if path == "/v1/sys/mounts/transit" {
				return http.StatusBadRequest, `{"errors":["path is already in use at transit/"]}`
			}
			return http.StatusBadRequest, `{"errors":["key already exists"]}`
		}},
		{name: "mount refused", wantKey: "api-keys", wantErr: "cannot enable transit engine", answer: func(string) (int, string) {
			return http.StatusForbidden, `{"errors":["permission denied"]}`
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var mu sync.Mutex
			var requests []request
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				mu.Lock()
				requests = append(requests, request{r.Method, r.URL.Path, string(body), r.Header.Get("X-Vault-Token")})
				mu.Unlock()
				status, answer := test.answer(r.URL.Path)
				w.WriteHeader(status)
				_, _ = io.WriteString(w, answer)
			}))
			defer server.Close()

			runtime := NewRuntime()
			if test.transitKey != "" {
				runtime.TransitKey = test.transitKey
			}
			runtime.vaultAddress = server.URL
			// Mounting and key creation are privileged: they present local
			// custody's administrative token, never the consumer's.
			runtime.vaultAdminToken = "local-admin-token"
			runtime.vaultToken = "local-consumer-token"
			err := runtime.enableTransit(context.Background())
			if test.wantErr != "" {
				require.ErrorContains(t, err, test.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, []request{
				{http.MethodPost, "/v1/sys/mounts/transit", `{"type":"transit"}`, "local-admin-token"},
				{http.MethodPost, "/v1/transit/keys/" + test.wantKey, `{"type":"aes256-gcm96"}`, "local-admin-token"},
			}, requests)
		})
	}
}
