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

type renderedContainer struct {
	Name      string `yaml:"name"`
	Lifecycle struct {
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
		Template struct {
			Spec struct {
				Containers []renderedContainer `yaml:"containers"`
			} `yaml:"spec"`
		} `yaml:"template"`
	} `yaml:"spec"`
}

func renderedVaultContainer(t *testing.T, destination string) renderedContainer {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(destination, "base", "stateful-set.yaml"))
	require.NoError(t, err)
	var statefulSet renderedStatefulSet
	require.NoError(t, yaml.Unmarshal(content, &statefulSet))
	require.Len(t, statefulSet.Spec.Template.Spec.Containers, 1)
	return statefulSet.Spec.Template.Spec.Containers[0]
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

// The restricted render is what a deployed cell runs. Its Vault must come up
// with the transit engine and the configured key, or every consumer's
// /v1/transit/encrypt|hmac/<key> answers 404.
func TestRestrictedRenderProvisionsTransitOnVaultStart(t *testing.T) {
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

			container := renderedVaultContainer(t, destination)
			require.Equal(t, "vault", container.Name)
			require.Equal(t,
				[]string{"/bin/sh", "-c", transitProvisionScript, "vault-provision", test.want},
				container.Lifecycle.PostStart.Exec.Command,
				"the hook runs the embedded script verbatim with the key name as $1")

			// The hook authenticates with the token the container already
			// holds, projected from the one secret reference the composition
			// supplies — no new secret, no literal value in the tree.
			var token []string
			for _, env := range container.Env {
				if env.Name == vaultTokenEnvironmentVariable {
					require.Empty(t, env.Value)
					require.NotNil(t, env.ValueFrom)
					token = append(token, env.ValueFrom.SecretKeyRef.Name+"/"+env.ValueFrom.SecretKeyRef.Key)
				}
			}
			require.Equal(t, []string{"vault-credentials/CODEFLY__SERVICE_SECRET_CONFIGURATION__MODULE__VAULT__VAULT__VAULT_TOKEN"}, token)
			require.Contains(t, transitProvisionScript, `VAULT_TOKEN="$VAULT_DEV_ROOT_TOKEN_ID"`)

			tree := readManifestTree(t, destination)
			require.NotContains(t, tree, "kind: Job", "provisioning follows the in-memory Vault process, not the rollout")
			require.NotContains(t, tree, "kind: Namespace")
			require.NotContains(t, tree, "kind: Secret")
		})
	}
}

// Local apply renders the same in-memory dev server, so it provisions the same way.
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
		[]string{"/bin/sh", "-c", transitProvisionScript, "vault-provision", "api-keys"},
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
// control flow. It models only the five invocations the script makes, keeps
// Vault's state as files, and appends every call to a log.
const fakeVault = `#!/bin/sh
state="$FAKE_VAULT_STATE"
echo "$VAULT_ADDR $VAULT_TOKEN $*" >> "$state/calls"
if [ -e "$state/down" ]; then echo "connection refused" >&2; exit 1; fi
case "$*" in
status) exit 0 ;;
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
*) echo "fake vault: unexpected invocation: $*" >&2; exit 99 ;;
esac
`

type provisionRun struct {
	state string
	bin   string
}

func newProvisionRun(t *testing.T) *provisionRun {
	t.Helper()
	run := &provisionRun{state: t.TempDir(), bin: t.TempDir()}
	require.NoError(t, os.WriteFile(filepath.Join(run.bin, "vault"), []byte(fakeVault), 0o755))
	return run
}

func (run *provisionRun) mark(t *testing.T, name, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(run.state, name), []byte(content), 0o644))
}

// exec runs the script exactly as the hook does: `sh -c <script> <$0> <key>`.
func (run *provisionRun) exec(t *testing.T, token string, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command("/bin/sh", append([]string{"-c", transitProvisionScript, "vault-provision"}, args...)...)
	cmd.Env = []string{
		"PATH=" + run.bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"FAKE_VAULT_STATE=" + run.state,
		"VAULT_PROVISION_ATTEMPTS=2",
	}
	if token != "" {
		cmd.Env = append(cmd.Env, "VAULT_DEV_ROOT_TOKEN_ID="+token)
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

	code, out := run.exec(t, "root-token", "api-keys")
	require.Equal(t, 0, code, out)
	require.Equal(t, []string{
		"http://127.0.0.1:8200 root-token secrets enable -path=transit transit",
		"http://127.0.0.1:8200 root-token write -f transit/keys/api-keys type=aes256-gcm96",
	}, run.writes(t), "a fresh Vault gets the engine and the key, over loopback, with the container's root token")

	// Every later start of the same process finds both and writes nothing.
	for range 2 {
		code, out = run.exec(t, "root-token", "api-keys")
		require.Equal(t, 0, code, out)
	}
	require.Len(t, run.writes(t), 2, "re-running must not re-enable the engine or rewrite the key")
}

func TestTransitProvisionScriptAcceptsExistingState(t *testing.T) {
	run := newProvisionRun(t)
	run.mark(t, "mount", "transit\n")
	run.mark(t, "key-api-keys", "chacha20-poly1305\n")

	code, out := run.exec(t, "root-token", "api-keys")
	require.Equal(t, 0, code, out)
	require.Empty(t, run.writes(t), "an existing engine and key are success and are left as they are")
}

func TestTransitProvisionScriptConvergesOnALostRace(t *testing.T) {
	run := newProvisionRun(t)
	run.mark(t, "race", "")

	code, out := run.exec(t, "root-token", "api-keys")
	require.Equal(t, 0, code, out)
	content, err := os.ReadFile(filepath.Join(run.state, "key-api-keys"))
	require.NoError(t, err)
	require.Equal(t, "aes256-gcm96\n", string(content))
}

func TestTransitProvisionScriptFailsClosed(t *testing.T) {
	t.Run("transit/ holds another engine", func(t *testing.T) {
		run := newProvisionRun(t)
		run.mark(t, "mount", "kv\n")
		code, out := run.exec(t, "root-token", "api-keys")
		require.Equal(t, 1, code)
		require.Contains(t, out, `transit/ is mounted as "kv", not a transit engine`)
		require.Empty(t, run.writes(t))
	})
	t.Run("engine cannot be enabled", func(t *testing.T) {
		run := newProvisionRun(t)
		run.mark(t, "deny", "")
		code, out := run.exec(t, "root-token", "api-keys")
		require.Equal(t, 1, code)
		require.Contains(t, out, "cannot enable the transit engine: permission denied")
	})
	t.Run("vault never answers", func(t *testing.T) {
		run := newProvisionRun(t)
		run.mark(t, "down", "")
		code, out := run.exec(t, "root-token", "api-keys")
		require.Equal(t, 1, code)
		require.Contains(t, out, "did not become ready")
	})
	t.Run("no token", func(t *testing.T) {
		run := newProvisionRun(t)
		code, out := run.exec(t, "", "api-keys")
		require.Equal(t, 64, code)
		require.Contains(t, out, "VAULT_DEV_ROOT_TOKEN_ID is not set")
		require.Empty(t, run.calls(t))
	})
	t.Run("no key name", func(t *testing.T) {
		run := newProvisionRun(t)
		code, out := run.exec(t, "root-token")
		require.Equal(t, 64, code)
		require.Contains(t, out, "transit key name is required")
		require.Empty(t, run.calls(t))
	})
}

// TestRenderedHookProvisionsThePinnedVault runs the pinned image the way the
// StatefulSet does — `server -dev`, read-only root filesystem, the root token
// in VAULT_DEV_ROOT_TOKEN_ID — then executes the rendered postStart command
// inside it, twice, and calls transit the way a consumer does.
func TestRenderedHookProvisionsThePinnedVault(t *testing.T) {
	response, destination := deployRestricted(t, "")
	require.Equal(t, builderv0.DeploymentStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())
	hook := renderedVaultContainer(t, destination).Lifecycle.PostStart.Exec.Command
	require.NotEmpty(t, hook)

	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	docker := func(args ...string) string {
		t.Helper()
		var stderr strings.Builder
		cmd := exec.CommandContext(ctx, "docker", args...)
		cmd.Stderr = &stderr
		raw, err := cmd.Output()
		if err != nil {
			t.Fatalf("docker %s failed: %v (%s%s)", args[0], err, raw, strings.TrimSpace(stderr.String()))
		}
		return strings.TrimSpace(string(raw))
	}
	const token = "provision-test-root-token"
	id := docker("run", "-d", "--read-only",
		"--tmpfs", "/tmp:mode=1777", "--tmpfs", "/home/vault:mode=1777",
		"-e", vaultTokenEnvironmentVariable+"="+token, "-e", "SKIP_SETCAP=true",
		"-p", "127.0.0.1::8200",
		image.FullName(), "server", "-dev", "-dev-listen-address=0.0.0.0:8200")
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-fv", id).Run() })
	address := "http://" + docker("port", id, "8200/tcp")

	// The hook starts with the server, so the first run also covers the wait.
	for range 2 {
		out := docker(append([]string{"exec", id}, hook...)...)
		require.Contains(t, out, `transit engine and key "api-keys" ready`)
	}

	call := func(path, body string) map[string]any {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, address+path, strings.NewReader(body))
		require.NoError(t, err)
		request.Header.Set("X-Vault-Token", token)
		response, err := http.DefaultClient.Do(request)
		require.NoError(t, err)
		defer func() { _ = response.Body.Close() }()
		raw, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, response.StatusCode, string(raw))
		var decoded struct {
			Data map[string]any `json:"data"`
		}
		require.NoError(t, json.Unmarshal(raw, &decoded))
		return decoded.Data
	}
	plaintext := base64.StdEncoding.EncodeToString([]byte("credential"))
	encrypted := call("/v1/transit/encrypt/api-keys", fmt.Sprintf(`{"plaintext":%q}`, plaintext))
	require.Regexp(t, `^vault:v1:`, encrypted["ciphertext"], "re-running the hook must not rotate the key")
	decrypted := call("/v1/transit/decrypt/api-keys", fmt.Sprintf(`{"ciphertext":%q}`, encrypted["ciphertext"]))
	require.Equal(t, plaintext, decrypted["plaintext"])
	require.NotEmpty(t, call("/v1/transit/hmac/api-keys", fmt.Sprintf(`{"input":%q}`, plaintext))["hmac"])
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
			runtime.vaultToken = "local-token"
			err := runtime.enableTransit(context.Background())
			if test.wantErr != "" {
				require.ErrorContains(t, err, test.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, []request{
				{http.MethodPost, "/v1/sys/mounts/transit", `{"type":"transit"}`, "local-token"},
				{http.MethodPost, "/v1/transit/keys/" + test.wantKey, `{"type":"aes256-gcm96"}`, "local-token"},
			}, requests)
		})
	}
}
