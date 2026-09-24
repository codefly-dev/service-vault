package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	builderv0 "github.com/codefly-dev/core/generated/go/codefly/services/builder/v0"
	"github.com/stretchr/testify/require"
)

// The durable server refuses to start without an auto-unseal seal: a sealed
// server with nobody holding its unseal keys would take every consumer down on
// the first restart. The check runs before the script touches anything.
func TestDurableServerRequiresAnAutoUnsealSeal(t *testing.T) {
	for _, test := range []struct {
		name string
		seal string
		want string
	}{
		{name: "no seal", want: "no auto-unseal seal is configured"},
		{name: "shamir", seal: "shamir", want: "VAULT_SEAL_TYPE=shamir is not an auto-unseal seal"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cmd := exec.Command("/bin/sh", "-c", serverScript, "vault-server")
			cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
			if test.seal != "" {
				cmd.Env = append(cmd.Env, "VAULT_SEAL_TYPE="+test.seal)
			}
			out, err := cmd.CombinedOutput()
			var exitErr *exec.ExitError
			require.ErrorAs(t, err, &exitErr)
			require.Equal(t, 78, exitErr.ExitCode())
			require.Contains(t, string(out), test.want)
		})
	}
}

func TestDurableProvisioningRefusesBadInputs(t *testing.T) {
	for _, test := range []struct {
		name string
		env  []string
		args []string
		want string
	}{
		{name: "no access token", args: []string{"durable", "api-keys"}, want: "VAULT_ACCESS_TOKEN is not set"},
		{name: "token outside the token alphabet", env: []string{`VAULT_ACCESS_TOKEN=a"b`}, args: []string{"durable", "api-keys"}, want: "holds characters a Vault token id cannot carry"},
		{name: "unknown mode", env: []string{"VAULT_ACCESS_TOKEN=t"}, args: []string{"prod", "api-keys"}, want: `unknown mode "prod"`},
		{name: "no key", env: []string{"VAULT_ACCESS_TOKEN=t"}, args: []string{"durable"}, want: "usage: provision.sh"},
	} {
		t.Run(test.name, func(t *testing.T) {
			// No vault binary on PATH: a refused input must stop before any call.
			cmd := exec.Command("/bin/sh", append([]string{"-c", provisionScript, "vault-provision"}, test.args...)...)
			cmd.Env = append([]string{"PATH=/nonexistent"}, test.env...)
			out, err := cmd.CombinedOutput()
			var exitErr *exec.ExitError
			require.ErrorAs(t, err, &exitErr)
			require.Equal(t, 64, exitErr.ExitCode())
			require.Contains(t, string(out), test.want)
		})
	}
}

// durableHarness runs the pinned image exactly as the restricted render does:
// the rendered container command on a read-only root filesystem with a
// persistent data volume, and the rendered postStart hook executed inside it.
// The seal is a transit seal served by a second, throwaway Vault — the local
// stand-in for the cloud KMS an environment supplies (gcpckms on GCP), passed
// the way the environment passes it: as environment variables.
type durableHarness struct {
	t       *testing.T
	ctx     context.Context
	suffix  string
	network string
	server  []string
	hook    []string
}

func newDurableHarness(t *testing.T) *durableHarness {
	t.Helper()
	response, destination := deployRestricted(t, "")
	require.Equal(t, builderv0.DeploymentStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())
	container := renderedVaultContainer(t, destination)
	require.NotEmpty(t, container.Command)
	require.NotEmpty(t, container.Lifecycle.PostStart.Exec.Command)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	t.Cleanup(cancel)
	suffix := make([]byte, 4)
	_, err := rand.Read(suffix)
	require.NoError(t, err)
	h := &durableHarness{
		t: t, ctx: ctx, suffix: hex.EncodeToString(suffix),
		server: container.Command, hook: container.Lifecycle.PostStart.Exec.Command,
	}
	h.network = "vault-durable-" + h.suffix
	h.docker("network", "create", h.network)
	t.Cleanup(func() { _ = exec.Command("docker", "network", "rm", h.network).Run() })

	kms := "kms-" + h.suffix
	h.docker("run", "-d", "--name", kms, "--network", h.network,
		"-e", "VAULT_DEV_ROOT_TOKEN_ID=kms-token", "-e", "SKIP_SETCAP=true",
		image.FullName(), "server", "-dev", "-dev-listen-address=0.0.0.0:8200")
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-fv", kms).Run() })
	h.eventually(func() error {
		_, err := h.try("exec", "-e", "VAULT_ADDR=http://127.0.0.1:8200", "-e", "VAULT_TOKEN=kms-token", kms, "vault", "status")
		return err
	})
	h.docker("exec", "-e", "VAULT_ADDR=http://127.0.0.1:8200", "-e", "VAULT_TOKEN=kms-token", kms,
		"sh", "-c", "vault secrets enable transit && vault write -f transit/keys/unseal")
	return h
}

func (h *durableHarness) try(args ...string) (string, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(h.ctx, "docker", args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err != nil {
		return stdout.String() + stderr.String(), fmt.Errorf("docker %s: %w: %s%s", args[0], err, stdout.String(), stderr.String())
	}
	return stdout.String() + stderr.String(), nil
}

func (h *durableHarness) docker(args ...string) string {
	h.t.Helper()
	out, err := h.try(args...)
	require.NoError(h.t, err)
	return strings.TrimSpace(out)
}

func (h *durableHarness) eventually(check func() error) {
	h.t.Helper()
	var err error
	for range 60 {
		if err = check(); err == nil {
			return
		}
		time.Sleep(time.Second)
	}
	require.NoError(h.t, err)
}

// volume creates a data volume owned the way fsGroup makes a PVC writable.
func (h *durableHarness) volume(name string) string {
	h.t.Helper()
	volume := name + "-" + h.suffix
	h.docker("volume", "create", volume)
	h.t.Cleanup(func() { _ = exec.Command("docker", "volume", "rm", "-f", volume).Run() })
	h.docker("run", "--rm", "-u", "0", "-v", volume+":/vault/data", "--entrypoint", "chown", image.FullName(), "100:1000", "/vault/data")
	return volume
}

// start runs the rendered server command against volume and returns the
// container name and its published address.
func (h *durableHarness) start(volume, accessToken string, extraEnv ...string) (string, string) {
	h.t.Helper()
	name := fmt.Sprintf("vault-%s-%d", h.suffix, time.Now().UnixNano())
	args := []string{"run", "-d", "--name", name, "--network", h.network,
		"--read-only", "--tmpfs", "/tmp:mode=1777", "--tmpfs", "/home/vault:mode=1777",
		"-u", "100:1000", "--cap-drop", "ALL",
		"-v", volume + ":/vault/data", "-p", "127.0.0.1::8200",
		"-e", "VAULT_ACCESS_TOKEN=" + accessToken,
		"-e", "VAULT_SEAL_TYPE=transit",
		"-e", "VAULT_ADDR=http://kms-" + h.suffix + ":8200",
		"-e", "VAULT_TOKEN=kms-token",
		"-e", "VAULT_TRANSIT_SEAL_KEY_NAME=unseal",
		"-e", "VAULT_TRANSIT_SEAL_MOUNT_PATH=transit/",
	}
	for _, env := range extraEnv {
		args = append(args, "-e", env)
	}
	args = append(args, "--entrypoint", h.server[0], image.FullName())
	args = append(args, h.server[1:]...)
	h.docker(args...)
	h.t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	return name, "http://" + h.docker("port", name, "8200/tcp")
}

// provision runs the rendered hook in the container, as the kubelet does.
func (h *durableHarness) provision(container string) (string, error) {
	return h.try(append([]string{"exec", container}, h.hook...)...)
}

func (h *durableHarness) stop(container string) {
	h.t.Helper()
	h.docker("rm", "-f", container)
}

func (h *durableHarness) call(address, token, method, path, body string) (int, map[string]any) {
	h.t.Helper()
	request, err := http.NewRequestWithContext(h.ctx, method, address+path, strings.NewReader(body))
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
	if len(raw) > 0 {
		require.NoError(h.t, json.Unmarshal(raw, &decoded), string(raw))
	}
	return response.StatusCode, decoded.Data
}

func (h *durableHarness) initRecord(volume string) map[string]any {
	h.t.Helper()
	mode := h.docker("run", "--rm", "-u", "0", "-v", volume+":/vault/data", "--entrypoint", "stat", image.FullName(),
		"-c", "%a %U", "/vault/data/bootstrap", "/vault/data/bootstrap/init.json")
	require.Equal(h.t, "700 vault\n600 vault", mode, "the init record is private to the vault user")
	raw := h.docker("run", "--rm", "-u", "0", "-v", volume+":/vault/data", "--entrypoint", "cat", image.FullName(), "/vault/data/bootstrap/init.json")
	var record map[string]any
	require.NoError(h.t, json.Unmarshal([]byte(raw), &record), raw)
	return record
}

// TestDurableVaultSurvivesRestart is the property a deployed cell needs: what
// consumers encrypted, HMACed and stored before a restart is still readable
// after it, with the same token, and the provisioning hook changes nothing on
// an already-provisioned Vault.
func TestDurableVaultSurvivesRestart(t *testing.T) {
	h := newDurableHarness(t)
	volume := h.volume("data")
	const token = "composition-access-token"

	first, address := h.start(volume, token)
	out, err := h.provision(first)
	require.NoError(t, err, out)
	require.Contains(t, out, "initialized; recovery key material is in /vault/data/bootstrap/init.json")
	require.Contains(t, out, "installed the access token")
	require.Contains(t, out, "revoked the initial root token")
	require.Contains(t, out, `transit engine and key "api-keys" ready`)

	// The initial root token is gone from the volume and from Vault; the
	// recovery key is kept; the access token is a non-expiring root-policy
	// orphan the consumers and the environment's seeding present.
	record := h.initRecord(volume)
	require.Equal(t, "", record["root_token"])
	require.Len(t, record["recovery_keys_b64"], 1)
	status, lookup := h.call(address, token, http.MethodGet, "/v1/auth/token/lookup-self", "")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, []any{"root"}, lookup["policies"])
	require.Equal(t, true, lookup["orphan"])
	require.EqualValues(t, 0, lookup["ttl"])

	// A consumer's state: a ciphertext, an HMAC, and a KV v2 secret written
	// the way the environment seeds the host's signing key.
	plaintext := base64.StdEncoding.EncodeToString([]byte("credential"))
	status, encrypted := h.call(address, token, http.MethodPost, "/v1/transit/encrypt/api-keys", fmt.Sprintf(`{"plaintext":%q}`, plaintext))
	require.Equal(t, http.StatusOK, status)
	status, hmac := h.call(address, token, http.MethodPost, "/v1/transit/hmac/api-keys", fmt.Sprintf(`{"input":%q}`, plaintext))
	require.Equal(t, http.StatusOK, status)
	status, _ = h.call(address, token, http.MethodPost, "/v1/secret/data/example", `{"data":{"private_key":"seed"}}`)
	require.Equal(t, http.StatusOK, status)

	// Twice more on the same process: nothing to do.
	for range 2 {
		out, err = h.provision(first)
		require.NoError(t, err, out)
		require.Equal(t, "vault provisioning: transit engine and key \"api-keys\" ready", strings.TrimSpace(out))
	}

	// Replace the container (a pod restart, a reschedule, a rollout).
	h.stop(first)
	second, address := h.start(volume, token)
	out, err = h.provision(second)
	require.NoError(t, err, out)
	require.Equal(t, "vault provisioning: transit engine and key \"api-keys\" ready", strings.TrimSpace(out),
		"a restarted Vault unseals itself and needs no initialization, token or key")

	status, decrypted := h.call(address, token, http.MethodPost, "/v1/transit/decrypt/api-keys", fmt.Sprintf(`{"ciphertext":%q}`, encrypted["ciphertext"]))
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, plaintext, decrypted["plaintext"], "a ciphertext from before the restart decrypts after it")
	status, again := h.call(address, token, http.MethodPost, "/v1/transit/hmac/api-keys", fmt.Sprintf(`{"input":%q}`, plaintext))
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, hmac["hmac"], again["hmac"], "an API-key HMAC from before the restart still matches")
	status, secret := h.call(address, token, http.MethodGet, "/v1/secret/data/example", "")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, map[string]any{"private_key": "seed"}, secret["data"])
	status, key := h.call(address, token, http.MethodGet, "/v1/transit/keys/api-keys", "")
	require.Equal(t, http.StatusOK, status)
	require.EqualValues(t, 1, key["latest_version"], "the key was never rotated")

	// A different token on the same Vault is refused, not silently installed:
	// the initial root token is gone, and rotating the access token is an
	// operator step taken with the current one.
	h.stop(second)
	third, _ := h.start(volume, "some-other-token")
	out, err = h.provision(third)
	require.Error(t, err)
	require.Contains(t, out, "vault rejects VAULT_ACCESS_TOKEN and cannot install it")
}

// A data volume that lost its storage but kept its init record must not be
// initialized over: that would mint fresh keys and hide the loss.
func TestDurableVaultRefusesToInitializeOverAnInitRecord(t *testing.T) {
	h := newDurableHarness(t)
	volume := h.volume("mismatch")
	h.docker("run", "--rm", "-u", "100:1000", "-v", volume+":/vault/data", "--entrypoint", "sh", image.FullName(),
		"-c", `mkdir -p /vault/data/bootstrap && echo '{"root_token": ""}' > /vault/data/bootstrap/init.json`)
	container, _ := h.start(volume, "composition-access-token")
	out, err := h.provision(container)
	require.Error(t, err)
	require.Contains(t, out, "vault storage is uninitialized but /vault/data/bootstrap/init.json exists")
	raw := h.docker("exec", container, "wget", "-qO-", "http://127.0.0.1:8200/v1/sys/init")
	require.JSONEq(t, `{"initialized":false}`, raw, "the server was left uninitialized")
}

// With VAULT_RECOVERY_PGP_KEY the recovery key is only ever written encrypted
// to that recipient.
func TestDurableVaultEncryptsTheRecoveryKey(t *testing.T) {
	gpg, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("gpg is not installed; the PGP recovery path is exercised where it is")
	}
	// A short home: gpg-agent's socket path must fit the platform's limit,
	// which a nested t.TempDir() can exceed.
	home, err := os.MkdirTemp("", "gpg")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = exec.Command("gpgconf", "--homedir", home, "--kill", "gpg-agent").Run()
		_ = os.RemoveAll(home)
	})
	run := func(stdin []byte, args ...string) []byte {
		t.Helper()
		cmd := exec.Command(gpg, append([]string{"--homedir", home, "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", ""}, args...)...)
		cmd.Stdin = bytes.NewReader(stdin)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		require.NoError(t, err, stderr.String())
		return out
	}
	require.NoError(t, os.Chmod(home, 0o700))
	run(nil, "--quick-generate-key", "recovery@example.com", "rsa3072", "encr", "never")
	public := base64.StdEncoding.EncodeToString(run(nil, "--export", "recovery@example.com"))

	h := newDurableHarness(t)
	volume := h.volume("pgp")
	container, _ := h.start(volume, "composition-access-token", "VAULT_RECOVERY_PGP_KEY="+public)
	out, err := h.provision(container)
	require.NoError(t, err, out)

	record := h.initRecord(volume)
	shares, ok := record["recovery_keys_b64"].([]any)
	require.True(t, ok)
	require.Len(t, shares, 1)
	encrypted, err := base64.StdEncoding.DecodeString(shares[0].(string))
	require.NoError(t, err)
	recovery := run(encrypted, "--decrypt")
	require.Regexp(t, `^[0-9a-f]{64}$`, string(recovery), "the recipient decrypts the hex-encoded 32-byte recovery key")
	_, err = h.try("run", "--rm", "-u", "0", "-v", volume+":/vault/data", "--entrypoint", "test", image.FullName(), "-e", "/vault/data/bootstrap/recovery.pgp")
	require.Error(t, err, "the staged public key is removed after initialization")
	require.Equal(t, "", record["root_token"])
}
