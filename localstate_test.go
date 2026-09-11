package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLocalVaultCustodyLockAndPermissions(t *testing.T) {
	dir := t.TempDir()
	s, err := openLocalVaultState(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if second, err := openLocalVaultState(dir); err == nil {
		second.close()
		t.Fatal("concurrent state owner admitted")
	}
	original := &localVaultCredentials{RootToken: "fixture-root", UnsealKey: "fixture-key", AccessToken: "fixture-access"}
	if err = s.save(original); err != nil {
		t.Fatal(err)
	}
	loaded, err := s.load()
	if err != nil || *loaded != *original {
		t.Fatal("custody round trip failed")
	}
	info, _ := os.Stat(filepath.Join(dir, "credentials.json"))
	if info.Mode().Perm() != 0600 {
		t.Fatal("custody permissions")
	}
	s.close()
	reopened, err := openLocalVaultState(dir)
	if err != nil {
		t.Fatal(err)
	}
	reopened.close()
}
func TestLocalVaultRefusesMismatchedCustodyAndStorage(t *testing.T) {
	for _, initialized := range []bool{false, true} {
		t.Run(fmt.Sprint(initialized), func(t *testing.T) {
			s, err := openLocalVaultState(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer s.close()
			if !initialized {
				if err = s.save(&localVaultCredentials{RootToken: "root", UnsealKey: "key", AccessToken: "root"}); err != nil {
					t.Fatal(err)
				}
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.Path != "/v1/sys/init" {
					t.Error("attempted to replace missing state")
					w.WriteHeader(500)
					return
				}
				fmt.Fprintf(w, `{"initialized":%t}`, initialized)
			}))
			defer server.Close()
			if _, err = s.bootstrap(t.Context(), server.URL, ""); err == nil {
				t.Fatal("accepted inconsistent local state")
			}
		})
	}
}

// Explicit opt-in, isolated random loopback port and owned container/directory.
func TestLocalVaultRestartKeepsCiphertext(t *testing.T) {
	image := os.Getenv("VAULT_PERSISTENCE_IMAGE")
	if image == "" {
		t.Skip("set VAULT_PERSISTENCE_IMAGE to the installed pinned runtime image")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	dir := t.TempDir()
	state, err := openLocalVaultState(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { state.close() }()
	if err = state.config(filepath.Join(dir, "server.json"), "/vault/file/vault-data", "0.0.0.0:8200"); err != nil {
		t.Fatal(err)
	}
	docker := func(args ...string) string {
		t.Helper()
		raw, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("docker %s failed: %v (%s)", args[0], err, strings.TrimSpace(string(raw)))
		}
		return strings.TrimSpace(string(raw))
	}
	start := func() (string, string) {
		id := docker("run", "-d", "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "-e", "SKIP_SETCAP=true", "-p", "127.0.0.1::8200", "-v", dir+":/vault/file", image, "vault", "server", "-config=/vault/file/server.json")
		t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", id).Run() })
		port := docker("port", id, "8200/tcp")
		return id, "http://" + port
	}
	id, address := start()
	token, err := state.bootstrap(ctx, address, "")
	if err != nil {
		t.Fatal(err)
	}
	call := func(method, path string, body, out any) {
		t.Helper()
		if err := localVaultCall(ctx, address, method, path, token, body, out); err != nil {
			t.Fatal(err)
		}
	}
	call("POST", "/v1/sys/mounts/transit", map[string]string{"type": "transit"}, nil)
	call("POST", "/v1/transit/keys/fixture", map[string]string{"type": "aes256-gcm96"}, nil)
	var encrypted struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	call("POST", "/v1/transit/encrypt/fixture", map[string]string{"plaintext": base64.StdEncoding.EncodeToString([]byte("restart-proof"))}, &encrypted)
	call("POST", "/v1/secret/data/restart-proof", map[string]any{"data": map[string]string{"value": "preserved"}}, nil)
	if encrypted.Data.Ciphertext == "" {
		t.Fatal("no ciphertext")
	}
	docker("stop", id)
	docker("rm", id)
	state.close()
	state, err = openLocalVaultState(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, address = start()
	recovered, err := state.bootstrap(ctx, address, "")
	if err != nil {
		t.Fatal(err)
	}
	if recovered != token {
		t.Fatal("access token changed on restart")
	}
	var decrypted struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	call("POST", "/v1/transit/decrypt/fixture", map[string]string{"ciphertext": encrypted.Data.Ciphertext}, &decrypted)
	if decrypted.Data.Plaintext != base64.StdEncoding.EncodeToString([]byte("restart-proof")) {
		t.Fatal("ciphertext did not survive replacement")
	}
	var stored struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}
	call("GET", "/v1/secret/data/restart-proof", nil, &stored)
	if stored.Data.Data["value"] != "preserved" {
		t.Fatal("KV v2 value did not survive replacement")
	}
	t.Log("file backend and local custody survived container replacement; original ciphertext decrypted")
}
