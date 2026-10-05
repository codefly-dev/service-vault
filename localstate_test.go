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
	"reflect"
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
				_, _ = fmt.Fprintf(w, `{"initialized":%t}`, initialized)
			}))
			defer server.Close()
			if _, _, err = s.bootstrap(t.Context(), server.URL, "", "api-keys"); err == nil {
				t.Fatal("accepted inconsistent local state")
			}
		})
	}
}

// fakeLocalVault answers the bootstrap sequence against an initialized,
// unsealed server with secret/ already mounted. It records what the policy and
// token endpoints were asked to do, which is what SP-SEC-04 turns on.
type fakeLocalVault struct {
	policies    map[string][]string // token id -> its policies
	policy      string              // the last ACL policy written, by its HCL
	tunedMaxTTL string              // the ceiling the token store was raised to
	revoked     []string
	minted      int
}

func (f *fakeLocalVault) start(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Vault-Token")
		var body map[string]any
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&body)
		}
		switch {
		case r.URL.Path == "/v1/sys/init":
			_, _ = io.WriteString(w, `{"initialized":true}`)
		case r.URL.Path == "/v1/sys/unseal":
			_, _ = io.WriteString(w, `{"sealed":false}`)
		case r.URL.Path == "/v1/sys/mounts":
			_, _ = io.WriteString(w, `{"data":{"secret/":{"type":"kv","options":{"version":"2"}}}}`)
		case r.URL.Path == "/v1/sys/auth/token/tune":
			f.tunedMaxTTL, _ = body["max_lease_ttl"].(string)
			w.WriteHeader(http.StatusNoContent)
		case strings.HasPrefix(r.URL.Path, "/v1/sys/policies/acl/"):
			f.policy, _ = body["policy"].(string)
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/v1/auth/token/lookup-self":
			policies, known := f.policies[token]
			if !known {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			raw, _ := json.Marshal(map[string]any{"data": map[string]any{"policies": policies}})
			_, _ = w.Write(raw)
		case r.URL.Path == "/v1/auth/token/revoke":
			id, _ := body["token"].(string)
			f.revoked = append(f.revoked, id)
			delete(f.policies, id)
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/v1/auth/token/create-orphan":
			f.minted++
			id, _ := body["id"].(string)
			if id == "" {
				id = fmt.Sprintf("minted-%d", f.minted)
			}
			granted := []string{"default"}
			for _, policy := range body["policies"].([]any) {
				granted = append(granted, policy.(string))
			}
			f.policies[id] = granted
			raw, _ := json.Marshal(map[string]any{"auth": map[string]any{"client_token": id}})
			_, _ = w.Write(raw)
		default:
			t.Errorf("unexpected call %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(server.Close)
	return server.URL
}

// SP-SEC-04 on the local runtime. What it publishes is a token carrying only the
// consumer policy, whatever custody it starts from — including custody written
// by a build that published the root token itself. The root token stays in
// custody as the administrative credential and is never revoked.
func TestLocalVaultPublishesOnlyAScopedAccessToken(t *testing.T) {
	for _, test := range []struct {
		name      string
		custody   localVaultCredentials
		preferred string
		wantToken string
		wantMint  bool
		wantRevk  []string
	}{
		{
			name:      "custody that published the root token",
			custody:   localVaultCredentials{RootToken: "root", UnsealKey: "key", AccessToken: "root"},
			wantToken: "minted-1",
			wantMint:  true,
		},
		{
			name:      "an access token installed with the root policy",
			custody:   localVaultCredentials{RootToken: "root", UnsealKey: "key", AccessToken: "wide"},
			wantToken: "minted-1",
			wantMint:  true,
			wantRevk:  []string{"wide"},
		},
		{
			name:      "an already scoped access token",
			custody:   localVaultCredentials{RootToken: "root", UnsealKey: "key", AccessToken: "scoped"},
			wantToken: "scoped",
		},
		{
			name:      "a configured token replaces a scoped one",
			custody:   localVaultCredentials{RootToken: "root", UnsealKey: "key", AccessToken: "scoped"},
			preferred: "configured",
			wantToken: "configured",
			wantMint:  true,
			wantRevk:  []string{"scoped"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := &fakeLocalVault{policies: map[string][]string{
				"root":   {"root"},
				"wide":   {"root"},
				"scoped": {consumerPolicyName, "default"},
			}}
			address := fake.start(t)
			state, err := openLocalVaultState(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer state.close()
			if err = state.save(&test.custody); err != nil {
				t.Fatal(err)
			}

			access, admin, err := state.bootstrap(t.Context(), address, test.preferred, "tenant-keys")
			if err != nil {
				t.Fatal(err)
			}
			if access != test.wantToken {
				t.Fatalf("published token = %q, want %q", access, test.wantToken)
			}
			if admin != test.custody.RootToken {
				t.Fatalf("administrative token = %q, want the root token in custody", admin)
			}
			if access == admin {
				t.Fatal("the published token is the administrative token")
			}
			if !scopedToConsumerPolicy(fake.policies[access]) {
				t.Fatalf("published token policies = %v", fake.policies[access])
			}
			if (fake.minted > 0) != test.wantMint {
				t.Fatalf("minted %d tokens, wantMint = %v", fake.minted, test.wantMint)
			}
			if fake.policy != consumerPolicy("tenant-keys") {
				t.Fatalf("installed policy = %q", fake.policy)
			}
			if test.wantMint && fake.tunedMaxTTL != consumerTokenTTL {
				t.Fatalf("token store max lease TTL = %q, want %q so the scoped token is not capped", fake.tunedMaxTTL, consumerTokenTTL)
			}
			if !reflect.DeepEqual(fake.revoked, test.wantRevk) {
				t.Fatalf("revoked %v, want %v", fake.revoked, test.wantRevk)
			}
			for _, revoked := range fake.revoked {
				if revoked == test.custody.RootToken {
					t.Fatal("the administrative token was revoked")
				}
			}
			// Custody records the published token, so the next start reuses it.
			saved, err := state.load()
			if err != nil {
				t.Fatal(err)
			}
			if saved.AccessToken != access || saved.RootToken != test.custody.RootToken {
				t.Fatalf("custody = %+v", saved)
			}
		})
	}
}

// Always exercise the production pin using owned containers and random loopback ports.
func TestLocalVaultRestartKeepsCiphertext(t *testing.T) {
	runtimeImage := image.FullName()
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
		// Pull progress goes to stderr on a fresh runner. Only stdout is the
		// container ID/port; mixing streams makes cold-image qualification fail.
		var stderr strings.Builder
		cmd := exec.CommandContext(ctx, "docker", args...)
		cmd.Stderr = &stderr
		raw, err := cmd.Output()
		if err != nil {
			t.Fatalf("docker %s failed: %v (%s)", args[0], err, strings.TrimSpace(stderr.String()))
		}
		return strings.TrimSpace(string(raw))
	}
	start := func() (string, string) {
		id := docker("run", "-d", "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "-e", "SKIP_SETCAP=true", "-p", "127.0.0.1::8200", "-v", dir+":/vault/file", runtimeImage, "vault", "server", "-config=/vault/file/server.json")
		t.Cleanup(func() { _ = exec.Command("docker", "rm", "-fv", id).Run() })
		port := docker("port", id, "8200/tcp")
		return id, "http://" + port
	}
	id, address := start()
	token, admin, err := state.bootstrap(ctx, address, "", "fixture")
	if err != nil {
		t.Fatal(err)
	}
	call := func(method, path string, body, out any) {
		t.Helper()
		if err := localVaultCall(ctx, address, method, path, token, body, out); err != nil {
			t.Fatal(err)
		}
	}
	// SP-SEC-04: what the local runtime publishes is not the administrative
	// token and carries only the consumer policy.
	if token == admin {
		t.Fatal("the published token is local custody's administrative token")
	}
	policies, err := accessTokenPolicies(ctx, address, token)
	if err != nil {
		t.Fatal(err)
	}
	if !scopedToConsumerPolicy(policies) {
		t.Fatalf("published token policies = %v, want only %q (and Vault's default)", policies, consumerPolicyName)
	}
	// Mounting and creating a key are privileged: local custody's own token
	// does them. The published token is a consumer's, and must not be able to.
	if err = localVaultCall(ctx, address, "POST", "/v1/sys/mounts/transit", token, map[string]string{"type": "transit"}, nil); err == nil {
		t.Fatal("the published token mounted a secrets engine")
	}
	if err = localVaultCall(ctx, address, "GET", "/v1/sys/mounts", token, nil, nil); err == nil {
		t.Fatal("the published token read every mount")
	}
	if err = localVaultCall(ctx, address, "POST", "/v1/auth/token/create-orphan", token, map[string]any{"policies": []string{"root"}}, nil); err == nil {
		t.Fatal("the published token minted a token")
	}
	if err = localVaultCall(ctx, address, "POST", "/v1/sys/mounts/transit", admin, map[string]string{"type": "transit"}, nil); err != nil {
		t.Fatal(err)
	}
	if err = localVaultCall(ctx, address, "POST", "/v1/transit/keys/fixture", admin, map[string]string{"type": "aes256-gcm96"}, nil); err != nil {
		t.Fatal(err)
	}
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
	docker("rm", "-v", id)
	state.close()
	state, err = openLocalVaultState(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, address = start()
	custodyPath := filepath.Join(dir, "credentials.json")
	original, err := os.ReadFile(custodyPath)
	if err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(dir, "credentials.backup")
	if err = os.Rename(custodyPath, backupPath); err != nil {
		t.Fatal(err)
	}
	if _, _, err = state.bootstrap(ctx, address, "", "fixture"); err == nil {
		t.Fatal("initialized storage accepted missing custody")
	}
	if err = os.Rename(backupPath, custodyPath); err != nil {
		t.Fatal(err)
	}
	custody, err := state.load()
	if err != nil {
		t.Fatal(err)
	}
	custody.UnsealKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
	if err = state.save(custody); err != nil {
		t.Fatal(err)
	}
	if _, _, err = state.bootstrap(ctx, address, "", "fixture"); err == nil {
		t.Fatal("initialized storage accepted mismatched custody")
	}
	if err = os.WriteFile(custodyPath, original, 0600); err != nil {
		t.Fatal(err)
	}
	custody, err = state.load()
	if err != nil {
		t.Fatal(err)
	}
	custody.AccessToken = "unrelated-access-token"
	if err = state.save(custody); err != nil {
		t.Fatal(err)
	}
	if _, _, err = state.bootstrap(ctx, address, "", "fixture"); err == nil {
		t.Fatal("initialized storage accepted mismatched access custody")
	}
	if err = os.WriteFile(custodyPath, original, 0600); err != nil {
		t.Fatal(err)
	}
	recovered, _, err := state.bootstrap(ctx, address, "", "fixture")
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
