package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// Local development custody only. Production initialization/unseal stays external.
// The lock covers the server lifetime, not just bootstrap: two local processes
// must never write one file-backend directory concurrently.
type localVaultState struct {
	dir  string
	lock *os.File
}

// RootToken and UnsealKey are custody: the agent's own administrative
// credentials for this local server. They stay in this file, are used only to
// provision the server and to mint the access token, and are never published to
// a consumer or written to output.
//
// AccessToken is what consumers receive. It is a separate orphan token carrying
// only consumerPolicyName, so a local consumer reaches exactly the paths it
// reads and writes — the same scope the deployed renders install.
type localVaultCredentials struct {
	RootToken   string `json:"root_token"`
	UnsealKey   string `json:"unseal_key"`
	AccessToken string `json:"access_token"`
}

func openLocalVaultState(dir string) (*localVaultState, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(dir, "runtime.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("local Vault state is already in use: %w", err)
	}
	return &localVaultState{dir: dir, lock: lock}, nil
}
func (s *localVaultState) close() {
	if s != nil && s.lock != nil {
		_ = syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN)
		_ = s.lock.Close()
		s.lock = nil
	}
}
func (s *localVaultState) config(file, data, listen string) error {
	raw, err := json.Marshal(map[string]any{"disable_mlock": true, "storage": map[string]any{"file": map[string]string{"path": data}}, "listener": map[string]any{"tcp": map[string]any{"address": listen, "tls_disable": true}}})
	if err != nil {
		return err
	}
	return os.WriteFile(file, raw, 0600)
}
func (s *localVaultState) load() (*localVaultCredentials, error) {
	raw, err := os.ReadFile(filepath.Join(s.dir, "credentials.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var c localVaultCredentials
	if json.Unmarshal(raw, &c) != nil || c.RootToken == "" || c.UnsealKey == "" {
		return nil, errors.New("invalid local Vault custody file; restore its backup, do not reinitialize")
	}
	return &c, nil
}
func (s *localVaultState) save(c *localVaultCredentials) error {
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(s.dir, ".credentials-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(f.Name(), filepath.Join(s.dir, "credentials.json")); err != nil {
		return err
	}
	d, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// call never includes tokens, request/response bodies, or unseal keys in errors.
func localVaultCall(ctx context.Context, address, method, path, token string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, address+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	response, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("local Vault request %s: %w", path, err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode >= 400 {
		return fmt.Errorf("local Vault %s returned HTTP %d", path, response.StatusCode)
	}
	if out == nil {
		_, err = io.Copy(io.Discard, response.Body)
		return err
	}
	if err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(out); err != nil {
		return fmt.Errorf("invalid local Vault response for %s", path)
	}
	return nil
}

// bootstrap brings the local server to the state consumers need and returns two
// tokens: the access token consumers are published, scoped to consumerPolicyName
// for transitKey, and the administrative token the agent keeps for its own
// privileged seeding. They are never the same token.
func (s *localVaultState) bootstrap(ctx context.Context, address, preferredToken, transitKey string) (string, string, error) {
	c, err := s.load()
	if err != nil {
		return "", "", err
	}
	var initialized struct {
		Initialized bool `json:"initialized"`
	}
	for i := 0; i < 30; i++ {
		err = localVaultCall(ctx, address, "GET", "/v1/sys/init", "", nil, &initialized)
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return "", "", ctx.Err()
		case <-time.After(time.Second):
		}
	}
	if err != nil {
		return "", "", err
	}
	if initialized.Initialized && c == nil {
		return "", "", errors.New("local Vault is initialized but local custody is missing; restore credentials.json, refusing to replace keys")
	}
	if !initialized.Initialized && c != nil {
		return "", "", errors.New("local Vault storage is missing but local custody exists; restore vault-data, refusing to replace keys")
	}
	if !initialized.Initialized {
		var result struct {
			Keys      []string `json:"keys_base64"`
			RootToken string   `json:"root_token"`
		}
		if err = localVaultCall(ctx, address, "POST", "/v1/sys/init", "", map[string]int{"secret_shares": 1, "secret_threshold": 1}, &result); err != nil {
			return "", "", err
		}
		if len(result.Keys) != 1 || result.RootToken == "" {
			return "", "", errors.New("invalid Vault initialization response")
		}
		// AccessToken stays empty: it is minted below as a scoped token, never
		// the root token this response carries.
		c = &localVaultCredentials{RootToken: result.RootToken, UnsealKey: result.Keys[0]}
		if err = s.save(c); err != nil {
			return "", "", fmt.Errorf("persist local Vault custody: %w", err)
		}
	}
	var unsealed struct {
		Sealed bool `json:"sealed"`
	}
	if err = localVaultCall(ctx, address, "POST", "/v1/sys/unseal", "", map[string]string{"key": c.UnsealKey}, &unsealed); err != nil {
		return "", "", err
	}
	if unsealed.Sealed {
		return "", "", errors.New("local Vault remains sealed")
	}
	// Dev mode previously mounted secret/ automatically. A file-backed server
	// needs the same KV v2 capability, installed once without replacing data.
	var mounts struct {
		Data map[string]struct {
			Type    string            `json:"type"`
			Options map[string]string `json:"options"`
		} `json:"data"`
	}
	if err = localVaultCall(ctx, address, "GET", "/v1/sys/mounts", c.RootToken, nil, &mounts); err != nil {
		return "", "", err
	}
	if mount, exists := mounts.Data["secret/"]; exists {
		if mount.Type != "kv" || mount.Options["version"] != "2" {
			return "", "", errors.New("local Vault secret/ mount must be KV v2")
		}
	} else if err = localVaultCall(ctx, address, "POST", "/v1/sys/mounts/secret", c.RootToken, map[string]any{"type": "kv", "options": map[string]string{"version": "2"}}, nil); err != nil {
		return "", "", err
	}
	// Rewritten on every start, so a changed transit-key reaches the policy the
	// published token already carries.
	if err = localVaultCall(ctx, address, "PUT", "/v1/sys/policies/acl/"+consumerPolicyName, c.RootToken,
		map[string]string{"policy": consumerPolicy(transitKey)}, nil); err != nil {
		return "", "", fmt.Errorf("install the local Vault %s policy: %w", consumerPolicyName, err)
	}
	accessToken, err := s.ensureAccessToken(ctx, address, c, preferredToken)
	if err != nil {
		return "", "", err
	}
	return accessToken, c.RootToken, nil
}

// accessTokenPolicies is what Vault holds for token, and the error the previous
// behaviour already failed closed on: custody can be stale or belong to another
// server even when unseal and root access succeed, and a token Vault rejects is
// never published or silently replaced.
func accessTokenPolicies(ctx context.Context, address, token string) ([]string, error) {
	var lookup struct {
		Data struct {
			Policies []string `json:"policies"`
		} `json:"data"`
	}
	if err := localVaultCall(ctx, address, "GET", "/v1/auth/token/lookup-self", token, nil, &lookup); err != nil {
		return nil, fmt.Errorf("validate local Vault access custody: %w", err)
	}
	return lookup.Data.Policies, nil
}

// scopedToConsumerPolicy reports whether policies are a consumer's scope and
// nothing wider. Vault adds its own `default` policy to every non-root token;
// anything else, root above all, means the token grants more than the paths a
// consumer reads.
func scopedToConsumerPolicy(policies []string) bool {
	found := false
	for _, policy := range policies {
		switch policy {
		case consumerPolicyName:
			found = true
		case "default":
		default:
			return false
		}
	}
	return found
}

// ensureAccessToken returns the token to publish: the one in custody when it is
// already an orphan scoped to consumerPolicyName and matches the configured id,
// otherwise a freshly minted one. A token that is being replaced is revoked
// first — except the root token itself, which custody from an earlier version of
// this agent published directly and which stays as the administrative
// credential.
func (s *localVaultState) ensureAccessToken(ctx context.Context, address string, c *localVaultCredentials, preferredToken string) (string, error) {
	if have := c.AccessToken; have != "" && have != c.RootToken {
		policies, err := accessTokenPolicies(ctx, address, have)
		if err != nil {
			return "", err
		}
		if scopedToConsumerPolicy(policies) && (preferredToken == "" || preferredToken == have) {
			return have, nil
		}
		if err = localVaultCall(ctx, address, "POST", "/v1/auth/token/revoke", c.RootToken,
			map[string]string{"token": have}, nil); err != nil {
			return "", fmt.Errorf("replace the local Vault access token: %w", err)
		}
	}
	// Vault caps a non-root token at the token store's max lease TTL and a
	// scoped token cannot renew itself, so the ceiling is raised before the
	// token is created: see consumerTokenTTL.
	if err := localVaultCall(ctx, address, "PUT", "/v1/sys/auth/token/tune", c.RootToken,
		map[string]string{"max_lease_ttl": consumerTokenTTL}, nil); err != nil {
		return "", fmt.Errorf("raise the local Vault token store's maximum lease TTL: %w", err)
	}
	request := map[string]any{
		"policies":     []string{consumerPolicyName},
		"no_parent":    true,
		"ttl":          consumerTokenTTL,
		"display_name": consumerPolicyName,
	}
	if preferredToken != "" {
		request["id"] = preferredToken
	}
	var created struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := localVaultCall(ctx, address, "POST", "/v1/auth/token/create-orphan", c.RootToken, request, &created); err != nil {
		return "", fmt.Errorf("create the local Vault access token: %w", err)
	}
	if created.Auth.ClientToken == "" {
		return "", errors.New("local Vault returned no access token")
	}
	policies, err := accessTokenPolicies(ctx, address, created.Auth.ClientToken)
	if err != nil {
		return "", err
	}
	if !scopedToConsumerPolicy(policies) {
		return "", fmt.Errorf("local Vault issued an access token outside the %s policy", consumerPolicyName)
	}
	c.AccessToken = created.Auth.ClientToken
	if err = s.save(c); err != nil {
		return "", err
	}
	return c.AccessToken, nil
}
