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
	defer os.Remove(f.Name())
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
	defer d.Close()
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
	defer response.Body.Close()
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
func (s *localVaultState) bootstrap(ctx context.Context, address, preferredToken string) (string, error) {
	c, err := s.load()
	if err != nil {
		return "", err
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
			return "", ctx.Err()
		case <-time.After(time.Second):
		}
	}
	if err != nil {
		return "", err
	}
	if initialized.Initialized && c == nil {
		return "", errors.New("Vault is initialized but local custody is missing; restore credentials.json, refusing to replace keys")
	}
	if !initialized.Initialized && c != nil {
		return "", errors.New("Vault storage is missing but local custody exists; restore vault-data, refusing to replace keys")
	}
	if !initialized.Initialized {
		var result struct {
			Keys      []string `json:"keys_base64"`
			RootToken string   `json:"root_token"`
		}
		if err = localVaultCall(ctx, address, "POST", "/v1/sys/init", "", map[string]int{"secret_shares": 1, "secret_threshold": 1}, &result); err != nil {
			return "", err
		}
		if len(result.Keys) != 1 || result.RootToken == "" {
			return "", errors.New("invalid Vault initialization response")
		}
		c = &localVaultCredentials{RootToken: result.RootToken, UnsealKey: result.Keys[0], AccessToken: result.RootToken}
		if err = s.save(c); err != nil {
			return "", fmt.Errorf("persist local Vault custody: %w", err)
		}
	}
	var unsealed struct {
		Sealed bool `json:"sealed"`
	}
	if err = localVaultCall(ctx, address, "POST", "/v1/sys/unseal", "", map[string]string{"key": c.UnsealKey}, &unsealed); err != nil {
		return "", err
	}
	if unsealed.Sealed {
		return "", errors.New("local Vault remains sealed")
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
		return "", err
	}
	if mount, exists := mounts.Data["secret/"]; exists {
		if mount.Type != "kv" || mount.Options["version"] != "2" {
			return "", errors.New("local Vault secret/ mount must be KV v2")
		}
	} else if err = localVaultCall(ctx, address, "POST", "/v1/sys/mounts/secret", c.RootToken, map[string]any{"type": "kv", "options": map[string]string{"version": "2"}}, nil); err != nil {
		return "", err
	}
	if preferredToken != "" && preferredToken != c.AccessToken {
		if err = localVaultCall(ctx, address, "POST", "/v1/auth/token/create-orphan", c.RootToken, map[string]any{"id": preferredToken, "policies": []string{"root"}, "no_parent": true}, nil); err != nil {
			return "", err
		}
		c.AccessToken = preferredToken
		if err = s.save(c); err != nil {
			return "", err
		}
	}
	if c.AccessToken == "" {
		return c.RootToken, nil
	}
	return c.AccessToken, nil
}
