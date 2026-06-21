package main

// nixvault.go — Docker-free vault runtime (mirrors postgres' nixpg.go, neo4j's
// nixneo4j.go, redis' nixredis.go).
//
// The vault service agent runs the server in a container by default
// (NewDockerHeadlessEnvironment, `vault server -dev`). On hosts without Docker,
// the same agent runs vault NATIVELY from a nix-provisioned binary: the codefly
// NixEnvironment materializes `vault` from the embedded flake (nixpkgs is
// instantiated with allowUnfree since Vault is BUSL), and this file launches
// `vault server -dev` bound to the agent-assigned port with the configured root
// token. Dev mode is in-memory and auto-unsealed, so there is no data dir or
// unseal step — the post-init transit/JWT seeding (HTTP, via vaultAddress) is
// unchanged across runtimes.

import (
	"context"
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	runners "github.com/codefly-dev/core/runners/base"
)

//go:embed nix/flake.nix
var vaultFlakeNix string

//go:embed nix/flake.lock
var vaultFlakeLock string

// nixVault runs a native `vault server -dev` off a nix-provisioned binary.
type nixVault struct {
	env      *runners.NixEnvironment
	flakeDir string
	port     uint16
	token    string
	out      io.Writer
	proc     runners.Proc
	// serverCtx is the context vault runs under. It MUST outlive Init: starting
	// vault under the Init RPC's ctx kills it the instant Init returns. Cancelled
	// only by Stop.
	serverCtx    context.Context
	serverCancel context.CancelFunc
	// binDir is the absolute nix store bin dir holding the vault binary.
	binDir string
}

// newNixVault materializes the embedded flake under baseDir/nix and prepares a
// native vault. Dev mode keeps no on-disk state, so there is no data dir.
func newNixVault(ctx context.Context, baseDir string, port uint16, token string, out io.Writer) (*nixVault, error) {
	flakeDir := filepath.Join(baseDir, "nix")
	if err := os.MkdirAll(flakeDir, 0o755); err != nil {
		return nil, fmt.Errorf("create nix flake dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(flakeDir, "flake.nix"), []byte(vaultFlakeNix), 0o644); err != nil {
		return nil, fmt.Errorf("write flake.nix: %w", err)
	}
	if err := os.WriteFile(filepath.Join(flakeDir, "flake.lock"), []byte(vaultFlakeLock), 0o644); err != nil {
		return nil, fmt.Errorf("write flake.lock: %w", err)
	}
	env, err := runners.NewNixEnvironment(ctx, flakeDir)
	if err != nil {
		return nil, fmt.Errorf("nix environment (is nix installed?): %w", err)
	}
	env.WithCacheDir(filepath.Join(baseDir, ".nix-cache"))
	return &nixVault{
		env:      env,
		flakeDir: flakeDir,
		port:     port,
		token:    token,
		out:      out,
	}, nil
}

// Init materializes the nix env, locates the vault binary, launches `vault
// server -dev`, and waits for the HTTP health endpoint to answer.
func (n *nixVault) Init(ctx context.Context) error {
	if err := n.env.Init(ctx); err != nil {
		return fmt.Errorf("materialize nix vault env: %w", err)
	}
	if err := n.resolveStore(); err != nil {
		return err
	}
	if err := n.startServer(ctx); err != nil {
		return err
	}
	return n.waitReady(ctx)
}

// resolveStore locates the nix-store vault binary by absolute path so we run the
// nix-built vault even if a system vault shadows PATH.
func (n *nixVault) resolveStore() error {
	matches, err := filepath.Glob("/nix/store/*-vault-*/bin/vault")
	if err != nil {
		return fmt.Errorf("glob nix vault: %w", err)
	}
	if len(matches) == 0 {
		return fmt.Errorf("no nix vault with bin/vault found in /nix/store (materialization may have failed)")
	}
	n.binDir = filepath.Dir(matches[0])
	return nil
}

// startServer launches `vault server -dev` bound to loopback on the assigned
// port with the configured root token. Dev mode is in-memory + auto-unsealed.
func (n *nixVault) startServer(ctx context.Context) error {
	proc, err := n.env.NewProcess(filepath.Join(n.binDir, "vault"),
		"server", "-dev",
		"-dev-root-token-id="+n.token,
		fmt.Sprintf("-dev-listen-address=127.0.0.1:%d", n.port),
	)
	if err != nil {
		return err
	}
	if n.out != nil {
		proc.WithOutput(n.out)
	}
	n.serverCtx, n.serverCancel = context.WithCancel(context.Background())
	if err := proc.Start(n.serverCtx); err != nil {
		n.serverCancel()
		return fmt.Errorf("start vault: %w", err)
	}
	n.proc = proc
	return nil
}

// waitReady polls vault's health endpoint until it responds. Any HTTP status
// counts as ready: dev mode returns 200 (initialized + unsealed + active), but
// a reachable endpoint at all proves the server is up.
func (n *nixVault) waitReady(ctx context.Context) error {
	url := fmt.Sprintf("http://127.0.0.1:%d/v1/sys/health", n.port)
	client := &http.Client{Timeout: 1 * time.Second}
	deadline := time.Now().Add(30 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			return nil
		}
		lastErr = err
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("vault did not become ready on %s: %w", url, lastErr)
}

// Stop terminates the vault server process.
func (n *nixVault) Stop(ctx context.Context) error {
	if n.serverCancel != nil {
		n.serverCancel()
	}
	if n.proc == nil {
		return nil
	}
	return n.proc.Stop(ctx)
}
