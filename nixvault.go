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

	"github.com/codefly-dev/core/resources"
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

// Init materializes the nix env, launches `vault server -dev`, and waits for
// the HTTP health endpoint to answer.
func (n *nixVault) Init(ctx context.Context) error {
	if err := n.env.Init(ctx); err != nil {
		return fmt.Errorf("materialize nix vault env: %w", err)
	}
	if err := n.startServer(ctx); err != nil {
		return err
	}
	return n.waitReady(ctx)
}

// startServer launches `vault server -dev` bound to loopback on the assigned
// port with the configured root token. Dev mode is in-memory + auto-unsealed.
func (n *nixVault) startServer(ctx context.Context) error {
	proc, err := n.env.NewProcess("vault", n.serverArgs()...)
	if err != nil {
		return err
	}
	// Vault supports VAULT_DEV_ROOT_TOKEN_ID directly. Environment injection
	// keeps the root token out of process listings and diagnostic argv dumps.
	proc.WithEnvironmentVariables(ctx, resources.Env("VAULT_DEV_ROOT_TOKEN_ID", n.token))
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

func (n *nixVault) serverArgs() []string {
	return []string{
		"server",
		"-dev",
		fmt.Sprintf("-dev-listen-address=127.0.0.1:%d", n.port),
	}
}

// waitReady polls vault's health endpoint until it responds. Any HTTP status
// counts as ready: dev mode returns 200 (initialized + unsealed + active), but
// a reachable endpoint at all proves the server is up.
//
// It also watches the server process: a `vault server -dev` that exits right
// after launch (port already bound, bad flag, crash) would otherwise look
// identical to a slow start — the probe just sees "connection refused" for the
// whole 30s and reports a misleading timeout. Detecting the dead process turns
// that into an immediate, accurate error.
func (n *nixVault) waitReady(ctx context.Context) error {
	addr := fmt.Sprintf("127.0.0.1:%d", n.port)
	url := fmt.Sprintf("http://%s/v1/sys/health", addr)
	if n.out != nil {
		fmt.Fprintf(n.out, "waiting for vault readiness on %s\n", addr)
	}
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
		// If the process is already gone there is nothing left to wait for —
		// fail now with a clear cause instead of polling a dead address.
		if n.proc != nil {
			if running, rerr := n.proc.IsRunning(ctx); rerr == nil && !running {
				return fmt.Errorf("vault process exited before binding %s "+
					"(check the vault log above for the bind address / error): %w", addr, lastErr)
			}
		}
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
