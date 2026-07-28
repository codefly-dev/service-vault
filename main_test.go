package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"testing"
	"time"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	builderv0 "github.com/codefly-dev/core/generated/go/codefly/services/builder/v0"
	runtimev0 "github.com/codefly-dev/core/generated/go/codefly/services/runtime/v0"
	"github.com/codefly-dev/core/network"
	"github.com/codefly-dev/core/resources"
	runners "github.com/codefly-dev/core/runners/base"
	"github.com/codefly-dev/core/shared"
	"github.com/codefly-dev/core/wool"
	"github.com/stretchr/testify/require"
)

// TestCreateToRunDocker runs the full agent lifecycle against the Docker
// runtime (the default container backend).
func TestCreateToRunDocker(t *testing.T) {
	testCreateToRun(t, resources.NewRuntimeContextFree())
}

func TestVaultImagePin(t *testing.T) {
	require.Equal(t, "ghcr.io/codefly-dev/service-vault-runtime", image.Name)
	require.Equal(t, "runtime-v2.0.3-patched.4", image.Tag)
	require.Equal(t, "sha256:00b9a5fb0eef11f758be2e0978ed8b5a01f9fdadb1f895f652f84d52699741e5", image.Digest)
	require.Equal(t, "ghcr.io/codefly-dev/service-vault-runtime@sha256:00b9a5fb0eef11f758be2e0978ed8b5a01f9fdadb1f895f652f84d52699741e5", image.FullName())
}

func TestAgentVersion(t *testing.T) {
	require.Equal(t, "0.0.16", agent.Version)
}

func TestVaultImageAudit(t *testing.T) {
	response, err := NewBuilder().Audit(context.Background(), &builderv0.AuditRequest{FailOnVuln: true})
	require.NoError(t, err)
	require.Equal(t, builderv0.AuditStatus_CLEAN, response.GetState().GetState(), "message: %s; findings: %v", response.GetState().GetMessage(), response.GetFindings())
	require.Empty(t, response.GetFindings())
}

// TestCreateToRunNix runs the SAME full lifecycle against the nix runtime —
// the Docker-free backend used on hosts without Docker. Requires nix.
//
// This is the test that exercises `nixVault` end to end: Init materializes the
// flake, launches `vault server -dev`, and waits for /v1/sys/health; Start then
// drives the post-unseal transit/JWT seeding over HTTP. A regression where the
// nix-launched vault starts, unseals, then exits before binding (the failure
// that surfaced only at `codefly run` time) fails HERE instead of in the field.
func TestCreateToRunNix(t *testing.T) {
	if !runners.CheckNixInstalled() || !runners.IsNixSupported() {
		t.Skip("nix not installed/supported on this host")
	}
	testCreateToRun(t, resources.NewRuntimeContextNix())
}

// testCreateToRun drives Load → Init → Start → GET /v1/sys/health for one
// runtime context, so docker and nix exercise the identical agent path.
func testCreateToRun(t *testing.T, runtimeContext *basev0.RuntimeContext) {
	wool.SetGlobalLogLevel(wool.DEBUG)
	ctx := context.Background()

	workspace := &resources.Workspace{Name: "test"}

	tmpDir := t.TempDir()

	serviceName := fmt.Sprintf("svc-%v", time.Now().UnixMilli())
	service := resources.Service{Name: serviceName, Version: "test-me"}
	err := service.SaveAtDir(ctx, path.Join(tmpDir, "mod", service.Name))
	require.NoError(t, err)

	identity := &basev0.ServiceIdentity{
		Name:                service.Name,
		Module:              "mod",
		Workspace:           workspace.Name,
		WorkspacePath:       tmpDir,
		RelativeToWorkspace: fmt.Sprintf("mod/%s", service.Name),
	}
	builder := NewBuilder()

	resp, err := builder.Load(ctx, &builderv0.LoadRequest{DisableCatch: true, Identity: identity, CreationMode: &builderv0.CreationMode{Communicate: false}})
	require.NoError(t, err)
	require.NotNil(t, resp)

	_, err = builder.Create(ctx, &builderv0.CreateRequest{})
	require.NoError(t, err)

	// Now run it
	runtime := NewRuntime()

	networkManager, err := network.NewRuntimeManager(ctx, nil)
	require.NoError(t, err)
	networkManager.WithTemporaryPorts()

	env := resources.LocalEnvironment()

	_, err = runtime.Load(ctx, &runtimev0.LoadRequest{
		Identity:     identity,
		Environment:  shared.Must(env.Proto()),
		DisableCatch: true})
	require.NoError(t, err)

	require.Equal(t, 1, len(runtime.Endpoints))

	networkMappings, err := networkManager.GenerateNetworkMappings(ctx, env, workspace, runtime.Identity, runtime.Endpoints)
	require.NoError(t, err)
	require.Equal(t, 1, len(networkMappings))

	// vault reads its root token from the "vault" configuration (VAULT_TOKEN).
	conf := &basev0.Configuration{
		Origin:         fmt.Sprintf("mod/%s", service.Name),
		RuntimeContext: resources.NewRuntimeContextFree(),
		Infos: []*basev0.ConfigurationInformation{
			{Name: "vault",
				ConfigurationValues: []*basev0.ConfigurationValue{
					{Key: "VAULT_TOKEN", Value: "dev-root-token"},
				},
			},
		},
	}

	// Init boots vault (nix: `vault server -dev` off the nix binary) and waits
	// for it to bind. This is where the "exited before binding" regression bites.
	init, err := runtime.Init(ctx, &runtimev0.InitRequest{
		RuntimeContext:          runtimeContext,
		Configuration:           conf,
		ProposedNetworkMappings: networkMappings,
	})
	require.NoError(t, err)
	require.NotNil(t, init)

	defer func() {
		_, _ = runtime.Destroy(ctx, &runtimev0.DestroyRequest{})
	}()

	// Start drives the post-unseal seeding (transit engine + JWT key) over HTTP,
	// which only succeeds if vault is up and stayed up.
	_, err = runtime.Start(ctx, &runtimev0.StartRequest{})
	require.NoError(t, err)

	// Explicit health assertion: vault answers 200 (initialized, unsealed, active).
	require.NotEmpty(t, runtime.vaultAddress)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, runtime.vaultAddress+"/v1/sys/health", nil)
	require.NoError(t, err)
	healthResp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer healthResp.Body.Close()
	require.Equal(t, http.StatusOK, healthResp.StatusCode)

	var health struct {
		Version string `json:"version"`
	}
	require.NoError(t, json.NewDecoder(healthResp.Body).Decode(&health))
	require.Equal(t, "2.0.3", health.Version)
}
