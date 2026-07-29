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
	require.Equal(t, "runtime-v2.0.3-patched.5", image.Tag)
	require.Equal(t, "sha256:f5ccde0eb6844d754c2bf693da1375023cf9827bfa2135c8c743bdd816bda94d", image.Digest)
	require.Equal(t, "ghcr.io/codefly-dev/service-vault-runtime@sha256:f5ccde0eb6844d754c2bf693da1375023cf9827bfa2135c8c743bdd816bda94d", image.FullName())
}

func TestAgentVersion(t *testing.T) {
	require.Equal(t, "0.0.18", agent.Version)
}

func TestConnectionConfigurationTokenProfiles(t *testing.T) {
	service := NewService()
	service.Identity = &resources.ServiceIdentity{Workspace: "workspace", Module: "module", Name: "vault"}
	instance := resources.NewHTTPNetworkInstance("vault.example.com", 8200, true)
	instance.Access = resources.NewPublicNetworkAccess()

	ephemeral := service.CreateConnectionConfiguration(instance, "must-stay-ephemeral")
	require.Len(t, ephemeral.GetInfos(), 1)
	require.Len(t, ephemeral.GetInfos()[0].GetConfigurationValues(), 2)
	require.Equal(t, "must-stay-ephemeral", ephemeral.GetInfos()[0].GetConfigurationValues()[1].GetValue())
	require.True(t, ephemeral.GetInfos()[0].GetConfigurationValues()[1].GetSecret())

	gitOps := service.CreateGitOpsConnectionConfiguration(instance)
	require.Len(t, gitOps.GetInfos(), 1)
	require.Len(t, gitOps.GetInfos()[0].GetConfigurationValues(), 1)
	require.Equal(t, "address", gitOps.GetInfos()[0].GetConfigurationValues()[0].GetKey())
	require.Equal(t, "https://vault.example.com:8200", gitOps.GetInfos()[0].GetConfigurationValues()[0].GetValue())
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

	networkMappings, err := networkManager.GenerateNetworkMappings(ctx, env, workspace, runtime.Identity, runtime.Endpoints, runtimeContext)
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
