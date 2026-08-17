package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/codefly-dev/core/agents/services"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	runtimev0 "github.com/codefly-dev/core/generated/go/codefly/services/runtime/v0"
	"github.com/codefly-dev/core/resources"
	dockerrun "github.com/codefly-dev/core/runners/dockerrun"
	"github.com/codefly-dev/core/wool"
)

type Runtime struct {
	services.RuntimeServer
	*Service

	runnerEnvironment *dockerrun.DockerEnvironment
	vaultPort         uint16
	vaultAddress      string
	vaultToken        string

	// nixRuntime is set instead of runnerEnvironment when the caller requests
	// RuntimeContextNix — vault runs natively from a nix-provisioned binary.
	nixRuntime *nixVault
}

func NewRuntime() *Runtime {
	return &Runtime{
		Service: NewService(),
	}
}

func (s *Runtime) Load(ctx context.Context, req *runtimev0.LoadRequest) (*runtimev0.LoadResponse, error) {
	defer s.Wool.Catch()

	return s.Runtime.LoadService(ctx, req, services.RuntimeLoad{
		Settings:     s.Settings,
		Requirements: requirements,
		ResolveEndpoints: func(ctx context.Context, endpoints []*basev0.Endpoint) error {
			s.Wool.Debug("endpoints", wool.Field("endpoints", resources.MakeManyEndpointSummary(endpoints)))
			endpoint, err := resources.FindHTTPEndpoint(ctx, endpoints)
			if err != nil {
				return s.Wool.Wrapf(err, "cannot find HTTP endpoint")
			}
			s.HttpEndpoint = endpoint
			return nil
		},
	})
}

func callingContext() *basev0.NetworkAccess {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return resources.NewContainerNetworkAccess()
	}
	return resources.NewNativeNetworkAccess()
}

// vaultTokenFromRuntimeConfiguration keeps the local runtime self-contained
// without weakening deployment builds. A Docker/Nix development Vault is
// ephemeral, so its root token may be ephemeral too and is exported to
// dependants only through secret runtime configuration. Deployment still calls
// VaultTokenFromConfiguration directly and therefore fails closed unless a
// deployment supplies VAULT_TOKEN.
func (s *Runtime) vaultTokenFromRuntimeConfiguration(ctx context.Context, conf *basev0.Configuration) (string, error) {
	if conf != nil {
		return s.VaultTokenFromConfiguration(ctx, conf)
	}

	token := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, token); err != nil {
		return "", s.Wool.Wrapf(err, "cannot generate ephemeral vault token")
	}
	s.Wool.Info("generated ephemeral vault token for local runtime")
	return base64.RawURLEncoding.EncodeToString(token), nil
}

func (s *Runtime) Init(ctx context.Context, req *runtimev0.InitRequest) (*runtimev0.InitResponse, error) {
	defer s.Wool.Catch()
	ctx = s.Wool.Inject(ctx)

	s.Runtime.LogInitRequest(req)

	w := s.Wool.In("runtime::init")

	s.NetworkMappings = req.ProposedNetworkMappings

	net, err := resources.FindNetworkMapping(ctx, s.NetworkMappings, s.HttpEndpoint)
	if err != nil {
		return s.Runtime.InitError(err)
	}
	if net == nil {
		return s.Runtime.InitError(w.NewError("network mapping is nil"))
	}

	instance, err := resources.FindNetworkInstanceInNetworkMappings(ctx, s.NetworkMappings, s.HttpEndpoint, callingContext())
	if err != nil {
		return s.Runtime.InitError(err)
	}
	if instance == nil {
		return s.Runtime.InitError(w.NewError("network instance is nil"))
	}

	w.Debug("http network instance", wool.Field("instance", instance))

	s.vaultPort = 8200

	vaultToken, err := s.vaultTokenFromRuntimeConfiguration(ctx, req.Configuration)
	if err != nil {
		return s.Runtime.InitError(err)
	}

	// Create connection configs for all network instances
	runtimeConfigurations := make([]*basev0.Configuration, 0, len(net.Instances))
	for _, inst := range net.Instances {
		conf := s.CreateConnectionConfiguration(inst, vaultToken)
		w.Debug("adding configuration", wool.Field("config", resources.MakeConfigurationSummary(conf)), wool.Field("instance", inst))
		runtimeConfigurations = append(runtimeConfigurations, conf)
	}

	// Store the address for health checks
	hostInstance, err := resources.FindNetworkInstanceInNetworkMappings(ctx, s.NetworkMappings, s.HttpEndpoint, callingContext())
	if err != nil {
		return s.Runtime.InitError(err)
	}
	vaultAddress := hostInstance.Address

	// Nix runtime: run `vault server -dev` natively from a nix-provisioned binary
	// instead of a Docker container — selected when the caller requests
	// RuntimeContextNix (e.g. a host without Docker). vault binds the assigned
	// port directly, so vaultAddress (used by the transit/JWT seeding below) is
	// unchanged.
	if rc := req.GetRuntimeContext(); rc != nil && rc.Kind == resources.RuntimeContextNix {
		s.Infof("using nix runtime for vault on port %d", instance.Port)
		nixv, errNix := newNixVault(ctx, s.Location, uint16(instance.Port), vaultToken, newVaultLogWriter(s.Wool, vaultToken))
		if errNix != nil {
			return s.Runtime.InitError(errNix)
		}
		if errNix = nixv.Init(ctx); errNix != nil {
			return s.Runtime.InitError(errNix)
		}
		s.nixRuntime = nixv
	} else {
		// Docker
		runner, errDocker := dockerrun.NewDockerHeadlessEnvironment(ctx, image, s.UniqueWithWorkspace())
		if errDocker != nil {
			return s.Runtime.InitError(errDocker)
		}
		// vault dev-mode is stateless — mark the container ephemeral so a
		// SIGKILL'd run (which skips Stop) gets its vault reaped by the next
		// run's startup sweep instead of lingering and holding its port.
		runner.WithEphemeral()
		runner.WithOutput(newVaultLogWriter(s.Wool, vaultToken))
		runner.WithPortMapping(ctx, uint16(instance.Port), s.vaultPort)
		runner.WithEnvironmentVariables(ctx,
			resources.Env(vaultTokenEnvironmentVariable, vaultToken),
			resources.Env("VAULT_DEV_LISTEN_ADDRESS", "0.0.0.0:8200"),
			resources.Env("SKIP_SETCAP", "true"),
		)
		s.runnerEnvironment = runner
		w.Debug("init for runner environment: will start container")
		if errDocker = s.runnerEnvironment.Init(ctx); errDocker != nil {
			return s.Runtime.InitError(errDocker)
		}
	}

	s.vaultToken = vaultToken
	s.vaultAddress = vaultAddress
	s.Runtime.Lock()
	s.Runtime.RuntimeConfigurations = runtimeConfigurations
	s.Runtime.Unlock()

	w.Debug("init successful")
	return s.Runtime.InitResponse()
}

func (s *Runtime) WaitForReady(ctx context.Context) error {
	defer s.Wool.Catch()
	ctx = s.Wool.Inject(ctx)

	s.Wool.Debug("waiting for ready", wool.Field("address", s.vaultAddress))

	maxRetry := 10
	for retry := 0; retry < maxRetry; retry++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.vaultAddress+"/v1/sys/health", nil)
		if err != nil {
			return s.Wool.Wrapf(err, "cannot create health request")
		}

		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			// Vault returns 200 when initialized, unsealed, and active
			if resp.StatusCode == 200 {
				s.Wool.Debug("vault is ready!")
				return nil
			}
		}
		s.Wool.Debug("waiting for vault to be ready", wool.ErrField(err))
		time.Sleep(2 * time.Second)
	}
	return s.Wool.NewError("vault is not ready")
}

func (s *Runtime) enableTransit(ctx context.Context) error {
	defer s.Wool.Catch()

	// Enable transit secrets engine
	err := s.vaultRequest(ctx, http.MethodPost, "/v1/sys/mounts/transit",
		`{"type":"transit"}`)
	if err != nil {
		// Ignore "already enabled" errors
		if !strings.Contains(err.Error(), "existing mount") && !strings.Contains(err.Error(), "already in use") {
			return s.Wool.Wrapf(err, "cannot enable transit engine")
		}
	}
	s.Wool.Debug("transit engine enabled")

	// Create the transit key for API keys
	keyName := s.TransitKey
	if keyName == "" {
		keyName = "api-keys"
	}
	err = s.vaultRequest(ctx, http.MethodPost,
		fmt.Sprintf("/v1/transit/keys/%s", keyName),
		`{"type":"aes256-gcm96"}`)
	if err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			return s.Wool.Wrapf(err, "cannot create transit key")
		}
	}
	s.Wool.Debug("transit key created", wool.Field("key", keyName))

	return nil
}

func (s *Runtime) seedJWTSigningKey(ctx context.Context) error {
	defer s.Wool.Catch()

	// Check if key already exists
	err := s.vaultRequest(ctx, http.MethodGet, "/v1/secret/data/jwt-signing-key", "")
	if err == nil {
		s.Wool.Debug("JWT signing key already exists")
		return nil
	}

	// Generate Ed25519 key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return s.Wool.Wrapf(err, "cannot generate Ed25519 key pair")
	}

	// Store seed (first 32 bytes of private key) and public key
	privSeed := base64.StdEncoding.EncodeToString(priv.Seed())
	pubEncoded := base64.StdEncoding.EncodeToString(pub)

	body := fmt.Sprintf(`{"data":{"private_key":"%s","public_key":"%s","algorithm":"EdDSA"}}`,
		privSeed, pubEncoded)

	err = s.vaultRequest(ctx, http.MethodPost, "/v1/secret/data/jwt-signing-key", body)
	if err != nil {
		return s.Wool.Wrapf(err, "cannot store JWT signing key")
	}

	s.Wool.Debug("JWT signing key generated and stored")
	return nil
}

func (s *Runtime) vaultRequest(ctx context.Context, method, path, body string) error {
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, s.vaultAddress+path, bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", s.vaultToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		return fmt.Errorf("vault %s %s returned %d: %s", method, path, resp.StatusCode, string(respBody))
	}
	return nil
}

func (s *Runtime) Start(ctx context.Context, req *runtimev0.StartRequest) (*runtimev0.StartResponse, error) {
	defer s.Wool.Catch()
	ctx = s.Wool.Inject(ctx)

	s.Wool.Debug("starting")

	err := s.WaitForReady(ctx)
	if err != nil {
		return s.Runtime.StartError(err)
	}

	err = s.enableTransit(ctx)
	if err != nil {
		return s.Runtime.StartError(err)
	}

	err = s.seedJWTSigningKey(ctx)
	if err != nil {
		return s.Runtime.StartError(err)
	}

	s.Wool.Debug("start done")
	return s.Runtime.StartResponse()
}

func (s *Runtime) Information(ctx context.Context, req *runtimev0.InformationRequest) (*runtimev0.InformationResponse, error) {
	return s.Runtime.InformationResponse(ctx, req)
}

// teardown fully stops vault's runtime — the native nix process or the docker
// container. Unlike most infra agents, vault does NOT keep its environment
// alive for reuse: dev-mode is in-memory and stateless, so there is nothing to
// preserve, and a lingering vault only orphans its port and bleeds stale state
// into the next run (the failure mode that makes a later health probe fail).
// Shared by Stop and Destroy.
func (s *Runtime) teardown(ctx context.Context) error {
	if s.nixRuntime != nil {
		s.Wool.Debug("stopping nix vault process")
		return s.nixRuntime.Stop(ctx)
	}
	if s.runnerEnvironment != nil {
		s.Wool.Debug("shutting down vault container")
		return s.runnerEnvironment.Shutdown(ctx)
	}
	// No live handle (e.g. Destroy on a freshly loaded agent that never ran
	// Init): reconstruct the docker env by name and shut it down.
	runner, err := dockerrun.NewDockerHeadlessEnvironment(ctx, image, s.UniqueWithWorkspace())
	if err != nil {
		return err
	}
	return runner.Shutdown(ctx)
}

func (s *Runtime) Stop(ctx context.Context, req *runtimev0.StopRequest) (*runtimev0.StopResponse, error) {
	defer s.Wool.Catch()
	ctx = s.Wool.Inject(ctx)

	if err := s.teardown(ctx); err != nil {
		return s.Runtime.StopError(err)
	}
	return s.Runtime.StopResponse()
}

func (s *Runtime) Destroy(ctx context.Context, req *runtimev0.DestroyRequest) (*runtimev0.DestroyResponse, error) {
	defer s.Wool.Catch()
	ctx = s.Wool.Inject(ctx)

	s.Wool.Debug("destroying")

	if err := s.teardown(ctx); err != nil {
		return s.Runtime.DestroyError(err)
	}
	return s.Runtime.DestroyResponse()
}

func (s *Runtime) Test(ctx context.Context, req *runtimev0.TestRequest) (*runtimev0.TestResponse, error) {
	return s.Runtime.TestResponse()
}
