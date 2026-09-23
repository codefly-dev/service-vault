package main

import (
	"context"
	"embed"
	"fmt"
	"strings"

	"github.com/codefly-dev/core/agents/communicate"
	"github.com/codefly-dev/core/agents/services"
	"github.com/codefly-dev/core/agents/services/upgrade"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	builderv0 "github.com/codefly-dev/core/generated/go/codefly/services/builder/v0"
	"github.com/codefly-dev/core/resources"
	"github.com/codefly-dev/core/standards"
	"github.com/codefly-dev/core/wool"
)

type Builder struct {
	services.BuilderServer
	*Service
}

// deploymentTemplateParameters carries what the manifests cannot know on their
// own. Exactly one of three shapes renders:
//
//   - External: an environment bound to a Vault this service does not run
//     (Settings.ExternalInstances). Nothing is rendered; consumers receive the
//     external coordinates.
//   - Durable: a restricted (deployed) render. Vault runs as a raft-backed,
//     auto-unsealed server on a persistent volume (provision/server.sh) and
//     provision/provision.sh initializes and provisions it.
//   - Otherwise the ephemeral local-apply render: the in-memory dev server,
//     re-provisioned on every start.
type deploymentTemplateParameters struct {
	// ServicePort is the in-cluster port core allocated to vault's http
	// endpoint. Every consumer is handed that port in its network mapping, so
	// the Service publishes it and folds it onto 8200, the port the container
	// listens on. Zero leaves the template on 8200.
	ServicePort uint32
	// ProvisionCommand is the vault container's postStart exec command, as a
	// JSON array (a valid YAML flow sequence): provision/provision.sh run with
	// its mode and the configured transit key name. Empty renders no hook.
	ProvisionCommand string
	// ServerCommand is the durable container's command (provision/server.sh),
	// as a JSON array. Set only for a durable render.
	ServerCommand string
	// ServiceName is the service's own name, declared on the durable container
	// as CODEFLY__SERVICE so the environment's per-service configuration (the
	// seal) is projected into it.
	ServiceName string
	Durable     bool
	External    bool
}

func NewBuilder() *Builder {
	return &Builder{
		Service: NewService(),
	}
}

func (s *Builder) Load(ctx context.Context, req *builderv0.LoadRequest) (*builderv0.LoadResponse, error) {
	defer s.Wool.Catch()

	return s.Builder.LoadService(ctx, req, services.BuilderLoad{
		Settings:         s.Settings,
		Requirements:     requirements,
		FactoryTemplates: factoryFS,
		ResolveEndpoints: func(ctx context.Context, endpoints []*basev0.Endpoint) error {
			endpoint, err := resources.FindHTTPEndpoint(ctx, endpoints)
			if err != nil {
				return err
			}
			s.HttpEndpoint = endpoint
			s.Wool.Debug("endpoint", wool.Field("http", endpoint))
			return nil
		},
	})
}

func (s *Builder) Init(ctx context.Context, req *builderv0.InitRequest) (*builderv0.InitResponse, error) {
	defer s.Wool.Catch()
	return s.Builder.InitResponse()
}

func (s *Builder) Update(ctx context.Context, req *builderv0.UpdateRequest) (*builderv0.UpdateResponse, error) {
	defer s.Wool.Catch()
	return &builderv0.UpdateResponse{}, nil
}

func (s *Builder) Sync(ctx context.Context, req *builderv0.SyncRequest) (*builderv0.SyncResponse, error) {
	defer s.Wool.Catch()
	return s.Builder.SyncResponse()
}

func (s *Builder) Build(ctx context.Context, req *builderv0.BuildRequest) (*builderv0.BuildResponse, error) {
	defer s.Wool.Catch()
	s.Wool.Debug("build: vault has no build artifacts")
	return s.Builder.BuildResponse()
}

// Audit scans the vault image for vulnerabilities via trivy.
func (s *Builder) Audit(ctx context.Context, req *builderv0.AuditRequest) (*builderv0.AuditResponse, error) {
	defer s.Wool.Catch()
	ctx = s.Wool.Inject(ctx)
	return s.Builder.AuditContainer(ctx, req, image.FullName())
}

func (s *Builder) SBOM(ctx context.Context, _ *builderv0.SBOMRequest) (*builderv0.SBOMResponse, error) {
	defer s.Wool.Catch()
	ctx = s.Wool.Inject(ctx)
	return s.Builder.SBOMContainer(ctx, image.FullName())
}

// Upgrade reports a tag bump from the current vault image.
func (s *Builder) Upgrade(ctx context.Context, req *builderv0.UpgradeRequest) (*builderv0.UpgradeResponse, error) {
	defer s.Wool.Catch()
	ctx = s.Wool.Inject(ctx)
	res, err := upgrade.Docker(ctx, image.FullName(), upgrade.Options{
		IncludeMajor: req.IncludeMajor,
		DryRun:       req.DryRun,
	})
	if err != nil {
		return s.Builder.UpgradeError(err)
	}
	return s.Builder.UpgradeResponse(res.Changes, res.LockfileDiff)
}

// Deploy renders vault for Kubernetes. Which Vault it renders — none (an
// external binding), a durable server (restricted profiles), or the in-memory
// dev server (ephemeral local apply) — is described on
// deploymentTemplateParameters.
func (s *Builder) Deploy(ctx context.Context, req *builderv0.DeploymentRequest) (*builderv0.DeploymentResponse, error) {
	defer s.Wool.Catch()
	ctx = s.Wool.Inject(ctx)
	s.SetDockerImage(image)

	binding, err := s.externalInstance(req.GetEnvironment().GetName())
	if err != nil {
		return s.Builder.DeployError(err)
	}
	restricted := services.IsRestrictedOutputProfile(req.GetDeployment().GetKubernetes().GetProfile())
	parameters := &deploymentTemplateParameters{ServiceName: s.Identity.Name}
	switch {
	case binding != nil:
		parameters.External = true
	case restricted:
		parameters.Durable = true
		if parameters.ServerCommand, err = serverCommand(); err != nil {
			return s.Builder.DeployError(err)
		}
	}
	if !parameters.External {
		key, err := s.transitKeyName()
		if err != nil {
			return s.Builder.DeployError(err)
		}
		mode := provisionModeDev
		if parameters.Durable {
			mode = provisionModeDurable
		}
		if parameters.ProvisionCommand, err = provisionCommand(mode, key); err != nil {
			return s.Builder.DeployError(err)
		}
	}

	var configuration *basev0.Configuration
	response, err := s.Builder.DeployKustomize(ctx, req, services.KustomizeDeployment{
		EnvironmentVariables: s.EnvironmentVariables,
		Templates:            deploymentFS,
		Parameters:           parameters,
		Prepare: func(ctx context.Context, deployment *services.KustomizeDeploymentContext) error {
			restricted := services.IsRestrictedOutputProfile(deployment.Profile)
			// Vault's HTTP endpoint is visibility: module, so every deploy profile
			// receives a container-only mapping (a non-DNS internal endpoint has no
			// public instance) and its consumers reach it in-cluster. Resolve the
			// container Service address for both the restricted render and local
			// apply — the workload and its dependants run inside the cluster in both
			// cases, and requesting a public instance that never exists hard-fails.
			instance, err := resources.FindNetworkInstanceInNetworkMappings(ctx, req.GetNetworkMappings(), s.HttpEndpoint, resources.NewContainerNetworkAccess())
			if err != nil {
				return err
			}
			if binding != nil {
				return s.prepareExternal(ctx, deployment, req, instance, binding, restricted, &configuration)
			}
			if restricted {
				references, err := vaultRestrictedSecretReferences(deployment.Kubernetes.GetSecretReferences())
				if err != nil {
					return err
				}
				deployment.Kubernetes.SecretReferences = references
			}
			// The Service publishes the port core allocated to the endpoint — the
			// one every consumer dials — and targets 8200. Same mechanism as
			// redis: the mapping the CLI hands this Deploy carries our own endpoint.
			parameters.ServicePort = instance.GetPort()
			if !restricted {
				vaultToken, err := s.VaultTokenFromConfiguration(ctx, req.GetConfiguration())
				if err != nil {
					return err
				}
				return deployment.ExportConfiguration(ctx, s.CreateConnectionConfiguration(instance, vaultToken))
			}
			// Restricted profiles hand the connection off through the response
			// (not ExportConfiguration) so the empty token capability reaches the
			// promotion driver without being injected into the rendered manifests.
			configuration = s.CreateRestrictedConnectionConfiguration(instance)
			return nil
		},
	})
	if err != nil || response.GetState().GetState() != builderv0.DeploymentStatus_SUCCESS || configuration == nil {
		return response, err
	}
	response.Configuration = configuration
	return response, nil
}

// prepareExternal completes a deployment bound to an external Vault. Nothing is
// rendered, so the token reference a restricted request carries is consumed by
// no manifest here; it is still validated when consumers depend on it (no
// token file), and dropped from this service's bundle either way.
func (s *Builder) prepareExternal(
	ctx context.Context,
	deployment *services.KustomizeDeploymentContext,
	req *builderv0.DeploymentRequest,
	instance *basev0.NetworkInstance,
	binding *ExternalInstance,
	restricted bool,
	configuration **basev0.Configuration,
) error {
	if restricted {
		references := deployment.Kubernetes.GetSecretReferences()
		if binding.TokenFile == "" || len(references) > 0 {
			if _, err := vaultRestrictedSecretReferences(references); err != nil {
				return fmt.Errorf("external instance without token-file: %w", err)
			}
		}
		deployment.Kubernetes.SecretReferences = nil
		// The empty token capability, when present, is filled by the promotion
		// driver from the external secret, exactly as for a rendered Vault.
		empty := ""
		*configuration = s.externalConnectionConfiguration(instance, binding, &empty)
		return nil
	}
	var token *string
	if binding.TokenFile == "" {
		value, err := s.VaultTokenFromConfiguration(ctx, req.GetConfiguration())
		if err != nil {
			return err
		}
		token = &value
	}
	*configuration = s.externalConnectionConfiguration(instance, binding, token)
	return nil
}

// vaultRestrictedSecretReferences validates the caller-supplied external-secret
// references for a restricted deployment and remaps the single canonical Vault
// token reference onto the environment variable the container consumes. The
// plugin never receives the secret value — only the reference to it.
func vaultRestrictedSecretReferences(
	references map[string]*builderv0.KubernetesSecretKeyReference,
) (map[string]*builderv0.KubernetesSecretKeyReference, error) {
	if len(references) != 1 {
		return nil, fmt.Errorf("restricted profile requires exactly one canonical Vault token secret reference")
	}
	var source string
	var reference *builderv0.KubernetesSecretKeyReference
	for key, candidate := range references {
		source = key
		reference = candidate
	}
	if !strings.HasPrefix(source, "CODEFLY__SERVICE_SECRET_CONFIGURATION__") ||
		!strings.HasSuffix(source, "__VAULT__VAULT_TOKEN") {
		return nil, fmt.Errorf("restricted profile requires the canonical Vault token secret reference")
	}
	if reference.GetOptional() {
		return nil, fmt.Errorf("restricted Vault token secret reference must not be optional")
	}
	return map[string]*builderv0.KubernetesSecretKeyReference{
		vaultAccessTokenEnvironmentVariable: reference,
	}, nil
}

func (s *Builder) Create(ctx context.Context, req *builderv0.CreateRequest) (*builderv0.CreateResponse, error) {
	defer s.Wool.Catch()

	if s.TransitKey == "" {
		s.TransitKey = "api-keys"
	}

	err := s.Templates(ctx, s.Settings, services.WithFactory(factoryFS))
	if err != nil {
		return s.Builder.CreateError(err)
	}

	err = s.CreateEndpoints(ctx)
	if err != nil {
		return s.Builder.CreateErrorf(err, "cannot create endpoints")
	}

	s.Wool.Debug("created endpoints", wool.Field("endpoints", resources.MakeManyEndpointSummary(s.Endpoints)))

	return s.Builder.CreateResponse(ctx, s.Settings)
}

func (s *Builder) CreateEndpoints(ctx context.Context) error {
	httpAPI, err := resources.LoadHTTPAPI(ctx)
	if err != nil {
		return s.Wool.Wrapf(err, "cannot load http api")
	}
	endpoint := s.BaseEndpoint(standards.HTTP)
	endpoint.Visibility = resources.VisibilityModule
	s.HttpEndpoint, err = resources.NewAPI(ctx, endpoint, resources.ToHTTPAPI(httpAPI))
	if err != nil {
		return s.Wool.Wrapf(err, "cannot create http endpoint")
	}
	s.Endpoints = []*basev0.Endpoint{s.HttpEndpoint}
	return nil
}

func (s *Builder) Communicate(stream builderv0.Builder_CommunicateServer) error {
	asker := communicate.NewQuestionAsker(stream)
	_, err := asker.RunSequence(nil)
	return err
}

//go:embed templates/factory
var factoryFS embed.FS

//go:embed templates/deployment
var deploymentFS embed.FS
