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

// Deploy emits a Kustomize-rendered StatefulSet + Service for vault.
// Mirrors the redis/s3 shape: pull the network instance, build the
// connection configuration, hand it to the EnvironmentVariables
// manager, then KustomizeDeploy with templates/deployment/.
//
// Note on the dev-mode caveat: the templates run `vault server -dev`
// which is in-memory and single-unsealed. That's intentionally a
// dev/staging shape — saas-starter's prod path should swap this
// overlay for a real Vault setup or AWS Secrets Manager.
func (s *Builder) Deploy(ctx context.Context, req *builderv0.DeploymentRequest) (*builderv0.DeploymentResponse, error) {
	defer s.Wool.Catch()
	ctx = s.Wool.Inject(ctx)
	s.SetDockerImage(image)

	var restrictedConfiguration *basev0.Configuration
	response, err := s.Builder.DeployKustomize(ctx, req, services.KustomizeDeployment{
		EnvironmentVariables: s.EnvironmentVariables,
		Templates:            deploymentFS,
		Prepare: func(ctx context.Context, deployment *services.KustomizeDeploymentContext) error {
			if services.IsRestrictedOutputProfile(deployment.Profile) {
				references, err := vaultRestrictedSecretReferences(deployment.Kubernetes.GetSecretReferences())
				if err != nil {
					return err
				}
				deployment.Kubernetes.SecretReferences = references
			}
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
			if deployment.Profile == builderv0.KubernetesOutputProfile_KUBERNETES_OUTPUT_PROFILE_EPHEMERAL_LOCAL_APPLY_V1 {
				vaultToken, err := s.VaultTokenFromConfiguration(ctx, req.GetConfiguration())
				if err != nil {
					return err
				}
				return deployment.ExportConfiguration(ctx, s.CreateConnectionConfiguration(instance, vaultToken))
			}
			// Restricted profiles hand the connection off through the response
			// (not ExportConfiguration) so the empty token capability reaches the
			// promotion driver without being injected into the rendered manifests.
			restrictedConfiguration = s.CreateRestrictedConnectionConfiguration(instance)
			return nil
		},
	})
	if err != nil ||
		response.GetState().GetState() != builderv0.DeploymentStatus_SUCCESS ||
		restrictedConfiguration == nil {
		return response, err
	}
	response.Configuration = restrictedConfiguration
	return response, nil
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
		vaultTokenEnvironmentVariable: reference,
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
