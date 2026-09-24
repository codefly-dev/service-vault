package main

import (
	"context"
	"embed"
	"strings"

	"github.com/codefly-dev/core/agents"
	"github.com/codefly-dev/core/agents/services"
	"github.com/codefly-dev/core/builders"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	agentv0 "github.com/codefly-dev/core/generated/go/codefly/services/agent/v0"
	"github.com/codefly-dev/core/resources"
	runnersbase "github.com/codefly-dev/core/runners/base"
	"github.com/codefly-dev/core/shared"
	"github.com/codefly-dev/core/templates"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Agent version
var agent = shared.Must(resources.LoadFromFs[resources.Agent](shared.Embed(infoFS)))

var requirements = builders.NewDependencies(agent.Name,
	builders.NewDependency("service.codefly.yaml"),
)

// vaultTokenEnvironmentVariable carries the token into the in-memory dev server
// of the ephemeral local-apply render, which boots with it as its root token.
const vaultTokenEnvironmentVariable = "VAULT_DEV_ROOT_TOKEN_ID"

// vaultAccessTokenEnvironmentVariable carries the composition-supplied token
// into the durable server of a restricted render, where provision/provision.sh
// installs it. A durable server has no dev root token, so the variable is
// deliberately not VAULT_DEV_ROOT_TOKEN_ID (nor VAULT_TOKEN, which the vault
// CLI would pick up implicitly).
const vaultAccessTokenEnvironmentVariable = "VAULT_ACCESS_TOKEN"

type Settings struct {
	TransitKey string `yaml:"transit-key"`

	// ExternalInstances binds named deployment environments to a Vault
	// provisioned and operated outside this service. A bound environment's
	// deployment renders no Vault workload: consumers receive the external
	// address and how to authenticate to it. Keyed by environment so two
	// environments can never silently share one binding; see external.go.
	ExternalInstances map[string]ExternalInstance `yaml:"external-instances"`
}

var image = &resources.DockerImage{
	Name:   "ghcr.io/codefly-dev/service-vault-runtime",
	Tag:    "runtime-v2.0.3-patched.9",
	Digest: "sha256:5217e3e2d22e2cfbc7e89b68c48bba190d58d3f5e64f941e07b11f04070a94f4",
}

type Service struct {
	*services.Base

	// Settings
	*Settings

	HttpEndpoint *basev0.Endpoint
}

func (s *Service) GetAgentInformation(ctx context.Context, _ *agentv0.AgentInformationRequest) (*agentv0.AgentInformation, error) {
	readme, err := templates.ApplyTemplateFrom(ctx, shared.Embed(readmeFS), "templates/agent/README.md", s.Information)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return services.Advertisement{
		Backends: runnersbase.BackendSupport{
			Nix:    true,
			Docker: true,
		},
		Config: []*agentv0.ConfigurationValueDetail{
			{
				Name: "vault", Description: "vault connection",
				Fields: []*agentv0.ConfigurationValueInformation{
					{Name: "address", Description: "vault HTTP address"},
					{Name: "token", Description: "vault authentication token"},
				},
			},
		},
		ReadMe: readme,
	}.Build(), nil
}

func NewService() *Service {
	return &Service{
		Base:     services.NewServiceBase(context.Background(), agent.Of(resources.ServiceAgent)),
		Settings: &Settings{TransitKey: "api-keys"},
	}
}

func (s *Service) VaultTokenFromConfiguration(ctx context.Context, conf *basev0.Configuration) (string, error) {
	token, err := resources.GetConfigurationValue(ctx, conf, "vault", "VAULT_TOKEN")
	if err != nil {
		return "", s.Wool.Wrapf(err, "cannot get vault token")
	}
	if strings.TrimSpace(token) == "" {
		return "", s.Wool.NewError("cannot get vault token: VAULT_TOKEN is missing or empty")
	}
	return token, nil
}

func (s *Service) CreateConnectionConfiguration(instance *basev0.NetworkInstance, vaultToken string) *basev0.Configuration {
	return s.createConnectionConfiguration(instance, &vaultToken)
}

// CreateRestrictedConnectionConfiguration advertises the Vault connection for a
// restricted-profile deployment: the address plus an empty, secret token
// capability. The value is deliberately blank — the plugin never receives or
// serializes the token; the promotion driver fills it from the external secret.
func (s *Service) CreateRestrictedConnectionConfiguration(instance *basev0.NetworkInstance) *basev0.Configuration {
	token := ""
	return s.createConnectionConfiguration(instance, &token)
}

func (s *Service) createConnectionConfiguration(instance *basev0.NetworkInstance, vaultToken *string) *basev0.Configuration {
	address := instance.Address
	values := []*basev0.ConfigurationValue{
		{Key: "address", Value: address, Secret: false},
	}
	if vaultToken != nil {
		values = append(values, &basev0.ConfigurationValue{Key: "token", Value: *vaultToken, Secret: true})
	}
	return &basev0.Configuration{
		Origin:         s.Unique(),
		RuntimeContext: resources.RuntimeContextFromInstance(instance),
		Infos: []*basev0.ConfigurationInformation{
			{Name: "vault",
				ConfigurationValues: values,
			},
		},
	}
}

func main() {
	svc := NewService()
	agents.Serve(agents.PluginRegistration{
		Agent:   svc,
		Runtime: NewRuntime(),
		Builder: NewBuilder(),
	})
}

//go:embed agent.codefly.yaml
var infoFS embed.FS

//go:embed templates/agent
var readmeFS embed.FS
