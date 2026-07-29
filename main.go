package main

import (
	"context"
	"embed"

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

type Settings struct {
	TransitKey string `yaml:"transit-key"`
}

var image = &resources.DockerImage{
	Name:   "ghcr.io/codefly-dev/service-vault-runtime",
	Tag:    "runtime-v2.0.3-patched.4",
	Digest: "sha256:00b9a5fb0eef11f758be2e0978ed8b5a01f9fdadb1f895f652f84d52699741e5",
}

type Service struct {
	*services.Base

	// Settings
	*Settings

	vaultToken string

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

func (s *Service) LoadConfiguration(ctx context.Context, conf *basev0.Configuration) error {
	var err error
	s.vaultToken, err = resources.GetConfigurationValue(ctx, conf, "vault", "VAULT_TOKEN")
	if err != nil {
		return s.Wool.Wrapf(err, "cannot get vault token")
	}
	return nil
}

func (s *Service) CreateConnectionConfiguration(ctx context.Context, instance *basev0.NetworkInstance, includeToken bool) *basev0.Configuration {
	address := instance.Address
	values := []*basev0.ConfigurationValue{
		{Key: "address", Value: address, Secret: false},
	}
	if includeToken {
		values = append(values, &basev0.ConfigurationValue{Key: "token", Value: s.vaultToken, Secret: true})
	}
	return &basev0.Configuration{
		Origin:         s.Base.Unique(),
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
