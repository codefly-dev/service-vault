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

var image = &resources.DockerImage{Name: "hashicorp/vault", Tag: "1.21"}

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

	return &agentv0.AgentInformation{
		// Advertise the nix runtime (implemented in nixvault.go via
		// RuntimeContextNix) so the CLI's per-service Docker-free gate
		// (flow.resolveDockerFallback → Runner.SupportsNix) lets this service
		// fall back to a nix-provisioned native vault when Docker is
		// unreachable. Without it the run hard-stops with "requires Docker"
		// even though the nix path works.
		RuntimeRequirements: []*agentv0.Runtime{
			{Type: agentv0.Runtime_NIX},
		},
		Capabilities: []*agentv0.Capability{
			{Type: agentv0.Capability_BUILDER},
			{Type: agentv0.Capability_RUNTIME},
		},
		Protocols: []*agentv0.Protocol{},
		ConfigurationDetails: []*agentv0.ConfigurationValueDetail{
			{
				Name: "vault", Description: "vault connection",
				Fields: []*agentv0.ConfigurationValueInformation{
					{Name: "address", Description: "vault HTTP address"},
					{Name: "token", Description: "vault authentication token"},
				},
			},
		},
		ReadMe: readme,
	}, nil
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

func (s *Service) CreateConnectionConfiguration(ctx context.Context, instance *basev0.NetworkInstance) *basev0.Configuration {
	address := instance.Address
	return &basev0.Configuration{
		Origin:         s.Base.Unique(),
		RuntimeContext: resources.RuntimeContextFromInstance(instance),
		Infos: []*basev0.ConfigurationInformation{
			{Name: "vault",
				ConfigurationValues: []*basev0.ConfigurationValue{
					{Key: "address", Value: address, Secret: false},
					{Key: "token", Value: s.vaultToken, Secret: true},
				},
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
