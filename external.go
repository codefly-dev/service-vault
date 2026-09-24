package main

import (
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strings"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/resources"
)

// ExternalInstance binds one deployment environment to a Vault this service
// does not run. The operator of that Vault owns its storage, seal, TLS,
// authentication methods, policies, the transit key consumers use and any
// secret they read; this service only hands consumers the coordinates.
type ExternalInstance struct {
	// Address is the external Vault's base URL. It must be HTTPS: consumers
	// authenticate to it with a token and read key material from it.
	Address string `yaml:"address"`
	// CAFile is the absolute path, inside every consumer's pods, of the PEM
	// bundle that verifies Address. Empty verifies against the system roots.
	// The environment projects the file; this service never carries it.
	CAFile string `yaml:"ca-file"`
	// TokenFile is the absolute path, inside every consumer's pods, of a file
	// holding a current Vault token — typically kept fresh by an agent that
	// authenticates with the Vault's Kubernetes auth method as the consumer's
	// own workload identity. Empty means consumers present the static token
	// from this service's `vault` secret configuration instead.
	TokenFile string `yaml:"token-file"`
}

// externalInstance returns the binding for environment, nil when this service
// declares no external instances at all. Once any environment is bound, every
// environment must be: a misspelled or missing name must fail, not silently
// fall back to running a Vault of its own.
func (s *Service) externalInstance(environment string) (*ExternalInstance, error) {
	if s.Settings == nil || len(s.ExternalInstances) == 0 {
		return nil, nil
	}
	for name, binding := range s.ExternalInstances {
		if err := binding.validate(); err != nil {
			return nil, fmt.Errorf("external-instances.%s: %w", name, err)
		}
	}
	binding, bound := s.ExternalInstances[environment]
	if !bound {
		names := make([]string, 0, len(s.ExternalInstances))
		for name := range s.ExternalInstances {
			names = append(names, name)
		}
		sort.Strings(names)
		return nil, fmt.Errorf("external-instances binds %s but not environment %q; bind every environment this service deploys to", strings.Join(names, ", "), environment)
	}
	return &binding, nil
}

func (binding ExternalInstance) validate() error {
	address, err := url.Parse(binding.Address)
	if err != nil || address.Scheme != "https" || address.Host == "" || address.Hostname() == "" ||
		address.User != nil || address.RawQuery != "" || address.Fragment != "" || address.Opaque != "" ||
		(address.Path != "" && address.Path != "/") {
		return fmt.Errorf("address %q must be an https://host[:port] base URL", binding.Address)
	}
	for _, file := range []struct{ key, path string }{{"ca-file", binding.CAFile}, {"token-file", binding.TokenFile}} {
		if file.path == "" {
			continue
		}
		if !filepath.IsAbs(file.path) || filepath.Clean(file.path) != file.path || strings.ContainsAny(file.path, " \t\r\n") {
			return fmt.Errorf("%s %q must be a clean absolute path", file.key, file.path)
		}
	}
	return nil
}

// externalConnectionConfiguration is what consumers of an externally bound
// Vault receive under `vault`: the address, the CA and token files when the
// environment projects them, and — only without a token file — the token
// capability (the value for the ephemeral profile, an empty secret the
// promotion driver fills for a restricted one).
func (s *Service) externalConnectionConfiguration(instance *basev0.NetworkInstance, binding *ExternalInstance, token *string) *basev0.Configuration {
	values := []*basev0.ConfigurationValue{
		{Key: "address", Value: strings.TrimSuffix(binding.Address, "/")},
	}
	if binding.CAFile != "" {
		values = append(values, &basev0.ConfigurationValue{Key: "ca-file", Value: binding.CAFile})
	}
	if binding.TokenFile != "" {
		values = append(values, &basev0.ConfigurationValue{Key: "token-file", Value: binding.TokenFile})
	} else if token != nil {
		values = append(values, &basev0.ConfigurationValue{Key: "token", Value: *token, Secret: true})
	}
	return &basev0.Configuration{
		Origin:         s.Unique(),
		RuntimeContext: resources.RuntimeContextFromInstance(instance),
		Infos: []*basev0.ConfigurationInformation{
			{Name: "vault", ConfigurationValues: values},
		},
	}
}
