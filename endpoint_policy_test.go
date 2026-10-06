package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	runtimev0 "github.com/codefly-dev/core/generated/go/codefly/services/runtime/v0"
	"github.com/codefly-dev/core/network"
	"github.com/codefly-dev/core/resources"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Exercise the real owner's Load over gRPC, then the exact proposed mapping
// shape used at Init. No Vault process or secret is needed to prove endpoint
// policy projection at this boundary.
func TestRuntimeLoadCarriesEffectiveEndpointPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, export, visibility string
		allow                    []string
	}{
		{"unexported", "", "private", nil},
		{"narrow export", "    - service: vault\n      endpoint: http\n      visibility: internal\n      allow-modules: [consumer]\n", "internal", []string{"consumer"}},
		{"public export", "    - service: vault\n      endpoint: http\n      visibility: public\n", "public", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			write := func(name, value string) {
				p := filepath.Join(root, name)
				require.NoError(t, os.MkdirAll(filepath.Dir(p), 0755))
				require.NoError(t, os.WriteFile(p, []byte(value), 0600))
			}
			write("module.codefly.yaml", "kind: module\nname: example\nservices:\n  - name: vault\n  - name: frontend\ninterface:\n  endpoints:\n    - service: frontend\n      endpoint: http\n      visibility: public\n"+tc.export)
			for _, service := range []string{"vault", "frontend"} {
				write("services/"+service+"/service.codefly.yaml", fmt.Sprintf("name: %s\nversion: 0.0.0\nendpoints:\n  - name: http\n    visibility: internal\n    allow-modules: [\"*\"]\n", service))
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			server := grpc.NewServer()
			runtimev0.RegisterRuntimeServer(server, NewRuntime())
			go func() { _ = server.Serve(listener) }()
			t.Cleanup(server.Stop)
			conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
			require.NoError(t, err)
			t.Cleanup(func() { _ = conn.Close() })
			env := resources.LocalEnvironment()
			protoEnv, err := env.Proto()
			require.NoError(t, err)
			loaded, err := runtimev0.NewRuntimeClient(conn).Load(t.Context(), &runtimev0.LoadRequest{
				DisableCatch: true, Environment: protoEnv,
				Identity: &basev0.ServiceIdentity{Name: "vault", Module: "example", Workspace: "example", WorkspacePath: root, RelativeToWorkspace: "services/vault"},
			})
			require.NoError(t, err)
			require.Len(t, loaded.Endpoints, 1)
			endpoint := loaded.Endpoints[0]
			require.Equal(t, tc.visibility, endpoint.Visibility)
			require.Equal(t, tc.allow, endpoint.AllowModules, "authored wildcard must not survive a private/public/narrow module export")
			mappings, err := network.NewRuntimeManager(t.Context(), nil)
			require.NoError(t, err)
			mappings.WithTemporaryPorts()
			proposed, err := mappings.GenerateNetworkMappings(t.Context(), env, &resources.Workspace{Name: "example"}, &resources.ServiceIdentity{Module: "example", Name: "vault"}, loaded.Endpoints, resources.NewRuntimeContextFree())
			require.NoError(t, err)
			require.NoError(t, resources.Validate(&runtimev0.InitRequest{RuntimeContext: resources.NewRuntimeContextFree(), ProposedNetworkMappings: proposed}))
		})
	}
}
