# Endpoint policy at the agent boundary

Vault uses Core's module interface projection when Runtime.Load reads a service.
The endpoint returned over gRPC carries the effective visibility and grant list:
an endpoint absent from the module interface is private with no allow-list; a
public export has no allow-list; an internal export carries exactly its declared
allow-modules. The service's authored wildcard cannot widen a narrower export.
Location is a separate axis and remains unchanged.

Builder.Create authors an internal endpoint with an explicit wildcard, preserving
the scaffold's previous module reachability. A composing module still decides
whether to export that endpoint. Do not export an otherwise private Vault endpoint
to accommodate an old agent's wire output.

The agent consumes Core's current endpoint projection implementation. The
regression invokes the real Runtime.Load handler over gRPC for private, public
and narrower internal exports, then validates the proposed Init network mappings:

```sh
go test -race . -run '^TestRuntimeLoadCarriesEffectiveEndpointPolicy$' -count=1
go vet ./...
```

For local qualification without replacing a released installed agent, build in
an isolated Codefly home through the supported CLI:

```sh
codefly agent build --dir . --native-only --plugin-path /path/to/isolated-codefly-home
```

Select that same home with `--plugin-path` or `CODEFLY_HOME` in the consuming run.
The selection covers the entire Codefly home, including runtime state and other
agents resolved there. Keep its exact source commit and binary digest with the
run evidence. This local build does not publish a release or qualify deployment.
