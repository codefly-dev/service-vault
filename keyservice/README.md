# Managed key-service runtime client

This leaf Go module keeps the managed-key provider driver with the existing
key-service agent owner. Host imports the runtime client without importing an
agent executable or its Core/build dependencies. No server or proxy is added.

The first provider is Azure Managed HSM: remote AES-256-GCM with authenticated
purpose, version-pinned HS256 MAC, and a separate AES key for wrapping signing
material. The client never generates or changes Host's signing identity. A
consumer keeps its existing envelope framing and validates unwrapped key material.

`New` accepts a deployment-produced JSON descriptor with `provider` set to
`azure-managed-hsm` and `settings` containing `tenant_id`, `client_id`,
`envelope_key`, `mac_key`, and `signing_wrap_key`. Each key is an exact version URL
under the same public-cloud `managedhsm.azure.net` endpoint; purpose keys must be
distinct. Only Azure Workload Identity is used. There is no operator-login or
environment-secret credential fallback.

The constructor validates key identity, HSM custody, enabled state, validity and
operations, then proves encryption/decryption and MAC access before returning.
Ciphertexts retain their key version, IV and authentication tag. Reads accept
historical versions of the same purpose key, so normal rotation preserves old
data. MAC does not follow the latest key version: changing its configured version
requires an explicit lookup migration. Organization-bound clients cannot use
deployment MAC or signing-material operations. Provider errors preserve status
without retaining response bodies or reflected plaintext.

## Build or reuse

| Searched | Result and decision |
| --- | --- |
| service-vault external binding, projection and provisioning; Host key-service interfaces; CLI #924; SDK Go accessors; handbook service/agent inventory | Reuse the existing owner and Host's envelope/signing contracts. No managed runtime driver exists. Add a leaf client, following the existing service-redis/cache and service-postgres/libs/go ownership pattern. |
| Azure Go SDK azkeys/azidentity and Go crypto/encoding libraries | Use the existing SDK for identity, challenges, serialization and key operations. Use standard encoding for retained provider payloads; no HTTP/auth implementation or cryptographic primitive is added. |

## Qualification and deployment boundary

Run `go test -race ./...` and `go vet ./...` in this directory. Tests exercise the
real Azure SDK against a controlled transport using actual AES-GCM/HMAC, including
restart, rotation, preserved Ed25519 material, wrong purpose, denied access,
wrong key, exportable keys and organization isolation. They do not prove Azure
provisioning, live workload federation, backup/restore or HSM API compatibility.

A Standard Key Vault cannot provide this binding. Deployment still needs an
activated Managed HSM, supported recovery custody, exact workload grants and
applied key-version references. This package creates none of those resources.
Remote HS256 behavior and service limits must be qualified against that installed
backend before deployment; a controlled transport is not live evidence.

References: [Managed HSM algorithms](https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/about-keys-details),
[encryption API](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/encrypt/encrypt),
[sign API](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/sign/sign),
[existing owner gap](https://github.com/codefly-dev/cli/issues/924).
