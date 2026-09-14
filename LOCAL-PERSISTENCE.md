# Local Vault persistence

Docker and Nix local runtimes use Vault's file backend. The server process/container
can be replaced without replacing transit keys or the KV v2 data used by consumers.
Deployment templates and production initialization/unseal policy are unchanged.

State lives under Codefly's `runtime-cache/<workspace-service-identity>/vault-state`:

- `vault-data/` contains the file backend.
- `credentials.json` contains local root/access credentials and the unseal key,
  written with mode 0600 inside a mode-0700 directory.
- `server.json` contains the local listener/storage configuration, without secrets.
- `runtime.lock` prevents concurrent agents from starting the same storage directory.

Keep data and custody together. Ordinary Stop/Destroy removes only the runtime
process/container. It does not delete local state. An initialized server without
its custody file, or custody without initialized storage, fails explicitly rather
than creating replacement keys. First initialization has an unavoidable failure
window before the returned custody is persisted; recovery fails closed if that
response or file is lost. Back up both before intentional cleanup.

No-configuration startup reuses the saved access token. An explicitly configured
local token is installed using Vault's token API after initialization/unseal.
Initialization and unseal bodies never enter logs or process arguments. Local custody
is a development convenience and is not the production unseal design.

Existing dev-mode ciphertext cannot be migrated after its old in-memory transit key
has already been lost. Reconnect affected sources once using a fresh credential.
Install the fixed agent before reconnecting if the next restart must retain that
credential. Do not restart a shared running stack merely to test migration.

Qualification:

```sh
GOMAXPROCS=2 go test -p 1 -v ./... -count=1
# Required on the supported Linux Nix CI runner (absence is a failure):
VAULT_REQUIRE_NIX=1 go test -race -v ./... -count=1
```

The mandatory persistence test uses the agent's exact image digest, an owned
temporary directory, and disposable containers on random loopback ports. It
creates ciphertext and KV data, removes the first container, starts a replacement
with the same state, and verifies both values. Missing custody, wrong unseal
custody, and invalid access custody must fail before restoring the original
credentials and proving the data remains readable. Bootstrap validates the saved
access token before publishing readiness; it never silently replaces rejected
credentials.

Both full agent lifecycles (Docker and Nix) exercise Stop/Destroy and replacement,
original ciphertext decryption, KV v2 retention, configured-token creation, and
saved-token reuse. Their Codefly homes are test-owned temporary directories.
The dedicated Linux Nix CI job runs the full suite with the race detector,
requires Nix, and cannot skip qualification.
Local hosts without Nix still report the existing explicit skip; that is not
Nix qualification evidence.

Runtime image releases retain JSON HIGH/CRITICAL audit reports and CycloneDX
SBOMs for both amd64 and arm64 in the `vault-runtime-evidence` Actions artifact.
`image.txt` binds those reports to the immutable published digest. A finding or
scanner failure fails the release job; `TestVaultImageAudit` independently audits
the agent's final pin with `FailOnVuln: true`.

Issue #47 owns this qualification and the image blocker for PR #46. Wiki adoption,
source reconnection through the UI, and sync before/after restart remain the
coordinated rollout in https://github.com/obin-ai/core-solutions/issues/133.
No shared Wiki process, container, volume, or encrypted state is changed by these
tests. Already-lost dev keys remain unrecoverable.
