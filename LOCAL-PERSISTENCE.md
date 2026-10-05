# Local Vault persistence

Docker and Nix local runtimes use Vault's file backend. The server process/container
can be replaced without replacing transit keys or the KV v2 data used by consumers.
Deployments are described in the agent README: restricted renders run a durable,
auto-unsealed raft server or bind an external instance; only the ephemeral
local-apply render still runs the in-memory dev server.

State lives under Codefly's `runtime-cache/<workspace-service-identity>/vault-state`:

- `vault-data/` contains the file backend.
- `credentials.json` contains local custody — the root token and the unseal key —
  and the access token published to consumers, written with mode 0600 inside a
  mode-0700 directory.
- `server.json` contains the local listener/storage configuration, without secrets.
- `runtime.lock` prevents concurrent agents from starting the same storage directory.

Keep data and custody together. Ordinary Stop/Destroy removes only the runtime
process/container. It does not delete local state. An initialized server without
its custody file, or custody without initialized storage, fails explicitly rather
than creating replacement keys. First initialization has an unavoidable failure
window before the returned custody is persisted; recovery fails closed if that
response or file is lost. Back up both before intentional cleanup.

The root token and the unseal key stay in custody: the agent uses them to unseal
the server, mount KV v2 and transit, write the `codefly-access` policy and seed
the signing key, and never publishes or logs either. What consumers receive is a
separate orphan token carrying only `codefly-access`, which grants the paths a
consumer reads and writes — KV v2 under `secret/` and the configured transit
key's operations — and nothing under `sys/` or `auth/`. The published token
cannot mount an engine, read a policy, mint a token or touch another transit
key; the agent README lists the policy in full.

The published token is issued with a ten-year lifetime, and the local token
store's maximum lease TTL is raised to match before it is created: Vault caps a
non-root token at that ceiling and a scoped token cannot renew itself, so the
token stays the static secret consumers already hold.

No-configuration startup reuses the saved access token when Vault still holds it
with that policy. An explicitly configured local token is installed under the
same policy using Vault's token API after initialization/unseal. Custody carried
over from a build that published the root token directly is migrated on the next
start: the policy is written, a scoped token is minted and published, and a
previously published token that grants more is revoked first. The root token in
custody is never revoked — it is the administrative credential, not a published
one. An access token Vault rejects still fails closed rather than being replaced
silently. Initialization and unseal bodies never enter logs or process arguments.
The policy is rewritten on every start, so changing `transit-key` locally needs
no further step. Local custody is a development convenience and is not the
production unseal design.

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
