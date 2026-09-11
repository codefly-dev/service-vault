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
GOMAXPROCS=2 go test -p 1 ./... -run '^TestCreateToRunDocker$' -count=1
GOMAXPROCS=2 VAULT_PERSISTENCE_IMAGE=<installed-pinned-image> go test -p 1 ./... \
  -run 'TestLocalVault|TestRetryShutdown|TestVaultServerArgsKeepRootTokenSecret' -count=1
```

The opt-in persistence test owns a temporary directory and two disposable containers
on random loopback ports. It creates ciphertext and KV data, removes the first
container, starts a replacement with the same state, and verifies both values.
Unit cases cover concurrent local ownership, private custody permissions and missing
storage/custody. The full Docker lifecycle verifies configured-token creation and
reuse on a later initialization without configuration. Nix uses the same bootstrap;
its process qualification additionally requires Nix on the host.
