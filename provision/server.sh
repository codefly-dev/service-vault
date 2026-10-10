#!/bin/sh
# Starts the durable Vault server a restricted (deployed) render runs: integrated
# raft storage on the pod's persistent volume, auto-unsealed by the seal the
# environment supplies. It is the container's command, and it provisions the
# server it started: provision/provision.sh (durable mode, passed as $1 with the
# transit key name as $2) initializes it once and provisions it on every start.
#
# Provisioning runs here, not as a postStart hook: a cell's execution admission
# refuses any container with an exec probe or hook (a command of the delivering
# party's choosing, run inside a pod that already holds the workload identity),
# so the start-up work lives in the container's own command. A provisioning
# failure stops the server and exits non-zero, so the container restarts and
# the next start provisions again — what a failed hook did.
#
# The seal is environment configuration, never part of this agent's render: the
# composition declares it as the vault service's non-secret configuration
# (VAULT_SEAL_TYPE plus that seal's own variables, for example gcpckms's
# GOOGLE_PROJECT, GOOGLE_REGION, VAULT_GCPCKMS_SEAL_KEY_RING and
# VAULT_GCPCKMS_SEAL_CRYPTO_KEY), and the seal authenticates as the pod's
# workload identity. Without an auto-unseal seal a durable server would come up
# sealed after every restart with no one holding its unseal keys, so the server
# refuses to start instead.
#
# Rendered verbatim into the manifest, whose validator rejects any `$` + `{`
# sequence as an unresolved placeholder: variables are expanded only as $NAME.
set -eu

data="/vault/data"
config="/tmp/vault-server.hcl"

if [ -z "$(printenv VAULT_SEAL_TYPE || true)" ]; then
	echo "vault: no auto-unseal seal is configured. A durable Vault needs VAULT_SEAL_TYPE and that seal's settings (for gcpckms: GOOGLE_PROJECT, GOOGLE_REGION, VAULT_GCPCKMS_SEAL_KEY_RING, VAULT_GCPCKMS_SEAL_CRYPTO_KEY) supplied by the environment as this service's configuration" >&2
	exit 78
fi
if [ "$VAULT_SEAL_TYPE" = "shamir" ]; then
	echo "vault: VAULT_SEAL_TYPE=shamir is not an auto-unseal seal; a durable Vault must unseal itself after every restart" >&2
	exit 78
fi

umask 077
mkdir -p "$data/raft"

# One node, so the cluster and API addresses are loopback: the pod IP changes on
# every reschedule and nothing else ever joins this raft cluster. The listener
# is plaintext exactly as the in-memory server it replaces was; transport
# protection between pods is the platform's (mesh) concern.
cat > "$config" <<'EOF'
storage "raft" {
  path = "/vault/data/raft"
}

listener "tcp" {
  address         = "0.0.0.0:8200"
  cluster_address = "127.0.0.1:8201"
  tls_disable     = true
}

api_addr      = "http://127.0.0.1:8200"
cluster_addr  = "https://127.0.0.1:8201"
disable_mlock = true
ui            = false
EOF

provision="$1"
key="$2"

vault server -config="$config" &
server=$!
# dumb-init forwards a termination signal to the whole process group, so the
# server receives it too; wait for it to shut down rather than leave it to be
# killed when this shell exits.
trap 'wait "$server"; exit $?' TERM INT

if ! /bin/sh -c "$provision" vault-provision durable "$key"; then
	echo "vault: provisioning failed; stopping the server so the container restarts and provisions again" >&2
	kill -TERM "$server" 2>/dev/null || true
	wait "$server" || true
	exit 1
fi
echo "vault: provisioned"
wait "$server"
