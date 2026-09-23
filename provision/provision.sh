#!/bin/sh
# Provisions the state a deployed Vault's consumers depend on. It is the deployed
# counterpart of the local runtime (Runtime.enableTransit and localstate.go's
# bootstrap in runtime.go) and must converge on the same state: the transit
# engine at transit/ with the named key, and KV v2 at secret/.
#
# It runs as the vault container's postStart hook, so it runs on every start of
# the Vault process, against that process, over the pod's loopback. The
# container does not reach Running until it succeeds; a failure restarts the
# container and the next start runs it again.
#
# Usage: provision.sh <dev|durable> <transit-key-name>
#
# dev — `vault server -dev` (the ephemeral local-apply render). The server is
#   in-memory and initializes, unseals and mounts secret/ itself, so only
#   transit is provisioned, on every start. The token is VAULT_DEV_ROOT_TOKEN_ID,
#   the root token the server was started with.
#
# durable — the raft-backed, auto-unsealed server provision/server.sh starts
#   (restricted renders). State survives restarts; this script:
#     1. initializes the server once, when its storage is empty, writing the
#        init response to the data volume before anything else so a crash can
#        never lose the only root token;
#     2. installs VAULT_ACCESS_TOKEN — the token the composition supplies and
#        every consumer presents — as an orphan root-policy token;
#     3. mounts KV v2 at secret/ (the dev server's default mount) and
#        provisions transit, both idempotently;
#     4. revokes the initial root token and scrubs it from the init record,
#        which keeps only the recovery key material (PGP-encrypted to
#        VAULT_RECOVERY_PGP_KEY when the environment supplies one).
#
# Idempotent: existing state is success and nothing is rewritten. A transit key
# is never rotated or retyped — that would orphan every ciphertext and HMAC
# issued under it. Every write is read back, so a lost race converges and a
# failure reports what Vault actually holds.
#
# The script is rendered verbatim into the manifest, whose validator rejects any
# `$` + `{` sequence as an unresolved placeholder, so it expands variables only
# in the plain `$NAME` form. `set -u` is enabled once the optional inputs have
# been read.
set -e

if [ "$#" -lt 2 ] || [ -z "$2" ]; then
	echo "vault provisioning: usage: provision.sh <dev|durable> <transit-key-name>" >&2
	exit 64
fi
mode="$1"
key="$2"
case "$mode" in
dev)
	token="$VAULT_DEV_ROOT_TOKEN_ID"
	token_variable="VAULT_DEV_ROOT_TOKEN_ID"
	;;
durable)
	token="$VAULT_ACCESS_TOKEN"
	token_variable="VAULT_ACCESS_TOKEN"
	;;
*)
	echo "vault provisioning: unknown mode \"$mode\"" >&2
	exit 64
	;;
esac
if [ -z "$token" ]; then
	echo "vault provisioning: $token_variable is not set" >&2
	exit 64
fi
# The durable token is installed as a Vault token id through a JSON body; a
# value outside Vault's token alphabet could not be installed faithfully.
case "$token" in
*[!A-Za-z0-9._-]*)
	echo "vault provisioning: $token_variable holds characters a Vault token id cannot carry" >&2
	exit 64
	;;
esac
# How long to wait for the server, in one-second attempts, and where the
# durable init record lives. Only tests set them.
attempts=60
if [ -n "$VAULT_PROVISION_ATTEMPTS" ]; then
	attempts="$VAULT_PROVISION_ATTEMPTS"
fi
state="/vault/data/bootstrap"
if [ -n "$VAULT_BOOTSTRAP_DIR" ]; then
	state="$VAULT_BOOTSTRAP_DIR"
fi
recovery_pgp_key="$VAULT_RECOVERY_PGP_KEY"
set -u

export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_CLIENT_TIMEOUT="5s"
unset VAULT_TOKEN
# The init record holds the recovery key (and briefly the initial root token):
# everything this script writes is private to the vault user.
umask 077

fail() {
	echo "vault provisioning: $*" >&2
	exit 1
}

# `vault status` exits 0 when unsealed, 2 when sealed (an uninitialized server
# is sealed) and 1 when it cannot answer. `wait_for_server sealed` waits for the
# server to answer at all; `wait_for_server unsealed` waits for it to be usable.
wait_for_server() {
	attempt=0
	while :; do
		if vault status >/dev/null 2>&1; then
			return 0
		else
			status=$?
		fi
		if [ "$status" -eq 2 ] && [ "$1" = "sealed" ]; then
			return 0
		fi
		attempt=$((attempt + 1))
		if [ "$attempt" -ge "$attempts" ]; then
			fail "vault at $VAULT_ADDR did not become ready ($1)"
		fi
		sleep 1
	done
}

# The root token recorded in the init response, empty once scrubbed.
recorded_root() {
	if [ -f "$state/init.json" ]; then
		sed -n 's/^ *"root_token": *"\([^"]*\)".*$/\1/p' "$state/init.json"
	fi
}

initialize() {
	# Read from the API, not `vault operator init -status`, whose "not
	# initialized" exit code is also its exit code for an unreachable server.
	initialized="$(vault read -field=initialized sys/init 2>&1)" ||
		fail "cannot read the initialization status of vault at $VAULT_ADDR: $initialized"
	case "$initialized" in
	true) return 0 ;;
	false) ;;
	*) fail "unexpected initialization status from vault at $VAULT_ADDR: $initialized" ;;
	esac
	# Storage is empty. An init record without storage means the data volume is
	# not the one this record belongs to: initializing would mint new keys over
	# a lost store and hide the loss. That is an operator decision.
	if [ -e "$state/init.json" ]; then
		fail "vault storage is uninitialized but $state/init.json exists: the data volume does not match its init record; restore the volume, or move the record aside to initialize a new, empty Vault"
	fi
	mkdir -p "$state"
	chmod 700 "$state"
	set -- -recovery-shares=1 -recovery-threshold=1 -format=json
	if [ -n "$recovery_pgp_key" ]; then
		printf '%s\n' "$recovery_pgp_key" > "$state/recovery.pgp"
		set -- "$@" -recovery-pgp-keys="$state/recovery.pgp"
	fi
	# The response is the only copy of the root token and the recovery key, so
	# it goes straight to the data volume and is published by rename only once
	# it is complete. Initialization writes the keyring through the seal and
	# storage, so it gets far longer than the per-request timeout: a client that
	# gives up early can leave the server initialized with the response lost.
	VAULT_CLIENT_TIMEOUT="300s" vault operator init "$@" > "$state/init.json.partial" ||
		fail "vault initialization failed; if $state/init.json.partial is empty and vault now reports initialized, the response was lost: this Vault holds no data yet, so delete its data volume to initialize again"
	mv "$state/init.json.partial" "$state/init.json"
	rm -f "$state/recovery.pgp"
	echo "vault provisioning: initialized; recovery key material is in $state/init.json"
}

# Installs the supplied access token when the server does not yet know it.
install_access_token() {
	if VAULT_TOKEN="$token" vault token lookup >/dev/null 2>&1; then
		return 0
	fi
	root="$(recorded_root)"
	if [ -z "$root" ]; then
		reason="it holds no initial root token (the token was installed and the root revoked earlier)"
		if [ -e "$state/init.json.partial" ]; then
			reason="its initialization response was never recorded ($state/init.json.partial); this Vault holds no data yet, so delete its data volume to initialize again"
		fi
		fail "vault rejects $token_variable and cannot install it: $reason. A rotated access token must be created in Vault (orphan, root policy) with the current one before the secret changes"
	fi
	printf '{"id":"%s","policies":["root"],"no_parent":true,"display_name":"codefly-access"}\n' "$token" |
		VAULT_TOKEN="$root" vault write auth/token/create-orphan - >/dev/null 2>&1 || true
	if ! VAULT_TOKEN="$token" vault token lookup >/dev/null 2>&1; then
		fail "cannot install $token_variable as a vault token"
	fi
	echo "vault provisioning: installed the access token"
}

# secret/ must be KV version 2, the mount the dev server provides and consumers
# read with /v1/secret/data/<path>.
provision_kv() {
	if ! mount_type="$(vault read -field=type sys/mounts/secret 2>/dev/null)"; then
		enable_output="$(vault secrets enable -path=secret -version=2 kv 2>&1)" || true
		if ! mount_type="$(vault read -field=type sys/mounts/secret 2>&1)"; then
			fail "cannot enable KV v2 at secret/: $enable_output"
		fi
	fi
	if [ "$mount_type" != "kv" ]; then
		fail "secret/ is mounted as \"$mount_type\", not KV version 2"
	fi
	mount_options="$(vault read -field=options sys/mounts/secret 2>&1)" || fail "cannot read secret/ options: $mount_options"
	case "$mount_options" in
	*version:2*) ;;
	*) fail "secret/ is a KV mount but not version 2 ($mount_options)" ;;
	esac
}

provision_transit() {
	# transit/ must be a transit engine. Anything else mounted there is a
	# conflict this script must not paper over.
	if ! mount_type="$(vault read -field=type sys/mounts/transit 2>/dev/null)"; then
		enable_output="$(vault secrets enable -path=transit transit 2>&1)" || true
		if ! mount_type="$(vault read -field=type sys/mounts/transit 2>&1)"; then
			fail "cannot enable the transit engine: $enable_output"
		fi
	fi
	if [ "$mount_type" != "transit" ]; then
		fail "transit/ is mounted as \"$mount_type\", not a transit engine"
	fi
	# The key is created once; an existing key is left exactly as it is.
	if ! vault read -field=type "transit/keys/$key" >/dev/null 2>&1; then
		create_output="$(vault write -f "transit/keys/$key" type=aes256-gcm96 2>&1)" || true
		if ! vault read -field=type "transit/keys/$key" >/dev/null 2>&1; then
			fail "cannot create transit key \"$key\": $create_output"
		fi
	fi
}

# The initial root token is only a bootstrap credential: once the access token
# is installed and the mounts exist, it is revoked, and only then scrubbed from
# the record, so a crash in between leaves a token the next start can finish
# with.
retire_initial_root() {
	root="$(recorded_root)"
	if [ -z "$root" ]; then
		return 0
	fi
	VAULT_TOKEN="$root" vault token revoke -self >/dev/null 2>&1 || true
	if VAULT_TOKEN="$root" vault token lookup >/dev/null 2>&1; then
		fail "cannot revoke the initial root token"
	fi
	sed 's/^\( *"root_token": *"\)[^"]*"/\1"/' "$state/init.json" > "$state/init.json.scrubbed"
	mv "$state/init.json.scrubbed" "$state/init.json"
	echo "vault provisioning: revoked the initial root token"
}

if [ "$mode" = "durable" ]; then
	wait_for_server sealed
	initialize
	wait_for_server unsealed
	install_access_token
	export VAULT_TOKEN="$token"
	provision_kv
	provision_transit
	retire_initial_root
else
	wait_for_server unsealed
	export VAULT_TOKEN="$token"
	provision_transit
fi

echo "vault provisioning: transit engine and key \"$key\" ready"
