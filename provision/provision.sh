#!/bin/sh
# Provisions the state a deployed Vault's consumers depend on. It is the deployed
# counterpart of the local runtime (Runtime.enableTransit and localstate.go's
# bootstrap in runtime.go) and must converge on the same state: the transit
# engine at transit/ with the named key, KV v2 at secret/, and an access token
# that grants only the paths a consumer reads and writes.
#
# It runs as the vault container's postStart hook, so it runs on every start of
# the Vault process, against that process, over the pod's loopback. The
# container does not reach Running until it succeeds; a failure restarts the
# container and the next start runs it again.
#
# Usage: provision.sh <dev|durable> <transit-key-name>
#
# VAULT_ACCESS_TOKEN is, in both modes, the token the composition supplies and
# every consumer presents. It is installed as an orphan carrying only the
# "codefly-access" policy below: no consumer ever receives a root-policy token,
# so a consumer cannot read another module's key, reconfigure or rotate a
# transit key, mount an engine, read a policy or mint a token.
#
# Every privileged step runs under a bootstrap root token that never leaves the
# Vault's own container or data volume, is never published to a consumer and
# never reaches output:
#
# dev — the in-memory server of the ephemeral local-apply render. provision/dev.sh
#   mints the bootstrap root, starts `vault server -dev` with it and leaves it in
#   the container's tmpfs; both die with the container, as the store does. The
#   server initializes, unseals and mounts secret/ itself, so this script
#   provisions transit, the policy and the access token on every start.
#
# durable — the raft-backed, auto-unsealed server provision/server.sh starts
#   (restricted renders). State survives restarts; this script:
#     1. initializes the server once, when its storage is empty, writing the
#        init response to the data volume before anything else so a crash can
#        never lose the only root token;
#     2. mounts KV v2 at secret/ (the dev server's default mount) and provisions
#        transit, both idempotently, under that root token;
#     3. writes the "codefly-access" policy and installs VAULT_ACCESS_TOKEN as
#        an orphan carrying only it;
#     4. revokes the initial root token and scrubs it from the init record,
#        which keeps only the recovery key material (PGP-encrypted to
#        VAULT_RECOVERY_PGP_KEY when the environment supplies one).
#   A later start finds no bootstrap root and needs none: the access token
#   already exists and the mounts and the key are already there, so the script
#   only verifies what that token can reach.
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
dev | durable) ;;
*)
	echo "vault provisioning: unknown mode \"$mode\"" >&2
	exit 64
	;;
esac
token_variable="VAULT_ACCESS_TOKEN"
token="$VAULT_ACCESS_TOKEN"
if [ -z "$token" ]; then
	echo "vault provisioning: $token_variable is not set" >&2
	exit 64
fi
# The access token is installed as a Vault token id through a JSON body; a
# value outside Vault's token alphabet could not be installed faithfully.
case "$token" in
*[!A-Za-z0-9._-]*)
	echo "vault provisioning: $token_variable holds characters a Vault token id cannot carry" >&2
	exit 64
	;;
esac
# How long to wait for the server, in one-second attempts, and where the
# bootstrap credentials live. Only tests set them.
attempts=60
if [ -n "$VAULT_PROVISION_ATTEMPTS" ]; then
	attempts="$VAULT_PROVISION_ATTEMPTS"
fi
state="/vault/data/bootstrap"
if [ -n "$VAULT_BOOTSTRAP_DIR" ]; then
	state="$VAULT_BOOTSTRAP_DIR"
fi
dev_root_file="/tmp/vault-dev-root"
if [ -n "$VAULT_DEV_ROOT_FILE" ]; then
	dev_root_file="$VAULT_DEV_ROOT_FILE"
fi
recovery_pgp_key="$VAULT_RECOVERY_PGP_KEY"
set -u

# The policy the access token carries, and the only one it carries, and how long
# that token lives. provision.go declares both values and a test holds the two
# copies together.
#
# A root-policy token never expired; a scoped one is capped at the token store's
# max lease TTL (768h by default) and cannot renew itself, so the store is tuned
# to this TTL before the token is created. Consumers hold the token as a static
# secret with no renewal path: a real rotation lifetime means consumers
# authenticating to Vault themselves, which changes what they receive rather
# than what it reaches.
policy="codefly-access"
token_ttl="87600h"

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

# The bootstrap root token this start holds, empty when it holds none. In dev
# mode that is the token provision/dev.sh minted for this container; in durable
# mode the one recorded in the init response, which is empty once it has been
# revoked and scrubbed — every later start of a provisioned Vault.
bootstrap_root() {
	if [ "$mode" = "dev" ]; then
		if [ -f "$dev_root_file" ]; then
			cat "$dev_root_file"
		fi
		return 0
	fi
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

# The paths a consumer reads and writes, and nothing else: KV v2 under secret/,
# and the one configured transit key's operations plus a read of the key itself
# (its type and version, never its material). Vault attaches its own `default`
# policy to every non-root token on top of this; that policy grants a token only
# operations on itself and its own cubbyhole, and no path under secret/ or
# transit/. Absent here, and therefore denied: everything under sys/ (no mount,
# no policy, no audit device, no seal setting), everything under auth/ beyond
# `default`'s self-management (no token creation), every other transit key, and
# creating, rotating, retyping or deleting a transit key.
consumer_policy() {
	cat <<EOF
path "secret/data/*" {
  capabilities = ["create", "read", "update", "patch", "delete"]
}

path "secret/metadata/*" {
  capabilities = ["read", "list", "delete"]
}

path "secret/delete/*" {
  capabilities = ["update"]
}

path "secret/undelete/*" {
  capabilities = ["update"]
}

path "secret/destroy/*" {
  capabilities = ["update"]
}

path "transit/encrypt/$key" {
  capabilities = ["update"]
}

path "transit/decrypt/$key" {
  capabilities = ["update"]
}

path "transit/hmac/$key" {
  capabilities = ["update"]
}

path "transit/verify/$key" {
  capabilities = ["update"]
}

path "transit/rewrap/$key" {
  capabilities = ["update"]
}

path "transit/keys/$key" {
  capabilities = ["read"]
}
EOF
}

# Written under the bootstrap root, then read back. Rewriting it is how a
# changed transit key name reaches an already-provisioned Vault's policy.
install_consumer_policy() {
	policy_output="$(consumer_policy | VAULT_TOKEN="$1" vault policy write "$policy" - 2>&1)" || true
	if ! VAULT_TOKEN="$1" vault policy read "$policy" >/dev/null 2>&1; then
		fail "cannot write the \"$policy\" policy: $policy_output"
	fi
}

# Raises the token store's ceiling to $token_ttl so the access token below is
# issued with that lifetime instead of being silently capped at 768h — a cap
# would stop every consumer reading the store a month after provisioning. It
# lengthens no existing token and grants no capability; only the ceiling moves.
allow_long_lived_tokens() {
	tune_output="$(VAULT_TOKEN="$1" vault write sys/auth/token/tune max_lease_ttl="$token_ttl" 2>&1)" ||
		fail "cannot raise the token store's maximum lease TTL to $token_ttl, which the access token needs: $tune_output"
}

# Whether the token Vault holds for $token carries only the consumer policy. A
# Vault provisioned before this agent scoped the access token holds it with the
# root policy; that is detected here rather than served.
access_token_is_scoped() {
	policies="$(VAULT_TOKEN="$token" vault read -field=policies auth/token/lookup-self 2>/dev/null)" || return 1
	case "$policies" in
	*root*) return 1 ;;
	esac
	case "$policies" in
	*"$policy"*) return 0 ;;
	*) return 1 ;;
	esac
}

# Installs the supplied access token, scoped to the consumer policy, when the
# server does not yet hold it that way.
install_access_token() {
	root="$(bootstrap_root)"
	if VAULT_TOKEN="$token" vault token lookup >/dev/null 2>&1; then
		if access_token_is_scoped; then
			return 0
		fi
		# The token exists but grants more than a consumer's paths. Replacing it
		# needs a root credential: with one, revoke and reinstall; without one,
		# refuse rather than keep handing consumers an over-privileged token.
		if [ -z "$root" ]; then
			fail "vault holds $token_variable with more than the \"$policy\" policy and this start holds no bootstrap root token to replace it. Revoke that token and create it again as an orphan carrying only \"$policy\", using a root token generated from the recovery key in $state/init.json"
		fi
		VAULT_TOKEN="$root" vault token revoke "$token" >/dev/null 2>&1 || true
		if VAULT_TOKEN="$token" vault token lookup >/dev/null 2>&1; then
			fail "cannot revoke the over-privileged $token_variable"
		fi
		echo "vault provisioning: revoked an access token that was not scoped to \"$policy\""
	fi
	if [ -z "$root" ]; then
		reason="it holds no initial root token (the token was installed and the root revoked earlier)"
		if [ "$mode" = "dev" ]; then
			reason="the in-memory server's bootstrap credential is missing from $dev_root_file (provision/dev.sh did not start this container)"
		elif [ -e "$state/init.json.partial" ]; then
			reason="its initialization response was never recorded ($state/init.json.partial); this Vault holds no data yet, so delete its data volume to initialize again"
		fi
		# The current access token cannot mint its own replacement — that is the
		# point of scoping it — so a rotation is taken with a root token
		# generated from the recovery key.
		fail "vault rejects $token_variable and cannot install it: $reason. A rotated access token must be created in Vault (orphan, \"$policy\" policy, ttl $token_ttl) before the secret changes, using a root token generated from the recovery key in $state/init.json"
	fi
	install_consumer_policy "$root"
	allow_long_lived_tokens "$root"
	printf '{"id":"%s","policies":["%s"],"no_parent":true,"ttl":"%s","display_name":"codefly-access"}\n' "$token" "$policy" "$token_ttl" |
		VAULT_TOKEN="$root" vault write auth/token/create-orphan - >/dev/null 2>&1 || true
	if ! VAULT_TOKEN="$token" vault token lookup >/dev/null 2>&1; then
		fail "cannot install $token_variable as a vault token"
	fi
	if ! access_token_is_scoped; then
		fail "vault installed $token_variable without the \"$policy\" policy"
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

# What a consumer will actually find: the configured key, reachable with the
# access token's own capabilities. On a start that holds no bootstrap root this
# is the whole check, so a Vault whose key no longer matches `transit-key`
# reports it here instead of answering every consumer's encrypt with a 403.
verify_consumer_access() {
	if ! VAULT_TOKEN="$token" vault read -field=type "transit/keys/$key" >/dev/null 2>&1; then
		fail "$token_variable cannot read transit key \"$key\"; this Vault was provisioned with another key name, which is an operator step: create the key and rewrite the \"$policy\" policy with a root token generated from the recovery key in $state/init.json"
	fi
}

# The initial root token is only a bootstrap credential: once the access token
# is installed and the mounts exist, it is revoked, and only then scrubbed from
# the record, so a crash in between leaves a token the next start can finish
# with.
retire_initial_root() {
	root="$(bootstrap_root)"
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
fi
wait_for_server unsealed

# Mounts and the key are privileged: they are provisioned under the bootstrap
# root while this start holds one. A durable restart holds none and needs none —
# the store already carries them.
bootstrap="$(bootstrap_root)"
if [ -n "$bootstrap" ]; then
	export VAULT_TOKEN="$bootstrap"
	provision_kv
	provision_transit
	unset VAULT_TOKEN
fi
install_access_token
verify_consumer_access
if [ "$mode" = "durable" ]; then
	retire_initial_root
fi

echo "vault provisioning: transit engine and key \"$key\" ready"
