#!/bin/sh
# Provisions the transit state a deployed Vault's consumers depend on: the
# transit secrets engine at transit/ and the named encryption key. It is the
# deployed counterpart of Runtime.enableTransit in runtime.go and must converge
# on the same state.
#
# It runs as the vault container's postStart hook, so it runs on every start of
# the Vault process, against that process, over the pod's loopback. The deployed
# Vault is `vault server -dev` (in-memory): every restart starts from an empty
# store, so provisioning has to follow the process, not the rollout.
#
# Idempotent: an engine already mounted at transit/ and a key that already
# exists are success, and nothing is rewritten. Every step ends by reading the
# state back, so a lost race with a concurrent writer converges instead of
# failing, and a failure reports what Vault actually holds.
#
# Usage: transit.sh <transit-key-name>
# Reads the token from VAULT_DEV_ROOT_TOKEN_ID — the root token the container
# itself was started with, projected from the deployment's Vault token secret.
#
# The script is rendered verbatim into the manifest, whose validator rejects
# any `$` + `{` sequence as an unresolved placeholder, so it expands variables
# only in the plain `$NAME` form. `set -u` is enabled once the optional inputs
# have been read.
set -e

if [ "$#" -lt 1 ] || [ -z "$1" ]; then
	echo "vault provisioning: transit key name is required" >&2
	exit 64
fi
key="$1"
if [ -z "$VAULT_DEV_ROOT_TOKEN_ID" ]; then
	echo "vault provisioning: VAULT_DEV_ROOT_TOKEN_ID is not set" >&2
	exit 64
fi
# How long to wait for the server, in one-second attempts. Only tests set it.
attempts=60
if [ -n "$VAULT_PROVISION_ATTEMPTS" ]; then
	attempts="$VAULT_PROVISION_ATTEMPTS"
fi
set -u

export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN="$VAULT_DEV_ROOT_TOKEN_ID"
export VAULT_CLIENT_TIMEOUT="5s"

# The hook starts concurrently with the server; wait for it to answer unsealed
# (`vault status` exits 0 only when unsealed).
attempt=0
until vault status >/dev/null 2>&1; do
	attempt=$((attempt + 1))
	if [ "$attempt" -ge "$attempts" ]; then
		echo "vault provisioning: vault at $VAULT_ADDR did not become ready" >&2
		exit 1
	fi
	sleep 1
done

# transit/ must be a transit engine. Anything else mounted there is a conflict
# this script must not paper over.
if ! mount_type="$(vault read -field=type sys/mounts/transit 2>/dev/null)"; then
	enable_output="$(vault secrets enable -path=transit transit 2>&1)" || true
	if ! mount_type="$(vault read -field=type sys/mounts/transit 2>&1)"; then
		echo "vault provisioning: cannot enable the transit engine: $enable_output" >&2
		exit 1
	fi
fi
if [ "$mount_type" != "transit" ]; then
	echo "vault provisioning: transit/ is mounted as \"$mount_type\", not a transit engine" >&2
	exit 1
fi

# The key is created once, as the local runtime creates it; an existing key is
# left exactly as it is — rotating or retyping it would orphan every ciphertext
# and HMAC already issued under it.
if ! vault read -field=type "transit/keys/$key" >/dev/null 2>&1; then
	create_output="$(vault write -f "transit/keys/$key" type=aes256-gcm96 2>&1)" || true
	if ! vault read -field=type "transit/keys/$key" >/dev/null 2>&1; then
		echo "vault provisioning: cannot create transit key \"$key\": $create_output" >&2
		exit 1
	fi
fi

echo "vault provisioning: transit engine and key \"$key\" ready"
