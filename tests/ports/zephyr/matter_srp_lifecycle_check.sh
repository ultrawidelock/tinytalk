#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../../.." && pwd)
port="$repo_root/ports/zephyr/thread/matter_thread_port.c"

need() {
	local pattern=$1
	if ! grep -Eq "$pattern" "$port"; then
		echo "missing SRP lifetime invariant: $pattern" >&2
		exit 1
	fi
}

reject() {
	local pattern=$1
	if grep -Eq "$pattern" "$port"; then
		echo "forbidden SRP lifetime pattern: $pattern" >&2
		exit 1
	fi
}

# OpenThread retains otSrpClientService and every buffer it points at until
# the removal callback returns the object. Desired names therefore live in a
# separate bank, and ACTIVE -> REMOVING -> FREE is callback-driven.
need 'struct srp_wanted_reg'
need 'SRP_SLOT_REMOVING'
need 'SRP_COMM_REMOVING'
need 'srp_release_removed_locked\(removed\)'
need 'host->mState == OT_SRP_CLIENT_ITEM_STATE_REMOVED'
need 'SRP reset complete; reconciling queued registrations'
need 'if \(s_host_name_ready\)'
need 'if \(srp_free_find\(\) == NULL\)'
reject 'ARG_UNUSED\(removed\)'

# The regression caught on hardware was an asynchronous host removal followed
# immediately by memset(s_regs). Limit this check to the reset function so a
# callback-owned clear elsewhere remains legal.
reset_body=$(sed -n '/^void matter_thread_advertise_reset(void)/,/^static void srp_host_name_build/p' "$port")
if grep -q 'memset(s_regs' <<<"$reset_body"; then
	echo "SRP reset still clears OpenThread-owned registrations synchronously" >&2
	exit 1
fi
if ! grep -q 's_regs\[i\]\.state = SRP_SLOT_REMOVING' <<<"$reset_body"; then
	echo "SRP reset does not retire active registrations" >&2
	exit 1
fi

# Individual removals obey the same lifetime. They may clear immediately only
# when OpenThread says NOT_FOUND and therefore retained no pointer.
need 'reg->state = SRP_SLOT_REMOVING'
need 'err == OT_ERROR_NOT_FOUND'
reject 'slot released anyway'

echo "Matter SRP lifecycle checks passed"
