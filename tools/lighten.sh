#!/bin/bash
# SPDX-FileCopyrightText: (c) 2026 Ring Zero Desenvolvimento de Software LTDA
# SPDX-License-Identifier: MIT OR GPL-2.0-only
#
# lighten.sh — generate light.lua from a secret
#
# Usage: lighten.sh [-t] <secret_hex>
#   -t  use time-step salt for ephemeral key derivation (OTP)
#
# Generates:
#   light.lua — kernel Lua script that returns the derived key

source "$(dirname "$0")/util.sh"

OTP=false
while getopts "t" opt; do
	case $opt in t) OTP=true ;; esac
done
shift $((OPTIND - 1))

[ $# -ge 1 ] || die "usage: lighten.sh [-t] <secret_hex>"

SECRET_HEX="$1"
[ ${#SECRET_HEX} -eq 64 ] || die "secret must be 64 hex characters (32 bytes)"

if $OTP; then
	SALT_HEX=$(printf '%016x' "$(( $(date +%s) / 30 ))")
	KEY_HEX=$(hkdf_sha256 "$SECRET_HEX" "$SALT_HEX")
else
	KEY_HEX=$(hkdf_sha256 "$SECRET_HEX")
fi

cat > light.lua <<EOF
return "${KEY_HEX}"
EOF

