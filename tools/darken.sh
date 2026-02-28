#!/bin/bash
# SPDX-FileCopyrightText: (c) 2026 Ring Zero Desenvolvimento de Software LTDA
# SPDX-License-Identifier: MIT OR GPL-2.0-only
#
# darken.sh — encrypt a Lua script for use with Lunatik darken
#
# Usage: darken.sh [-t] <script.lua>
#   -t  use time-step salt for ephemeral key derivation (OTP)
#
# Generates:
#   <script>.dark.lua  — encrypted loader script
#   Prints the 32-byte secret (hex) to stdout

source "$(dirname "$0")/util.sh"

OTP=false
while getopts "t" opt; do
	case $opt in t) OTP=true ;; esac
done
shift $((OPTIND - 1))

[ $# -eq 1 ] || die "usage: darken.sh [-t] <script.lua>"
[ -f "$1" ] || die "file not found: $1"

SCRIPT="$1"
BASENAME="${SCRIPT%.lua}"
DARK="${BASENAME}.dark.lua"

SECRET_HEX=$(openssl rand -hex 32)
IV_HEX=$(openssl rand -hex 16)

if $OTP; then
	SALT_HEX=$(printf '%016x' "$(( $(date +%s) / 30 ))")
	KEY_HEX=$(hkdf_sha256 "$SECRET_HEX" "$SALT_HEX")
else
	KEY_HEX=$(hkdf_sha256 "$SECRET_HEX")
fi

CT_HEX=$(openssl enc -aes-256-ctr -K "$KEY_HEX" -iv "$IV_HEX" -nosalt \
	-in "$SCRIPT" | xxd -p | tr -d '\n')

cat > "$DARK" <<EOF
local lighten = require("lighten")
return lighten.run("${CT_HEX}", "${IV_HEX}")
EOF

echo "$SECRET_HEX"

