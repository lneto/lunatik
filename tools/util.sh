# SPDX-FileCopyrightText: (c) 2026 Ring Zero Desenvolvimento de Software LTDA
# SPDX-License-Identifier: MIT OR GPL-2.0-only
#
# util.sh — shared helpers for darken/lighten scripts

set -euo pipefail

die() { echo "error: $1" >&2; exit 1; }

# hex2bin: convert hex string on stdin to binary on stdout
hex2bin() { sed 's/../\\x&/g' | xargs -0 printf '%b'; }

# hkdf_sha256: derive a 32-byte key from a secret via HKDF-SHA256
# usage: KEY_HEX=$(hkdf_sha256 "$SECRET_HEX")
hkdf_sha256() {
	local secret_hex="$1"
	local salt_hex=$(printf '%064x' 0)
	local prk_hex=$(echo -n "$secret_hex" | hex2bin | openssl dgst -sha256 -mac HMAC \
		-macopt "hexkey:${salt_hex}" -hex 2>/dev/null | sed 's/.*= //')

	local info_hex=$(printf 'lunatik-darken' | xxd -p | tr -d '\n')
	echo -n "${info_hex}01" | hex2bin | openssl dgst -sha256 -mac HMAC \
		-macopt "hexkey:${prk_hex}" -hex 2>/dev/null | sed 's/.*= //'
}

