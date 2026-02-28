#!/bin/bash
# SPDX-FileCopyrightText: (c) 2026 Ring Zero Desenvolvimento de Software LTDA
# SPDX-License-Identifier: MIT OR GPL-2.0-only
#
# lighten.sh — generate light.lua from a secret
#
# Usage: lighten.sh <secret_hex>
#
# Generates:
#   light.lua — kernel Lua script that returns the derived key

source "$(dirname "$0")/util.sh"

[ $# -eq 1 ] || die "usage: lighten.sh <secret_hex>"

SECRET_HEX="$1"
[ ${#SECRET_HEX} -eq 64 ] || die "secret must be 64 hex characters (32 bytes)"

KEY_HEX=$(hkdf_sha256 "$SECRET_HEX")

cat > light.lua <<EOF
return "${KEY_HEX}"
EOF

