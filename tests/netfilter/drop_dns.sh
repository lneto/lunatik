#!/bin/bash
#
# SPDX-FileCopyrightText: (c) 2026 Ring Zero Desenvolvimento de Software LTDA
# SPDX-License-Identifier: MIT OR GPL-2.0-only
#
# Tests netfilter DNS drop hook: loads the kernel script, verifies DNS is
# blocked, then unloads and verifies DNS resolves again.
#
# Usage: sudo bash tests/netfilter/drop_dns.sh

set -e

SCRIPT="tests/netfilter/drop_dns"
DNS_HOST="github.com"
DNS_SERVER="8.8.8.8"

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; lunatik stop "$SCRIPT" 2>/dev/null; exit 1; }

# Baseline: DNS must work before the test
host -W 2 "$DNS_HOST" "$DNS_SERVER" > /dev/null 2>&1 || fail "baseline DNS not working — check connectivity"

lunatik run "$SCRIPT" false

# DNS should be blocked
host -W 2 "$DNS_HOST" "$DNS_SERVER" > /dev/null 2>&1 \
	&& fail "DNS query succeeded — hook did not block" \
	|| pass "DNS blocked"

lunatik stop "$SCRIPT"

# DNS should work again after unload
host -W 2 "$DNS_HOST" "$DNS_SERVER" > /dev/null 2>&1 \
	&& pass "DNS allowed after unload" \
	|| fail "DNS still failing after unload"

