#!/bin/bash
#
# SPDX-FileCopyrightText: (c) 2026 Ring Zero Desenvolvimento de Software LTDA
# SPDX-License-Identifier: MIT OR GPL-2.0-only
#
# Tests PRE_ROUTING hook: drops ICMP Echo Requests on loopback.
# Verifies ping fails with hook loaded and succeeds after unload.
#
# Usage: sudo bash tests/netfilter/prerouting.sh

SCRIPT="tests/netfilter/prerouting"

source "$(dirname "$(readlink -f "$0")")/../lib.sh"

cleanup() { :; }

ktap_header
ktap_plan 3

# Baseline: ping works
ping -c1 -W1 127.0.0.1 > /dev/null 2>&1 || fail "baseline: ping failed"
ktap_pass "baseline: ping OK"

lunatik run "$SCRIPT" false
mark_dmesg

# ICMP Echo Request dropped at PRE_ROUTING: ping should fail
ping -c1 -W1 127.0.0.1 > /dev/null 2>&1 && fail "ping succeeded — hook did not drop"
check_dmesg || exit 1
ktap_pass "ping dropped by PRE_ROUTING hook"

lunatik stop "$SCRIPT"

# Ping should work again
ping -c1 -W1 127.0.0.1 > /dev/null 2>&1 || fail "ping failed after unload"
ktap_pass "ping OK after unload"

ktap_totals

