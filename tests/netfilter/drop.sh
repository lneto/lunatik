#!/bin/bash
#
# SPDX-FileCopyrightText: (c) 2026 Ring Zero Desenvolvimento de Software LTDA
# SPDX-License-Identifier: MIT OR GPL-2.0-only
#
# Tests DROP verdict on LOCAL_OUT: hook drops UDP to port 5555.
# Verifies packet is not delivered with hook loaded, and is delivered after unload.
#
# Usage: sudo bash tests/netfilter/drop.sh

SCRIPT="tests/netfilter/drop"
PORT=5555
TIMEOUT=1

source "$(dirname "$(readlink -f "$0")")/../lib.sh"

cleanup() { kill "$LISTENER_PID" 2>/dev/null; }

ktap_header
ktap_plan 3

nc -lu -w$TIMEOUT $PORT > /tmp/drop_recv 2>/dev/null &
LISTENER_PID=$!

# Baseline: packet is delivered
echo -n "ping" | nc -u -w$TIMEOUT 127.0.0.1 $PORT
wait $LISTENER_PID 2>/dev/null
[ "$(cat /tmp/drop_recv)" = "ping" ] || fail "baseline: packet not delivered"
ktap_pass "baseline: packet delivered"

lunatik run "$SCRIPT" false
mark_dmesg

nc -lu -w$TIMEOUT $PORT > /tmp/drop_recv 2>/dev/null &
LISTENER_PID=$!
echo -n "ping" | nc -u -w$TIMEOUT 127.0.0.1 $PORT
wait $LISTENER_PID 2>/dev/null
check_dmesg || exit 1
[ -s /tmp/drop_recv ] && fail "packet delivered — hook did not drop"
ktap_pass "packet dropped by hook"

lunatik stop "$SCRIPT"

nc -lu -w$TIMEOUT $PORT > /tmp/drop_recv 2>/dev/null &
LISTENER_PID=$!
echo -n "ping" | nc -u -w$TIMEOUT 127.0.0.1 $PORT
wait $LISTENER_PID 2>/dev/null
[ "$(cat /tmp/drop_recv)" = "ping" ] || fail "packet not delivered after unload"
ktap_pass "packet delivered after unload"

rm -f /tmp/drop_recv
ktap_totals

