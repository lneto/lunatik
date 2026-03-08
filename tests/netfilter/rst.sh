#!/bin/bash
#
# SPDX-FileCopyrightText: (c) 2026 Ring Zero Desenvolvimento de Software LTDA
# SPDX-License-Identifier: MIT OR GPL-2.0-only
#
# Tests LOCAL_IN hook that injects a TCP RST via skb:forward and skb:resize.
# Verifies curl gets connection reset (exit 7) with hook loaded.
#
# Usage: sudo bash tests/netfilter/rst.sh

SCRIPT="tests/netfilter/rst"
PORT=7777
TIMEOUT=2

source "$(dirname "$(readlink -f "$0")")/../lib.sh"

RESPONSE=$(mktemp)
printf "HTTP/1.1 200 OK\r\n\r\n" > "$RESPONSE"

cleanup() { kill "$SERVER_PID" 2>/dev/null; rm -f "$RESPONSE"; }

ktap_header
ktap_plan 3

while nc -l -N -p $PORT < "$RESPONSE" > /dev/null 2>&1; do :; done &
SERVER_PID=$!

# Baseline: connection succeeds
curl -s -o /dev/null --max-time $TIMEOUT http://127.0.0.1:$PORT
EXIT=$?
[ "$EXIT" -eq 7 ]  && fail "baseline: connection rejected with RST"
[ "$EXIT" -eq 28 ] && fail "baseline: connection timed out"
ktap_pass "baseline: connection OK"

lunatik run "$SCRIPT" false
mark_dmesg

# curl exits 7 (COULDNT_CONNECT) on RST, 28 (OPERATION_TIMEDOUT) on drop
curl -s -o /dev/null --max-time $TIMEOUT http://127.0.0.1:$PORT
EXIT=$?
check_dmesg || exit 1
[ "$EXIT" -eq 7 ] || fail "expected RST (curl exit 7), got exit $EXIT"
ktap_pass "connection rejected with RST"

lunatik stop "$SCRIPT"

# Server still listening (SYN never reached it); connection should succeed again
curl -s -o /dev/null --max-time $TIMEOUT http://127.0.0.1:$PORT
EXIT=$?
[ "$EXIT" -eq 7 ]  && fail "connection rejected with RST after unload"
[ "$EXIT" -eq 28 ] && fail "connection timed out after unload"
ktap_pass "connection OK after unload"

cleanup
ktap_totals

