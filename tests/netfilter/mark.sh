#!/bin/bash
#
# SPDX-FileCopyrightText: (c) 2026 Ring Zero Desenvolvimento de Software LTDA
# SPDX-License-Identifier: MIT OR GPL-2.0-only
#
# Tests the mark filter in nf.register:
#   mark=0 hook fires for normal (unmarked) packets.
#   mark=1 hook is skipped for normal packets (skb->mark != 1).
#
# Usage: sudo bash tests/netfilter/mark.sh

SCRIPT="tests/netfilter/mark"
PORT_ZERO=5560
PORT_ONE=5561
TIMEOUT=1

source "$(dirname "$(readlink -f "$0")")/../lib.sh"

cleanup() {
	kill "$PID0" "$PID1" 2>/dev/null
	rm -f /tmp/mark_recv0 /tmp/mark_recv1
}

recv() {
	local port=$1 out=$2
	nc -lu -w$TIMEOUT "$port" > "$out" 2>/dev/null &
	echo $!
}

send() { echo -n "ping" | nc -u -w$TIMEOUT 127.0.0.1 "$1"; }

ktap_header
ktap_plan 4

lunatik run "$SCRIPT" false
mark_dmesg

# mark=0 hook: drops packets to PORT_ZERO (normal packets have mark=0)
PID0=$(recv $PORT_ZERO /tmp/mark_recv0)
send $PORT_ZERO
wait $PID0 2>/dev/null
check_dmesg || exit 1
[ -s /tmp/mark_recv0 ] && fail "mark=0 hook did not drop packet to port $PORT_ZERO"
ktap_pass "mark=0 hook drops unmarked packet"

# mark=1 hook: skipped for normal packets (mark mismatch), packet delivered
PID1=$(recv $PORT_ONE /tmp/mark_recv1)
send $PORT_ONE
wait $PID1 2>/dev/null
check_dmesg || exit 1
[ "$(cat /tmp/mark_recv1)" = "ping" ] || fail "mark=1 hook incorrectly dropped unmarked packet to port $PORT_ONE"
ktap_pass "mark=1 hook skipped for unmarked packet"

lunatik stop "$SCRIPT"

# After unload: both ports deliver
PID0=$(recv $PORT_ZERO /tmp/mark_recv0)
send $PORT_ZERO
wait $PID0 2>/dev/null
[ "$(cat /tmp/mark_recv0)" = "ping" ] || fail "packet not delivered to port $PORT_ZERO after unload"
ktap_pass "packet delivered to port $PORT_ZERO after unload"

PID1=$(recv $PORT_ONE /tmp/mark_recv1)
send $PORT_ONE
wait $PID1 2>/dev/null
[ "$(cat /tmp/mark_recv1)" = "ping" ] || fail "packet not delivered to port $PORT_ONE after unload"
ktap_pass "packet delivered to port $PORT_ONE after unload"

cleanup
ktap_totals

