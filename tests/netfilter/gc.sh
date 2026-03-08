#!/bin/bash
#
# SPDX-FileCopyrightText: (c) 2026 Ring Zero Desenvolvimento de Software LTDA
# SPDX-License-Identifier: MIT OR GPL-2.0-only
#
# Regression test: GC must not run under spinlock in lunatik_monitor.
# A hook allocates Lua tables on every packet to build GC pressure.
# Sending many packets triggers many hook invocations; if GC finalizers
# run inside the spinlock, the kernel reports "scheduling while atomic".
#
# Usage: sudo bash tests/netfilter/gc.sh

SCRIPT="tests/netfilter/gc"
PORT=5570
PACKETS=200

source "$(dirname "$(readlink -f "$0")")/../lib.sh"

cleanup() { :; }

ktap_header
ktap_plan 1

lunatik run "$SCRIPT" false
mark_dmesg

for i in $(seq $PACKETS); do
	echo -n "x" | nc -u -w0 127.0.0.1 $PORT 2>/dev/null || true
done

check_dmesg || exit 1
sched=$(dmesg | tail -n +$((DMESG_LINE+1)) | grep "scheduling while atomic" || true)
[ -n "$sched" ] && fail "GC ran under spinlock: scheduling while atomic"
ktap_pass "GC did not run under spinlock after $PACKETS packets"

lunatik stop "$SCRIPT"
ktap_totals

