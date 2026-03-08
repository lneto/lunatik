#!/bin/bash
#
# SPDX-FileCopyrightText: (c) 2026 Ring Zero Desenvolvimento de Software LTDA
# SPDX-License-Identifier: MIT OR GPL-2.0-only
#
# Regression test for lunatik spawn and graceful thread termination.
# Verifies that a spawned kthread starts, appears in the list, and
# stops cleanly without kernel errors.
#
# Usage: sudo bash tests/thread/spawn.sh

SCRIPT="tests/thread/spawn"

source "$(dirname "$(readlink -f "$0")")/../lib.sh"

cleanup() { lunatik stop "$SCRIPT" 2>/dev/null; }

ktap_header
ktap_plan 3

mark_dmesg

lunatik spawn "$SCRIPT"
lunatik list | grep -qF "$SCRIPT" || fail "script not listed after spawn"
ktap_pass "script running after spawn"

lunatik stop "$SCRIPT"
check_dmesg || exit 1
lunatik list | grep -qF "$SCRIPT" && fail "script still listed after stop"
ktap_pass "script stopped cleanly"

# No kernel errors or warnings related to thread termination
errs=$(dmesg | tail -n +$((DMESG_LINE+1)) | grep -E "(BUG|WARNING|scheduling while atomic)" || true)
[ -n "$errs" ] && fail "kernel error during spawn/stop: $errs"
ktap_pass "no kernel errors"

ktap_totals

