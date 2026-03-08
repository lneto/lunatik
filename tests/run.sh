#!/bin/bash
#
# SPDX-FileCopyrightText: (c) 2026 Ring Zero Desenvolvimento de Software LTDA
# SPDX-License-Identifier: MIT OR GPL-2.0-only
#
# Runs all lunatik test suites.
#
# Usage: sudo bash tests/run.sh

DIR="$(dirname "$(readlink -f "$0")")"
FAILED=0

bash "$DIR/netfilter/run.sh" || FAILED=$((FAILED+1))
bash "$DIR/thread/run.sh"   || FAILED=$((FAILED+1))

exit $FAILED

