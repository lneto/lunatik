#!/bin/bash
#
# SPDX-FileCopyrightText: (c) 2026 Ring Zero Desenvolvimento de Software LTDA
# SPDX-License-Identifier: MIT OR GPL-2.0-only
#
# Runs all netfilter tests and reports aggregated KTAP results.
#
# Usage: sudo bash tests/netfilter/run.sh

DIR="$(dirname "$(readlink -f "$0")")"
FAILED=0

for t in "$DIR"/drop.sh "$DIR"/rst.sh "$DIR"/prerouting.sh "$DIR"/mark.sh; do
	echo "# --- $(basename "$t") ---"
	bash "$t" || FAILED=$((FAILED+1))
done

exit $FAILED

