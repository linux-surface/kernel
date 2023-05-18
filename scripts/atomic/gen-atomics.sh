#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# Generate atomic headers

T="`mktemp -d ${TMPDIR-/tmp}/gen-atomics.sh.XXXXXX`"
trap 'rm -rf $T' 0
export T

ATOMICDIR=$(dirname $0)
ATOMICTBL=${ATOMICDIR}/atomics.tbl
LINUXDIR=${ATOMICDIR}/../..

cat <<EOF |
gen-atomic-instrumented.sh      linux/atomic/atomic-instrumented.h
gen-atomic-long.sh              linux/atomic/atomic-long.h
gen-atomic-fallback.sh          linux/atomic/atomic-arch-fallback.h
EOF
while read script header args; do
	/bin/sh ${ATOMICDIR}/${script} ${ATOMICTBL} ${args} > ${LINUXDIR}/include/${header}
	HASH="$(sha1sum ${LINUXDIR}/include/${header})"
	HASH="${HASH%% *}"
	printf "// %s\n" "${HASH}" >> ${LINUXDIR}/include/${header}
done
