#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# Check to see if the specified atomic is already in use.  This is
# done by keeping filenames in the temporary directory specified by the
# environment variable T.
#
# Usage:
#	chkdup.sh name fallback
#
# The "name" argument is the name of the function to be generated, and
# the "fallback" argument is the name of the fallback script that is
# doing the generation.
#
# If the function is a duplicate, output a comment saying so and
# exit with non-zero (error) status.  Otherwise exit successfully
#
# If the function is a duplicate, output a comment saying so and
# exit with non-zero (error) status.  Otherwise exit successfully.

if test -f ${T}/${1}
then
	echo // Fallback ${2} omitting duplicate "${1}()" kernel-doc header.
	exit 1
fi
touch ${T}/${1}
exit 0
