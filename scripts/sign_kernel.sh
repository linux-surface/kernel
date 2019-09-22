#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

# The path to the compiled kernel image is passed as the first argument
BUILDDIR=$(dirname $(dirname $0))
VMLINUX=$1

# Keys are stored in a toplevel directory called keys
# The following files need to be there:
#     * MOK.priv  (private key)
#     * MOK.pem   (public key)
#
# If the files don't exist, this script will do nothing.
if [ ! -f "$BUILDDIR/keys/MOK.key" ]; then
    exit 0
fi
if [ ! -f "$BUILDDIR/keys/MOK.crt" ]; then
    exit 0
fi

# Both required certificates were found. Check if sbsign is installed.
echo "Keys for automatic secureboot signing found."
if [ ! -x "$(command -v sbsign)" ]; then
    echo "ERROR: sbsign not found!"
    exit -2
fi

# Sign the kernel
sbsign --key $BUILDDIR/keys/MOK.key --cert $BUILDDIR/keys/MOK.crt \
    --output $VMLINUX $VMLINUX
