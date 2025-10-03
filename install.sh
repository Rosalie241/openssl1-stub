#!/usr/bin/env bash
set -e

exe="$1"

if [[ "x$exe" = "x" ]] || [[ ! -f "$exe" ]]
then
	echo "Usage: $0 path/to/exe"
	exit 1
fi

if [[ ! -f "libcrypto.so.1.0.0" ]] || [[ ! -f "libssl.so.1.0.0" ]]
then
	echo "Build libraries first!"
	exit 1
fi

path="$(dirname "$exe")"

echo "-> Copying libraries"

cp libcrypto.so.1.0.0 "$path/libcrypto.so.1.0.0"
cp libssl.so.1.0.0 "$path/libssl.so.1.0.0"

echo "-> Patching rpatch in executable"
patchelf --set-rpath '$ORIGIN' "$exe"

