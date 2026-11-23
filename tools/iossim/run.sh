#!/bin/sh
# Build a package's tests for the iOS simulator and run them there.
#
#   tools/iossim/run.sh ./endpoint -test.run TestPhoneMemory -test.v
#
# Needs Xcode. SIM names a simulator (default: the first available iPhone).
set -eu
pkg=${1:?usage: run.sh ./pkg [test flags...]}
shift
sdk=$(xcrun --sdk iphonesimulator --show-sdk-path)
cc="$(xcrun --sdk iphonesimulator -f clang) -isysroot $sdk -target arm64-apple-ios15.0-simulator"
out=$(mktemp -d)/$(basename "$pkg").test
GOOS=ios GOARCH=arm64 CGO_ENABLED=1 CC="$cc" go test -c -o "$out" "$pkg"
sim=${SIM:-$(xcrun simctl list devices available | sed -n 's/.*iPhone.*(\([0-9A-F-]\{36\}\)).*/\1/p' | head -1)}
xcrun simctl boot "$sim" 2>/dev/null || true
xcrun simctl bootstatus "$sim" -b >/dev/null
exec xcrun simctl spawn "$sim" "$out" "$@"
