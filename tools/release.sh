#!/usr/bin/env bash
# Build and package the prebuilt binary for one target triple.
#
#   tools/release.sh linux-x86_64
#
# Produces dist/scour-<version>-<triple>.tar.gz and a .sha256 sidecar. The
# build is a plain Release build with warnings as errors, the test suite runs
# before anything is packaged, and the archive is finally unpacked and driven
# from its extracted form: what gets verified is the shipped artefact, not the
# build tree it came from.
#
# Linux binaries are linked statically in full, so there is no glibc floor and
# nothing to install: the tarball runs on any x86-64 or aarch64 Linux. macOS
# cannot link libSystem statically; those builds declare macOS 13 as their
# minimum instead.
set -euo pipefail

# Prints the leading comment block, so the help text cannot drift out of the
# header or be cut short when a line is added to it.
usage() {
    awk 'NR == 1 { next } /^#!/ { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' \
        "${BASH_SOURCE[0]}"
}

triple="${1:-}"
case "$triple" in
    linux-x86_64 | linux-aarch64 | macos-arm64 | macos-x86_64) ;;
    "" | -h | --help)
        usage
        exit 0
        ;;
    *)
        echo "release.sh: unknown target '$triple'" >&2
        echo "expected one of: linux-x86_64 linux-aarch64 macos-arm64 macos-x86_64" >&2
        exit 2
        ;;
esac

die() {
    echo "release.sh: $*" >&2
    exit 1
}

# Every target is built natively: the runner in the release matrix is the same
# architecture as the artefact it produces. Building linux-x86_64 on a Mac, or
# macos-arm64 on Linux, would silently produce a binary named for the wrong
# platform, so refuse instead.
host_os="$(uname -s)"
host_arch="$(uname -m)"
case "$triple" in
    linux-x86_64)
        expect_os=Linux
        expect_archs="x86_64 amd64"
        ;;
    linux-aarch64)
        expect_os=Linux
        expect_archs="aarch64 arm64"
        ;;
    macos-arm64)
        expect_os=Darwin
        expect_archs="arm64 aarch64"
        ;;
    macos-x86_64)
        expect_os=Darwin
        expect_archs="x86_64 amd64"
        ;;
esac

[ "$host_os" = "$expect_os" ] ||
    die "$triple is a $expect_os target; this host is $host_os"
case " $expect_archs " in
    *" $host_arch "*) ;;
    *) die "$triple needs one of: $expect_archs; this host is $host_arch" ;;
esac

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

version="$(sed -n 's/^[[:space:]]*VERSION[[:space:]][[:space:]]*\([0-9][0-9.]*\).*/\1/p' CMakeLists.txt | head -1)"
if [ -z "$version" ]; then
    echo "cannot read the project version from CMakeLists.txt" >&2
    exit 1
fi

name="scour-${version}-${triple}"
build="$root/build-release/$triple"

# ---------------------------------------------------------------------------
# Configure and build
# ---------------------------------------------------------------------------
flags=(
    -S "$root"
    -B "$build"
    -DCMAKE_BUILD_TYPE=Release
    -DSCOUR_BUILD_TESTS=ON
    -DSCOUR_WARNINGS_AS_ERRORS=ON
    -DSCOUR_NATIVE=OFF
)

case "$triple" in
    linux-*)
        # Full static link: the only compatibility requirement left is the
        # kernel. -static-libstdc++ alone would still pin the build host's glibc.
        flags+=(-DCMAKE_EXE_LINKER_FLAGS=-static)
        ;;
    macos-*)
        # Runs on every Mac that can run a current Xcode toolchain's output.
        flags+=(-DCMAKE_OSX_DEPLOYMENT_TARGET=13.0)
        ;;
esac

echo "== $name =="
cmake "${flags[@]}"

jobs="${JOBS:-}"
if [ -n "$jobs" ]; then
    cmake --build "$build" --parallel "$jobs"
else
    cmake --build "$build" --parallel
fi

# ---------------------------------------------------------------------------
# Test before packaging
# ---------------------------------------------------------------------------
ctest --test-dir "$build" --output-on-failure

# ---------------------------------------------------------------------------
# Stage
# ---------------------------------------------------------------------------
staging="$(mktemp -d)"
check="$(mktemp -d)"
trap 'rm -rf "$staging" "$check"' EXIT

package="$staging/$name"
mkdir -p "$package/fixtures"

binary="$build/scour"
if [ ! -x "$binary" ]; then
    echo "missing $binary" >&2
    exit 1
fi
cp "$binary" "$package/scour"
cp man/scour.1 README.md LICENSE CHANGELOG.md "$package/"
cp fixtures/*.pdf "$package/fixtures/"

case "$triple" in
    linux-*)
        # Nothing links against this copy, so stripping is safe and removes the
        # symbol table a release does not need.
        strip --strip-unneeded "$package/scour"
        ;;
esac
chmod 0755 "$package/scour"

# ---------------------------------------------------------------------------
# Archive
# ---------------------------------------------------------------------------
mkdir -p dist
archive="$root/dist/$name.tar.gz"
rm -f "$archive" "$archive.sha256"

# COPYFILE_DISABLE stops macOS tar from adding ._ AppleDouble members. GNU tar
# can also normalise ownership, so the Linux archive does not record the build
# user; bsdtar spells that differently, and the uid it records is replaced by
# the extracting user anyway.
owner_flags=()
if tar --version 2>/dev/null | grep -q "GNU tar"; then
    owner_flags=(--owner=0 --group=0)
fi
# The +... form is the expansion that survives `set -u` with an empty array on
# the bash 3.2 that macOS still ships.
COPYFILE_DISABLE=1 tar ${owner_flags[@]+"${owner_flags[@]}"} -czf "$archive" -C "$staging" "$name"

if command -v sha256sum >/dev/null 2>&1; then
    (cd dist && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256")
else
    (cd dist && shasum -a 256 "$name.tar.gz" > "$name.tar.gz.sha256")
fi

# ---------------------------------------------------------------------------
# Verify the artefact as a user receives it
# ---------------------------------------------------------------------------
tar -xzf "$archive" -C "$check"
shipped="$check/$name"

if [ "$("$shipped/scour" --version)" != "scour $version" ]; then
    echo "shipped binary reports the wrong version" >&2
    exit 1
fi

case "$triple" in
    linux-*)
        linkage="$(ldd "$shipped/scour" 2>&1 || true)"
        case "$linkage" in
            *"not a dynamic executable"*) ;;
            *)
                echo "the shipped binary is not statically linked:" >&2
                echo "$linkage" >&2
                exit 1
                ;;
        esac
        ;;
esac

out="$check/clean.pdf"
"$shipped/scour" inspect "$shipped/fixtures/contract-leak.pdf" >"$check/inspect.txt" || test $? -eq 1
grep -q "SCOUR REPORT" "$check/inspect.txt"
"$shipped/scour" scrub "$shipped/fixtures/contract-leak.pdf" -o "$out" --pii >"$check/scrub.txt"
"$shipped/scour" verify "$out" --pii >"$check/verify.txt"
grep -q "CLEAN" "$check/verify.txt"
"$shipped/scour" inspect "$out" >/dev/null

members="$(tar -tzf "$archive" | wc -l | tr -d ' ')"
test -f "$shipped/scour.1"
test -f "$shipped/README.md"
test -f "$shipped/LICENSE"

digest="$(cut -d' ' -f1 "$archive.sha256")"
echo
echo "packaged  dist/$name.tar.gz"
echo "  version  $version"
echo "  size     $(du -h "$archive" | cut -f1)"
echo "  members  $members"
echo "  sha256   $digest"
echo "  verified extracted binary: --version, inspect, scrub --pii, verify --pii"
