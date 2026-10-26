#!/usr/bin/env bash
# Build the source zip that is attached to a release.
#
# The archive is intentionally source-only: no build directories, no virtual
# environments, no local output. Documentation images and sample fixtures are
# included so a fresh checkout can reproduce the screenshots and the tests.
# Everything sits under scour-<version>/ so unzipping into Downloads does not
# scatter a hundred files across the folder.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

version="$(sed -n 's/^[[:space:]]*VERSION[[:space:]][[:space:]]*\([0-9][0-9.]*\).*/\1/p' CMakeLists.txt | head -1)"
if [ -z "$version" ]; then
    echo "cannot read the project version from CMakeLists.txt" >&2
    exit 1
fi

mkdir -p dist
archive="$root/dist/scour-${version}-source.zip"
rm -f "$archive"

staging="$(mktemp -d)"
trap 'rm -rf "$staging"' EXIT
package="$staging/scour-${version}"
mkdir -p "$package"

# Keep this list explicit. A new local directory should be added deliberately,
# not silently shipped because it happened to match a wildcard.
for entry in .github CMakeLists.txt LICENSE README.md SECURITY.md CONTRIBUTING.md \
    CHANGELOG.md bench docs fixtures fuzz include man src tests tools .gitignore; do
    cp -a "$entry" "$package/"
done

rm -rf "$package"/docs/assets/__pycache__ "$package"/tools/__pycache__
find "$package" -name '__pycache__' -type d -prune -exec rm -rf {} +
find "$package" -name '*.pyc' -delete

(cd "$staging" && zip -q -X -r "$archive" "scour-${version}")

echo "wrote dist/scour-${version}-source.zip ($(du -h "$archive" | cut -f1))"
unzip -t "$archive" >/dev/null
echo "archive integrity: ok"
