#!/usr/bin/env bash
# Build dist/potomac-mfa.zip with a top-level potomac-mfa/ folder and no development files.
set -euo pipefail
cd "$(dirname "$0")/.."
SLUG=potomac-mfa
VERSION=$(grep -m1 -E '^\s*\*\s*Version:' "$SLUG.php" | awk '{print $NF}')
CONST=$(grep -m1 "define( 'PMFA_VERSION'" "$SLUG.php" | sed -E "s/.*'([0-9][^']*)'.*/\1/")
README=$(grep -m1 '^Stable tag:' readme.txt | awk '{print $NF}')
if [[ "$VERSION" != "$CONST" || "$VERSION" != "$README" ]]; then
	echo "Version mismatch: header=$VERSION constant=$CONST readme=$README" >&2
	exit 1
fi
rm -rf build dist && mkdir -p "build/$SLUG" dist
rsync -a --exclude-from=.distignore ./ "build/$SLUG/"
(cd build && zip -qr "../dist/$SLUG.zip" "$SLUG")
echo "Built dist/$SLUG.zip (version $VERSION)"
