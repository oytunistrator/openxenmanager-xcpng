#!/bin/bash
# build-openxenmanager.sh
# Arch Linux package build script for openxenmanager
# Use: ./build-openxenmanager.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== OpenXenManager Arch Linux Package Build ==="
echo "Repository: $REPO_DIR"
echo ""

# Navigate to repository
cd "$REPO_DIR"

# Step 1: Create tarball from git HEAD
echo "[1/4] Creating source tarball..."
PACKAGE_VERSION="0.1.0.dev1-1"
TARBALL_NAME="openxenmanager-${PACKAGE_VERSION}.tar.gz"

if [ -f "$TARBALL_NAME" ]; then
    rm "$TARBALL_NAME"
fi

# Create tarball from git archive (without .git directory)
git archive HEAD | gzip > "$TARBALL_NAME"
echo "   ✓ Created $TARBALL_NAME ($(du -h "$TARBALL_NAME" | cut -f1))"

# Step 2: Compute SHA256 checksums
echo ""
echo "[2/4] Computing SHA256 checksums..."
TARBALL_HASH=$(sha256sum "$TARBALL_NAME" | awk '{print $1}')
DESKTOP_HASH=$(sha256sum openxenmanager.desktop | awk '{print $1}')
ICON_HASH=$(sha256sum openxenmanager.png | awk '{print $1}')

echo "   TARBALL: $TARBALL_HASH"
echo "   DESKTOP: $DESKTOP_HASH"
echo "   ICON:    $ICON_HASH"

# Step 3: Update PKGBUILD with checksums
echo ""
echo "[3/4] Updating PKGBUILD..."
sed -i "s|sha256sums=(.*SKIP.*)|(sha256sums=(\n        '$TARBALL_HASH'\n        '$DESKTOP_HASH'\n        '$ICON_HASH'\n    ))|" PKGBUILD 2>/dev/null || true

# Better approach: replace the entire sha256sums section
if grep -q "SKIP" PKGBUILD; then
    cat > /tmp/pkgbuild_fix.sed << 'SEDSCRIPT'
/sha256sums=/,/)/ {
    s|sha256sums=(.*|sha256sums=(|
    /SKIP/d
}
) {
    a\        '"$TARBALL_HASH"'
    a\        '"$DESKTOP_HASH"'
    a\        '"$ICON_HASH"'
}
SEDSCRIPT

    sed -i -f /tmp/pkgbuild_fix.sed PKGBUILD
    rm -f /tmp/pkgbuild_fix.sed
fi

# Step 4: Verify files
echo ""
echo "[4/4] Verifying package structure..."
if [ ! -f "openxenmanager" ]; then
    echo "   ✗ ERROR: openxenmanager script not found!"
    exit 1
fi
if [ ! -d "src/OXM" ]; then
    echo "   ✗ ERROR: src/OXM directory not found!"
    exit 1
fi

echo "   ✓ All required files present"
echo ""
echo "=== Build Complete ==="
echo ""
echo "To install the package, run:"
echo "  cd $REPO_DIR"
echo "  makepkg -C -S -i"
echo ""
echo "Or just build without installing:"
echo "  cd $REPO_DIR"
echo "  makepkg -C -S"
echo ""

# Cleanup temp files if exists
[ -f /tmp/pkgbuild_fix.sed ] && rm -f /tmp/pkgbuild_fix.sed
