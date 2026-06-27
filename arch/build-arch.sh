#!/bin/bash
# Arch Linux Build Script for OpenXenManager-XCPNG
# This script creates a proper Arch package from local repository

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT_DIR="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_header() {
    echo -e "\n${GREEN}=== $1 ===${NC}\n"
}

print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

print_info() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Navigate to arch directory
cd "$SCRIPT_DIR"

print_header "OpenXenManager-XCPNG Arch Linux Package Build"

# Check dependencies
for cmd in makepkg; do
    if ! command -v "$cmd" &> /dev/null; then
        print_error "$cmd not found. Install pacman and base-devel."
        exit 1
    fi
done

print_status "Detected required tools: $(command -v makepkg)"

# Version info
PKGVER="0.1.0.dev1"
PKGREL="1"
VERSION_STRING="${PKGVER}-${PKGREL}"
TARBALL_NAME="openxenmanager-${VERSION_STRING}.tar.gz"

# Step 1: Create source archive from local repository
print_status "Creating source archive..."

if [ -d "$PARENT_DIR/.git" ]; then
    # Use git archive for clean build without .git directory
    print_info "Building from git repository..."

    cd "$PARENT_DIR"
    git archive --prefix="openxenmanager/" HEAD | gzip > "$SCRIPT_DIR/$TARBALL_NAME"
    cd "$SCRIPT_DIR"

    TARBALL_SIZE=$(du -h "$TARBALL_NAME" | cut -f1)
    print_status "Created tarball: $TARBALL_NAME ($TARBALL_SIZE)"
else
    # Fallback to manual tar creation
    print_info "No git repository found. Creating archive from files..."

    cd "$PARENT_DIR"
    tar czf "$SCRIPT_DIR/$TARBALL_NAME" \
        --exclude='.git' \
        --exclude='*.pyc' \
        --exclude='__pycache__' \
        --exclude='venv' \
        --exclude='.pytest_cache' \
        --exclude='openxenmanager.log' \
        --exclude='*.egg-info' \
        --exclude='node_modules' \
        --exclude='dist' \
        --exclude='build' \
        . 2>/dev/null

    # Rename if needed
    mv openxenmanager-*.tar.gz "$SCRIPT_DIR/$TARBALL_NAME" 2>/dev/null || true

    cd "$SCRIPT_DIR"
fi

# Step 2: Verify tarball contents
print_status "Verifying source archive structure..."

if tar tzf "$TARBALL_NAME" | grep -q "src/OXM"; then
    print_status "✓ Source tree contains src/OXM (valid)"
else
    print_error "✗ Source tree missing src/OXM. Archive may be invalid!"
    exit 1
fi

# Step 3: Update PKGBUILD with local source reference
print_status "Configuring PKGBUILD for local build..."

# Backup original PKGBUILD if exists
if [ -f "PKGBUILD.orig" ]; then
    cp "PKGBUILD.orig" PKGBUILD.bak 2>/dev/null || true
fi

# Update source array in PKGBUILD to use local file
sed -i "s|# source=(\"${pkgname}-${pkgver}-1.tar.gz\")|source=(\"${TARBALL_NAME}\")|" PKGBUILD 2>/dev/null || {
    # Manual update if sed failed
    print_info "Manually updating PKGBUILD..."
    cat > PKGBUILD.new << 'PKGBUILD_EOF'
# Maintainer: oytunistrator <https://github.com/oytunistrator/openxenmanager-xcpng>

pkgname=openxenmanager-xcpng
pkgver=0.1.0.dev1
pkgrel=1
pkgdesc='Open source management GUI for XenServer / XCP-NG (GTK3 migration)'
arch=('any')
url='https://github.com/oytunistrator/openxenmanager-xcpng'
license=('GPL2')

depends=(
    'python-gobject'
    'gtk3'
    'python-configobj'
    'gtk-vnc'
)

makedepends=(
    'git'
    'python-setuptools'
)

optdepends=(
    'gtkvnc-python: VNC console support for VM viewing'
)

install="openxenmanager.install"

source=(
    "openxenmanager-0.1.0.dev1-1.tar.gz"
)

sha256sums=(
    'SKIP'
    'SKIP'
    'SKIP'
)

pkgver() {
    cd "$srcdir/openxenmanager" 2>/dev/null && {
        local short_hash=$(git rev-parse --short HEAD 2>/dev/null || echo "local")
        local count=$(git rev-list --count HEAD 2>/dev/null || echo "0")
        printf '%s.%s.%s' "$pkgver" "$count" "g${short_hash}"
        return
    }
    printf '%s' "$pkgver"
}

prepare() {
    local SRCDIR="$srcdir/openxenmanager"
    if [ ! -d "${SRCDIR}/src/OXM" ]; then
        echo "ERROR: Source tree invalid."
        exit 1
    fi
}

package() {
    local SRC_OPENXEN="$srcdir/openxenmanager"

    install -Dm755 "${SRC_OPENXEN}/openxenmanager" \
        "${pkgdir}/usr/bin/openxenmanager"

    cp -r "${SRC_OPENXEN}/src/OXM" "${pkgdir}/usr/lib/python3.14/site-packages/"
    cp -r "${SRC_OPENXEN}/src/pygtk_chart" "${pkgdir}/usr/lib/python3.14/site-packages/"

    install -Dm644 "files/openxenmanager.desktop" \
        "${pkgdir}/usr/share/applications/openxenmanager.desktop"

    if [ -f "files/openxenmanager.png" ]; then
        install -Dm644 "files/openxenmanager.png" \
            "${pkgdir}/usr/share/icons/hicolor/256x256/apps/openxenmanager.png"
        install -d "${pkgdir}/usr/share/icons/hicolor/16x16/apps"
        ln -sf "../../256x256/apps/openxenmanager.png" \
            "${pkgdir}/usr/share/icons/hicolor/16x16/apps/openxenmanager.png"
    fi

    [ -f "${SRC_OPENXEN}/README.md" ] && \
        install -Dm644 "${SRC_OPENXEN}/README.md" \
        "${pkgdir}/usr/share/doc/${pkgname}/README.md"

    [ -f "${SRC_OPENXEN}/LICENSE" ] && \
        install -Dm644 "${SRC_OPENXEN}/LICENSE" \
        "${pkgdir}/usr/share/licenses/${pkgname}/LICENSE"

    install -Dm755 "openxenmanager.install" \
        "${pkgdir}/usr/share/${pkgname}/${pkgname}.install"
}
PKGBUILD_EOF

    if [ -f PKGBUILD.new ]; then
        mv PKGBUILD.new PKGBUILD
        rm -f PKGBUILD.orig PKGBUILD.bak
    fi
}

# Step 4: Build the package
print_header "Building Package"

echo ""
echo "Build options:"
echo "  makepkg           # Build only (no install)"
echo "  makepkg -i        # Build and install"
echo "  ./build-arch.sh   # Run this script with defaults"
echo ""

# Actually build now
if [ "${1:-}" = "-i" ] || [ "${1:-}" = "--install" ]; then
    print_status "Building and installing package..."
    makepkg -C -S -i --noconfirm
else
    print_status "Building package..."
    makepkg -C -S --noconfirm
fi

if [ $? -eq 0 ]; then
    BUILT_PKG=$(ls openxenmanager-*-1-*.pkg.tar.xz 2>/dev/null | head -1)

    if [ -n "$BUILT_PKG" ]; then
        echo ""
        print_header "Build Complete!"
        print_status "Package: $(basename $BUILT_PKG)"
        print_status "Size: $(du -h "$BUILT_PKG" | cut -f1)"

        echo ""
        echo "${CYAN}Installation:${NC}"
        echo "  sudo pacman -U $(basename $BUILT_PKG)"
        echo ""
        echo "Or copy to /var/cache/pacman/pkg/ and install via GUI package manager"
        echo ""
    else
        print_error "Package file not found after build!"
        exit 1
    fi
else
    print_error "Build failed. Check output above."
    exit 1
fi
