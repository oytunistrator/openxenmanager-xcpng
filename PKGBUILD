# Maintainer: OpenXenManager Contributors <https://github.com/OpenXenManager/openxenmanager>
# Contributor: Daniel Lintott <daniel@serverb.co.uk>

pkgname=openxenmanager
_pkgname=OpenXenManager
pkgver=0.1.0.dev1
pkgrel=1
pkgdesc='Open source management GUI for XenServer / XCP-NG (GTK3 migration)'
arch=('any')
url='https://github.com/OpenXenManager/openxenmanager'
license=('GPL2')
depends=(
    'python-gobject'      # PyGObject / gi.repository.Gtk
    'gtk3'                # GTK3 runtime
    'python-configobj'    # ConfigObj for oxc.conf parsing
    'python-raven'        # Sentry crash reporting (optional, harmless if missing)
    'gtk-vnc'             # VNC console support (provides GtkVnc 2.0 GI binding)
)
optdepends=(
    'gtkvnc-python': 'VNC console support for VM viewing'
)
makedepends=('python-setuptools')
install="${pkgname}.install"
source=(
    "${pkgver}.tar.gz::https://github.com/OpenXenManager/openxenmanager/archive/refs/tags/${pkgver}.tar.gz"
    "${pkgname}.desktop"
    "${pkgname}.png"
)
sha256sums=('SKIP'
            'SKIP'   # desktop file hash -- replace after adding real content
            'SKIP')  # icon hash

package() {
    # Install the main application script
    install -Dm755 "${srcdir}/${pkgname}" \
        "${pkgdir}/usr/bin/${pkgname}"

    # Install Python packages (src/OXM and src/pygtk_chart)
    cp -r "${srcdir}/src/OXM" "${pkgdir}/usr/lib/python3.14/site-packages/OXM"
    cp -r "${srcdir}/src/pygtk_chart" \
        "${pkgdir}/usr/lib/python3.14/site-packages/pygtk_chart"

    # Install desktop file
    install -Dm644 "${srcdir}/${pkgname}.desktop" \
        "${pkgdir}/usr/share/applications/${pkgname}.desktop"

    # Install icon (256x256)
    install -Dm644 "${srcdir}/${pkgname}.png" \
        "${pkgdir}/usr/share/icons/hicolor/256x256/apps/${pkgname}.png"

    # Also create a symlink for 16x16 (standard XenCenter icon size)
    install -d "${pkgdir}/usr/share/icons/hicolor/16x16/apps"
    ln -sf "../../256x256/apps/${pkgname}.png" \
        "${pkgdir}/usr/share/icons/hicolor/16x16/apps/${pkgname}.png"

    # Install documentation
    install -Dm644 "${srcdir}/README.md" \
        "${pkgdir}/usr/share/doc/${pkgname}/README.md"
    install -Dm644 "${srcdir}/LICENSE" \
        "${pkgdir}/usr/share/licenses/${pkgname}/LICENSE"
}

# -- Desktop file content (to be placed in the repo root) -------------------
# [Desktop Entry]
# Name=OpenXenManager
# Comment=XCP-NG / XenServer management GUI
# Exec=openxenmanager
# Icon=openxenmanager
# Terminal=false
# Type=Application
# Categories=System;Monitor;

# -- Icon source -------------------------------------------------------------
# Use: desktop_and_icons/icons/hicolor/256x256/apps/openxenmanager.png
# or generate from existing images/add_server.png (square icon)
# ---------------------------------------------------------------------------
