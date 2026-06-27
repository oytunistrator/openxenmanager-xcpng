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
    'python-gobject'
    'gtk3'
    'python-configobj'
    'gtk-vnc'
)

makedepends=(
    'python-setuptools'
)

install="${pkgname}.install"

source=(
    "${pkgver}.tar.gz::https://github.com/OpenXenManager/openxenmanager/archive/refs/tags/v${pkgver}.tar.gz"
    "openxenmanager.desktop"
    "openxenmanager.png"
)

sha256sums=(
    'SKIP'
    'SKIP'
    'SKIP'
)

package() {
    # Install the main application script
    install -Dm755 "${srcdir}/openxenmanager" \
        "${pkgdir}/usr/bin/openxenmanager"

    # Install Python packages (src/OXM and src/pygtk_chart)
    cp -r "${srcdir}/src/OXM" "${pkgdir}/usr/lib/python3.14/site-packages/OXM"
    cp -r "${srcdir}/src/pygtk_chart" \
        "${pkgdir}/usr/lib/python3.14/site-packages/pygtk_chart"

    # Install desktop file
    install -Dm644 "${srcdir}/openxenmanager.desktop" \
        "${pkgdir}/usr/share/applications/openxenmanager.desktop"

    # Install icon (256x256)
    install -Dm644 "${srcdir}/openxenmanager.png" \
        "${pkgdir}/usr/share/icons/hicolor/256x256/apps/openxenmanager.png"

    # Also create a symlink for 16x16 (standard XenCenter icon size)
    install -d "${pkgdir}/usr/share/icons/hicolor/16x16/apps"
    ln -sf "../../256x256/apps/openxenmanager.png" \
        "${pkgdir}/usr/share/icons/hicolor/16x16/apps/openxenmanager.png"

    # Install documentation
    install -Dm644 "${srcdir}/README.md" \
        "${pkgdir}/usr/share/doc/${pkgname}/README.md"
    install -Dm644 "${srcdir}/LICENSE" \
        "${pkgdir}/usr/share/licenses/${pkgname}/LICENSE"
}
