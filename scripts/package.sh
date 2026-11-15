#!/usr/bin/env bash
# Pack one architecture's binary into the four shapes a release carries.
#
#   scripts/package.sh <binary> <arch> <outdir>
#
# `arch` is the Rust name, x86_64 or aarch64. The three package formats each
# spell it differently — Debian says amd64 and arm64, RPM and pacman say
# x86_64 and aarch64 — and the mapping lives here so no caller has to know it.
#
# What comes out, for version 0.3.0 on x86_64:
#
#   oko-0.3.0-linux-x86_64.tar.gz          what the updater downloads
#   oko_0.3.0_amd64.deb                    Debian, Ubuntu, Mint
#   oko-0.3.0-1.x86_64.rpm                 Fedora, openSUSE, RHEL
#   oko-0.3.0-1-x86_64.pkg.tar.zst         Arch, CachyOS, Manjaro
#
# Nothing here signs anything: the key never leaves the release machine, and
# release.sh does the signing after this script has produced the files.
#
# The tarball is the one the updater's contract in src/update.rs describes, so
# its name and its inner layout are not free to change.

set -euo pipefail

cd "$(dirname "$0")/.."
ROOT=$PWD

BIN=${1:?usage: package.sh <binary> <arch> <outdir>}
ARCH=${2:?usage: package.sh <binary> <arch> <outdir>}
OUT=${3:?usage: package.sh <binary> <arch> <outdir>}

[ -f "$BIN" ] || { echo "no such binary: $BIN" >&2; exit 1; }
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)

VERSION=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)
[ -n "$VERSION" ] || { echo "no version in Cargo.toml" >&2; exit 1; }

case "$ARCH" in
    x86_64)  DEBARCH=amd64 ; RPMARCH=x86_64  ; ARCHARCH=x86_64  ; ELF=x86-64      ;;
    aarch64) DEBARCH=arm64 ; RPMARCH=aarch64 ; ARCHARCH=aarch64 ; ELF='ARM aarch64' ;;
    *) echo "unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

# The binary has to be the architecture it is being packed as. Without this a
# wrong artifact packs cleanly and fails on the user's machine, which is the
# worst place to find out.
file "$BIN" | grep -q "$ELF" \
    || { echo "$BIN is not an $ARCH binary" >&2; exit 1; }

# The binary must agree with Cargo.toml, or the updater offers this release to
# itself forever. Only checkable when the binary can run here: an aarch64 build
# on an x86_64 host is packed, not executed.
if [ "$ARCH" = "$(uname -m)" ]; then
    BUILT=$("$BIN" --version | awk '{print $2}')
    [ "$BUILT" = "$VERSION" ] || { echo "the binary says $BUILT, Cargo.toml says $VERSION" >&2; exit 1; }
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

say() { printf '\033[1m%s\033[0m\n' "$*"; }

# The files every package carries, laid out the way a Linux system expects.
# One function, so the three formats cannot drift apart.
stage() {
    local root=$1
    install -Dm755 "$BIN" "$root/usr/bin/oko"
    install -Dm644 packaging/io.github.etherhaus.Oko.desktop \
        "$root/usr/share/applications/io.github.etherhaus.Oko.desktop"
    install -Dm644 packaging/io.github.etherhaus.Oko.metainfo.xml \
        "$root/usr/share/metainfo/io.github.etherhaus.Oko.metainfo.xml"
    local size
    for size in 16 32 48 64 128 256; do
        install -Dm644 "assets/oko-$size.png" \
            "$root/usr/share/icons/hicolor/${size}x${size}/apps/io.github.etherhaus.Oko.png"
    done
    install -Dm644 assets/oko.svg \
        "$root/usr/share/icons/hicolor/scalable/apps/io.github.etherhaus.Oko.svg"
    install -Dm644 README.md "$root/usr/share/doc/oko/README.md"
    install -Dm644 README.en.md "$root/usr/share/doc/oko/README.en.md"
    install -Dm644 LICENSE "$root/usr/share/doc/oko/LICENSE"
}

# ── the tarball the updater takes ────────────────────────────────────────────
NAME="oko-$VERSION-linux-$ARCH"
TARBALL="$OUT/$NAME.tar.gz"
rm -rf "$WORK/$NAME"
mkdir -p "$WORK/$NAME"
install -m755 "$BIN" "$WORK/$NAME/oko"
install -m644 README.md README.en.md LICENSE "$WORK/$NAME/"
cp -r packaging assets "$WORK/$NAME/"
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime='@0' \
    -C "$WORK" -czf "$TARBALL" "$NAME"
say "Packed $TARBALL"

# ── the deb ──────────────────────────────────────────────────────────────────
# Built with ar and tar rather than dpkg-deb: the format is three members in a
# fixed order, and this way the package can be cut on a machine that has no
# dpkg at all. `dpkg-deb -I` in CI is what proves dpkg agrees.
DEBROOT="$WORK/deb"
stage "$DEBROOT"
INSTALLED=$(du -sk "$DEBROOT/usr" | cut -f1)
mkdir -p "$DEBROOT/DEBIAN"
cat > "$DEBROOT/DEBIAN/control" <<EOF
Package: oko
Version: $VERSION
Architecture: $DEBARCH
Maintainer: Dmitry Etherhaus <lehzenblad@proton.me>
Installed-Size: $INSTALLED
Depends: libfontconfig1, libfreetype6, libpng16-16, libbrotli1, libbz2-1.0, libexpat1, zlib1g, libxkbcommon0, libwayland-client0, libwayland-egl1, libegl1, libgl1, libx11-6, libx11-xcb1, libxcursor1, libxkbcommon-x11-0
Section: net
Priority: optional
Homepage: https://github.com/etherhaus/oko
Description: Blocking detector: measures, does not bypass
 Oko runs a series of network probes against services people actually use and
 says what stands in the way: a spoofed DNS answer, a middlebox that reads the
 server name, an address that is blocked, a Host header that is filtered, a
 connection cut at 16-20 KB.
 .
 It measures. It does not bypass.
EOF
# dpkg wants the *contents* of DEBIAN at the root of control.tar.gz, as
# ./control, and the payload as ./usr — not the DEBIAN/ directory itself.
( cd "$DEBROOT/usr" && find . -type f | sed 's|^\./||' | sort | xargs md5sum ) \
    > "$DEBROOT/DEBIAN/md5sums"
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime='@0' \
    -C "$DEBROOT/DEBIAN" -czf "$WORK/control.tar.gz" .
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime='@0' \
    -C "$DEBROOT" -czf "$WORK/data.tar.gz" ./usr
printf '2.0\n' > "$WORK/debian-binary"
DEB="$OUT/oko_${VERSION}_${DEBARCH}.deb"
rm -f "$DEB"
(cd "$WORK" && ar rc "$DEB" debian-binary control.tar.gz data.tar.gz)
say "Packed $DEB"

# ── the rpm ──────────────────────────────────────────────────────────────────
# rpmbuild wants a spec and a tree; the binary is handed over through
# _sourcedir, so there is no %prep and no source archive to fetch.
if command -v rpmbuild >/dev/null; then
    RPMTOP="$WORK/rpm"
    mkdir -p "$RPMTOP"/{BUILD,RPMS,SOURCES,SPECS,SRPMS,db}
    install -m755 "$BIN" "$RPMTOP/SOURCES/oko"
    install -m644 LICENSE "$RPMTOP/SOURCES/LICENSE"
    cat > "$RPMTOP/SPECS/oko.spec" <<EOF
# The binary arrives already stripped by the release profile, and the host
# strip cannot read a foreign architecture anyway: leave it alone.
%global debug_package %{nil}
%global __strip /bin/true
%global __objdump /bin/true

Name:           oko
Version:        $VERSION
Release:        1
Summary:        Blocking detector: measures, does not bypass
License:        MIT
URL:            https://github.com/etherhaus/oko
Requires:       fontconfig freetype libpng brotli bzip2-libs expat zlib xkbcommon
Requires:       wayland-libs-client mesa-libEGL mesa-libGL libX11 libXcursor

%description
Oko runs a series of network probes against services people actually use and
says what stands in the way: a spoofed DNS answer, a middlebox that reads the
server name, an address that is blocked, a Host header that is filtered, a
connection cut at 16-20 KB.

It measures. It does not bypass.

%install
install -Dm755 %{_sourcedir}/oko %{buildroot}%{_bindir}/oko
install -Dm644 $ROOT/packaging/io.github.etherhaus.Oko.desktop %{buildroot}%{_datadir}/applications/io.github.etherhaus.Oko.desktop
install -Dm644 $ROOT/packaging/io.github.etherhaus.Oko.metainfo.xml %{buildroot}%{_datadir}/metainfo/io.github.etherhaus.Oko.metainfo.xml
for size in 16 32 48 64 128 256; do
    install -Dm644 $ROOT/assets/oko-\$size.png %{buildroot}%{_datadir}/icons/hicolor/\${size}x\${size}/apps/io.github.etherhaus.Oko.png
done
install -Dm644 $ROOT/assets/oko.svg %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/io.github.etherhaus.Oko.svg
install -Dm644 $ROOT/README.md %{buildroot}%{_docdir}/oko/README.md
install -Dm644 $ROOT/README.en.md %{buildroot}%{_docdir}/oko/README.en.md
install -Dm644 %{_sourcedir}/LICENSE %{buildroot}%{_docdir}/oko/LICENSE

%files
%{_bindir}/oko
%{_datadir}/applications/io.github.etherhaus.Oko.desktop
%{_datadir}/metainfo/io.github.etherhaus.Oko.metainfo.xml
%{_datadir}/icons/hicolor/*/apps/io.github.etherhaus.Oko.*
%{_docdir}/oko/README.md
%{_docdir}/oko/README.en.md
%{_docdir}/oko/LICENSE
EOF
    # --target, not BuildArch: BuildArch makes rpmbuild check the host and
    # refuse an aarch64 package on an x86_64 machine, while --target just
    # says what the payload is.
    rpmbuild -bb --quiet --target "$RPMARCH-linux" \
        --define "_topdir $RPMTOP" \
        --define "_sourcedir $RPMTOP/SOURCES" \
        --define "_builddir $RPMTOP/BUILD" \
        --define "_rpmdir $RPMTOP/RPMS" \
        --define "_dbpath $RPMTOP/db" \
        --define "_build_name_fmt %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm" \
        "$RPMTOP/SPECS/oko.spec" >/dev/null
    RPM=$(find "$RPMTOP/RPMS" -name '*.rpm' | head -1)
    [ -n "$RPM" ] || { echo "rpmbuild produced no package" >&2; exit 1; }
    cp "$RPM" "$OUT/"
    say "Packed $OUT/$(basename "$RPM")"
else
    say "No rpmbuild: the rpm was not built"
fi

# ── the Arch package ─────────────────────────────────────────────────────────
# makepkg is the only thing that writes .PKGINFO and .MTREE correctly, so the
# package is cut by makepkg from a PKGBUILD that installs the prebuilt binary.
if command -v makepkg >/dev/null; then
    ARCDIR="$WORK/arch"
    mkdir -p "$ARCDIR"
    install -m755 "$BIN" "$ARCDIR/oko"
    cat > "$ARCDIR/PKGBUILD" <<EOF
pkgname=oko
pkgver=$VERSION
pkgrel=1
pkgdesc="Blocking detector: measures, does not bypass"
arch=('$ARCHARCH')
url="https://github.com/etherhaus/oko"
license=('MIT')
depends=('fontconfig' 'freetype2' 'libpng' 'brotli' 'bzip2' 'expat' 'zlib' 'libxkbcommon' 'wayland' 'libglvnd' 'libx11' 'libxcursor')
options=('!strip' '!debug')
source=()

package() {
    install -Dm755 "\$startdir/oko" "\$pkgdir/usr/bin/oko"
    install -Dm644 "$PWD/packaging/io.github.etherhaus.Oko.desktop" "\$pkgdir/usr/share/applications/io.github.etherhaus.Oko.desktop"
    install -Dm644 "$PWD/packaging/io.github.etherhaus.Oko.metainfo.xml" "\$pkgdir/usr/share/metainfo/io.github.etherhaus.Oko.metainfo.xml"
    for size in 16 32 48 64 128 256; do
        install -Dm644 "$PWD/assets/oko-\$size.png" "\$pkgdir/usr/share/icons/hicolor/\${size}x\${size}/apps/io.github.etherhaus.Oko.png"
    done
    install -Dm644 "$PWD/assets/oko.svg" "\$pkgdir/usr/share/icons/hicolor/scalable/apps/io.github.etherhaus.Oko.svg"
    install -Dm644 "$PWD/README.md" "\$pkgdir/usr/share/doc/oko/README.md"
    install -Dm644 "$PWD/README.en.md" "\$pkgdir/usr/share/doc/oko/README.en.md"
    install -Dm644 "$PWD/LICENSE" "\$pkgdir/usr/share/doc/oko/LICENSE"
}
EOF
    # CARCH is what lets makepkg cut an aarch64 package on an x86_64 host: the
    # arch check compares it against arch=() in the PKGBUILD, and the value
    # lands in .PKGINFO.
    ( cd "$ARCDIR" && PKGDEST="$OUT" SOURCE_DATE_EPOCH=0 CARCH="$ARCHARCH" \
        PACKAGER="Dmitry Etherhaus <lehzenblad@proton.me>" \
        makepkg --nodeps --force --cleanbuild --noconfirm >/dev/null 2>&1 ) \
        || { echo "makepkg failed" >&2; exit 1; }
    PKG=$(find "$OUT" -maxdepth 1 -name "oko-$VERSION-1-$ARCHARCH.pkg.tar.zst" | head -1)
    [ -n "$PKG" ] || { echo "makepkg produced no package" >&2; exit 1; }
    say "Packed $PKG"
else
    say "No makepkg: the Arch package was not built"
fi
