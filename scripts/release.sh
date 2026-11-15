#!/usr/bin/env bash
# Cut a release: build, pack the assets the updater expects, sign them, and
# open a draft on GitHub.
#
# The contract this script has to keep is the one in src/update.rs:
#
#   tag     vX.Y.Z, the same X.Y.Z as Cargo.toml
#   assets  oko-<version>-<os>-<arch>.tar.gz
#           oko-<version>-<os>-<arch>.tar.gz.minisig
#   inside  oko-<version>-<os>-<arch>/oko
#
# The signature is made here, on this machine, with the key named by
# OKO_MINISIGN_KEY. The key is never in the repository and never in CI: a
# release that cannot be signed is not a release.
#
#   scripts/release.sh --dry-run     build, pack and sign; do not touch GitHub
#   scripts/release.sh               the same, then `gh release create --draft`
#
# The draft is not published by this script. Publishing is a separate, explicit
# step: `gh release edit vX.Y.Z --draft=false`.

set -euo pipefail

cd "$(dirname "$0")/.."

DRY_RUN=0
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        -h|--help) sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

say() { printf '\033[1m%s\033[0m\n' "$*"; }
die() { printf '\033[31m%s\033[0m\n' "$*" >&2; exit 1; }

# ── the version ──────────────────────────────────────────────────────────────
# Cargo.toml is the only place the version lives. The tag follows it, never the
# other way round: a tag that disagrees with the binary is a release nobody can
# update to.
VERSION=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)
[ -n "$VERSION" ] || die "no version in Cargo.toml"
TAG="v$VERSION"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in
    linux) OS=linux ;;
    darwin) OS=macos ;;
    *) die "unsupported system: $OS" ;;
esac
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64) ARCH=x86_64 ;;
    aarch64|arm64) ARCH=aarch64 ;;
    *) die "unsupported architecture: $ARCH" ;;
esac

NAME="oko-$VERSION-$OS-$ARCH"
TARBALL="$NAME.tar.gz"

say "Oko $VERSION — $TAG, $OS/$ARCH"

# ── the key ──────────────────────────────────────────────────────────────────
# The public half in keys/ must be the one the private half belongs to, or the
# release would be signed with a key no binary trusts.
[ -f keys/minisign.pub ] || die "keys/minisign.pub is missing"
if [ "$DRY_RUN" -eq 0 ]; then
    [ -n "${OKO_MINISIGN_KEY:-}" ] || die "OKO_MINISIGN_KEY is not set: point it at the private key"
    [ -f "$OKO_MINISIGN_KEY" ] || die "OKO_MINISIGN_KEY does not name a file: $OKO_MINISIGN_KEY"
fi

# ── the build ────────────────────────────────────────────────────────────────
say "Building"
cargo build --release --locked

BIN=target/release/oko
[ -x "$BIN" ] || die "the build produced no $BIN"

# The binary must agree with the version in Cargo.toml, or the updater will
# offer this release to itself forever.
BUILT=$("$BIN" --version | awk '{print $2}')
[ "$BUILT" = "$VERSION" ] || die "the binary says $BUILT, Cargo.toml says $VERSION"

# ── the assets ───────────────────────────────────────────────────────────────
DIST=dist
rm -rf "$DIST/$NAME"
mkdir -p "$DIST/$NAME"
install -m755 "$BIN" "$DIST/$NAME/oko"
install -m644 README.md README.en.md LICENSE "$DIST/$NAME/"
# The desktop entry and the icons travel with the binary: the archive is the
# whole install kit, not just the file the updater swaps in.
cp -r packaging assets "$DIST/$NAME/"

# Deterministic archive: the same tree gives the same bytes, so a rebuild can be
# compared with what was published.
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime='@0' \
    -C "$DIST" -czf "$DIST/$TARBALL" "$NAME"

say "Packed $DIST/$TARBALL ($(du -h "$DIST/$TARBALL" | cut -f1))"

if [ "$DRY_RUN" -eq 1 ]; then
    # A dry run still signs, when a key is at hand: the point of the run is to
    # prove the whole path, and the signature is the part that matters most.
    if [ -n "${OKO_MINISIGN_KEY:-}" ] && [ -f "${OKO_MINISIGN_KEY:-}" ]; then
        minisign -S -s "$OKO_MINISIGN_KEY" -m "$DIST/$TARBALL" \
            -t "oko $VERSION $OS $ARCH" >/dev/null
        say "Signed $DIST/$TARBALL.minisig (dry run)"
        if minisign -Vm "$DIST/$TARBALL" -p keys/minisign.pub >/dev/null 2>&1; then
            say "The signature checks out against keys/minisign.pub"
        else
            say "Signed with a key that is not keys/minisign.pub — expected for a test key"
        fi
    else
        say "No OKO_MINISIGN_KEY: the archive is unsigned (dry run)"
    fi
    say "Dry run: GitHub was not touched"
    exit 0
fi

# ── the signature ────────────────────────────────────────────────────────────
say "Signing"
minisign -S -s "$OKO_MINISIGN_KEY" -m "$DIST/$TARBALL" -t "oko $VERSION $OS $ARCH" >/dev/null
[ -f "$DIST/$TARBALL.minisig" ] || die "minisign wrote no signature"

# Verify with the public key that is compiled into the binary. A signature that
# does not check out here would not check out on the user's machine either.
minisign -Vm "$DIST/$TARBALL" -p keys/minisign.pub >/dev/null \
    || die "the signature does not verify against keys/minisign.pub"
say "The signature verifies against keys/minisign.pub"

# ── the draft ────────────────────────────────────────────────────────────────
command -v gh >/dev/null || die "gh is not installed: the draft needs it"

if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
    die "tag $TAG already exists"
fi
git tag -a "$TAG" -m "Oko $VERSION"
# gh refuses to attach assets to a tag it cannot see on the remote, so the tag
# goes up before the draft does.
git push origin "$TAG"

say "Opening a draft release"
gh release create "$TAG" \
    --draft \
    --title "Oko $VERSION" \
    --notes "Oko $VERSION. Assets are signed with minisign; the key is in README.md." \
    "$DIST/$TARBALL" "$DIST/$TARBALL.minisig"

say "Draft $TAG is on GitHub. Nothing is published yet:"
say "  gh release edit $TAG --draft=false"
