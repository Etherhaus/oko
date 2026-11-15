#!/usr/bin/env bash
# Cut a release: build both architectures, pack the four shapes each one
# carries, sign every file, and open a draft on GitHub.
#
#   scripts/release.sh --dry-run     build, pack and sign; do not touch GitHub
#   scripts/release.sh               the same, then `gh release create --draft`
#
# The x86_64 binary is built here. The aarch64 one is taken from the CI run for
# this commit: there is no cross toolchain on the release machine, and a binary
# built elsewhere is still a binary this machine signs.
#
# The signature is made here, with the key named by OKO_MINISIGN_KEY. The key
# is never in the repository and never in CI: a release that cannot be signed
# is not a release.
#
# The draft is not published by this script. Publishing is a separate, explicit
# step: `gh release edit vX.Y.Z --draft=false`.

set -euo pipefail

cd "$(dirname "$0")/.."

DRY_RUN=0
ARM_BINARY=""
while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=1 ;;
        --arm-binary) ARM_BINARY=${2:?--arm-binary needs a path}; shift ;;
        -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
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

say "Oko $VERSION — $TAG"

# ── the key ──────────────────────────────────────────────────────────────────
# The public half in keys/ must be the one the private half belongs to, or the
# release would be signed with a key no binary trusts.
[ -f keys/minisign.pub ] || die "keys/minisign.pub is missing"
if [ "$DRY_RUN" -eq 0 ]; then
    [ -n "${OKO_MINISIGN_KEY:-}" ] || die "OKO_MINISIGN_KEY is not set: point it at the private key"
    [ -f "$OKO_MINISIGN_KEY" ] || die "OKO_MINISIGN_KEY does not name a file: $OKO_MINISIGN_KEY"
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
DIST=dist
rm -rf "$DIST"
mkdir -p "$DIST"

# ── the x86_64 binary ────────────────────────────────────────────────────────
say "Building x86_64"
cargo build --release --locked
X86=target/release/oko
[ -x "$X86" ] || die "the build produced no $X86"

# The binary must agree with the version in Cargo.toml, or the updater will
# offer this release to itself forever.
BUILT=$("$X86" --version | awk '{print $2}')
[ "$BUILT" = "$VERSION" ] || die "the binary says $BUILT, Cargo.toml says $VERSION"

# ── the aarch64 binary ───────────────────────────────────────────────────────
# It comes from CI, and it must come from *this* commit: a release whose two
# architectures were built from different trees is two releases wearing one tag.
if [ -n "$ARM_BINARY" ]; then
    [ -f "$ARM_BINARY" ] || die "no such file: $ARM_BINARY"
    ARM=$ARM_BINARY
    say "aarch64 binary taken from $ARM_BINARY"
else
    command -v gh >/dev/null || die "gh is not installed: the aarch64 binary comes from CI"
    REPO=$(git remote get-url origin | sed -E 's#(git@|https://)github\.com[:/]##; s#\.git$##')
    SHA=$(git rev-parse HEAD)
    say "Fetching the aarch64 binary from CI for $SHA"
    RUN=$(gh run list --repo "$REPO" --commit "$SHA" --workflow ci.yml --limit 1 \
        --json databaseId,conclusion --jq '.[0].databaseId // empty')
    [ -n "$RUN" ] || die "no CI run for $SHA: push the commit and let build-arm finish"
    CONCLUSION=$(gh run view "$RUN" --repo "$REPO" --json conclusion --jq '.conclusion')
    [ "$CONCLUSION" = "success" ] || die "the CI run for $SHA is $CONCLUSION, not success"
    gh run download "$RUN" --repo "$REPO" --name oko-linux-aarch64 --dir "$WORK/arm"
    ARM="$WORK/arm/oko"
    [ -f "$ARM" ] || die "the CI run carried no oko binary"
fi

# A wrong-architecture binary would pack cleanly and fail on the user's machine.
file "$ARM" | grep -q 'ARM aarch64' || die "$ARM is not an aarch64 binary"

# ── the packages ─────────────────────────────────────────────────────────────
say "Packing x86_64"
./scripts/package.sh "$X86" x86_64 "$DIST"
say "Packing aarch64"
./scripts/package.sh "$ARM" aarch64 "$DIST"

# Every format the release promises, named once. A release that quietly ships
# three of four is worse than one that stops here.
EXPECTED=(
    "oko-$VERSION-linux-x86_64.tar.gz"
    "oko_${VERSION}_amd64.deb"
    "oko-$VERSION-1.x86_64.rpm"
    "oko-$VERSION-1-x86_64.pkg.tar.zst"
    "oko-$VERSION-linux-aarch64.tar.gz"
    "oko_${VERSION}_arm64.deb"
    "oko-$VERSION-1.aarch64.rpm"
    "oko-$VERSION-1-aarch64.pkg.tar.zst"
)
for asset in "${EXPECTED[@]}"; do
    [ -f "$DIST/$asset" ] || die "missing from the release: $asset"
done
say "All ${#EXPECTED[@]} assets are in $DIST"

# ── the signatures ───────────────────────────────────────────────────────────
if [ "$DRY_RUN" -eq 1 ] && { [ -z "${OKO_MINISIGN_KEY:-}" ] || [ ! -f "${OKO_MINISIGN_KEY:-}" ]; }; then
    say "No OKO_MINISIGN_KEY: the assets are unsigned (dry run)"
    say "Dry run: GitHub was not touched"
    exit 0
fi

say "Signing"
for asset in "${EXPECTED[@]}"; do
    minisign -S -s "$OKO_MINISIGN_KEY" -m "$DIST/$asset" -t "oko $VERSION" >/dev/null
    [ -f "$DIST/$asset.minisig" ] || die "minisign wrote no signature for $asset"
done

# Verify with the public key that is compiled into the binary. A signature that
# does not check out here would not check out on the user's machine either.
for asset in "${EXPECTED[@]}"; do
    minisign -Vm "$DIST/$asset" -p keys/minisign.pub >/dev/null \
        || die "the signature on $asset does not verify against keys/minisign.pub"
done
say "All ${#EXPECTED[@]} signatures verify against keys/minisign.pub"

if [ "$DRY_RUN" -eq 1 ]; then
    say "Dry run: GitHub was not touched"
    exit 0
fi

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
    --notes "Oko $VERSION.

Linux x86_64 and aarch64. Each architecture comes as a tarball (what the
built-in updater takes), a .deb, an .rpm and an Arch .pkg.tar.zst.

Every asset is signed with minisign; the key is in README.md. A binary
installed by a package manager will not update itself — that is what the
package manager is for." \
    "$DIST"/*.tar.gz "$DIST"/*.deb "$DIST"/*.rpm "$DIST"/*.pkg.tar.zst \
    "$DIST"/*.minisig

say "Draft $TAG is on GitHub. Nothing is published yet:"
say "  gh release edit $TAG --draft=false"
