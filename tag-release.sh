#!/usr/bin/env bash
set -euo pipefail

# Tags a release and pushes it, which triggers .github/workflows/publish.yml.
#
# Publishing to crates.io and npm is effectively irreversible (crates.io versions can
# only be yanked, never replaced), so this script front-loads the checks that the
# release workflow would otherwise fail on after the tag already exists.

PKG_DIR="tauri-plugin-passkey"
NPM_PKG="tauri-plugin-passkey-api"

if [ $# -ne 1 ]; then
    echo "Usage: $0 <tag>"
    echo "Example: $0 v1.2.3  or  $0 v1.2.3-beta.1"
    exit 1
fi

TAG="$1"

# Ensure tag starts with 'v' — publish.yml triggers on 'v*' and strips the prefix.
if [[ "$TAG" != v* ]]; then
    echo "Error: tag must start with 'v' (e.g. v1.2.3-beta.1)"
    exit 1
fi

# The version as the registries see it: no leading 'v'.
VERSION="${TAG#v}"

# Run from the repository root regardless of the caller's cwd.
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

read_version() {
    grep -m1 "$2" "$1" | sed -E 's/.*"([^"]+)".*/\1/'
}

CARGO_VERSION="$(read_version "$PKG_DIR/Cargo.toml" '^version = ')"
NPM_VERSION="$(read_version "$PKG_DIR/package.json" '"version":')"

# publish.yml verifies both of these too, but only after the tag has been pushed.
# Catching it here avoids a junk tag that has to be deleted and re-pushed.
if [ "$CARGO_VERSION" != "$VERSION" ]; then
    echo "Error: $PKG_DIR/Cargo.toml is $CARGO_VERSION but the tag says $VERSION."
    echo "Bump the version and commit before tagging."
    exit 1
fi

if [ "$NPM_VERSION" != "$VERSION" ]; then
    echo "Error: $PKG_DIR/package.json is $NPM_VERSION but the tag says $VERSION."
    echo "Bump the version and commit before tagging."
    exit 1
fi

# Ensure working tree is clean
if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "Error: working tree has uncommitted changes. Commit or stash them first."
    exit 1
fi

if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
    echo "Error: tag $TAG already exists locally."
    exit 1
fi

git fetch -q origin

if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null 2>&1 ||
    git ls-remote --exit-code --tags origin "refs/tags/$TAG" >/dev/null 2>&1; then
    echo "Error: tag $TAG already exists on origin. Published versions cannot be replaced."
    exit 1
fi

# Releasing from a stale or side branch would publish that commit's contents.
# Set ALLOW_ANY_BRANCH=1 to override deliberately.
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [ "${ALLOW_ANY_BRANCH:-0}" != "1" ]; then
    if [ "$BRANCH" != "main" ]; then
        echo "Error: on branch '$BRANCH', not 'main'. Set ALLOW_ANY_BRANCH=1 to override."
        exit 1
    fi
    if [ "$(git rev-parse HEAD)" != "$(git rev-parse origin/main)" ]; then
        echo "Error: HEAD does not match origin/main. Pull or push first."
        echo "Set ALLOW_ANY_BRANCH=1 to override."
        exit 1
    fi
fi

# Mirrors the channel logic in publish.yml so the guidance below matches what the
# workflow will actually do.
#
# The final case is deliberately a hard error rather than a fallthrough: publish.yml
# recognizes only -alpha, -beta and -rc, and its else branch publishes everything else
# with --tag latest. A version like "1.0.0-pre" would therefore be published as the
# stable release. Refuse it here instead.
case "$VERSION" in
    *-alpha*) CHANNEL="alpha" ;;
    *-beta*) CHANNEL="beta" ;;
    *-rc*) CHANNEL="next" ;;
    *-*)
        echo "Error: unrecognized prerelease suffix in '$VERSION'."
        echo "publish.yml only understands -alpha, -beta and -rc; anything else would be"
        echo "published to npm as 'latest'. Use one of those, or teach publish.yml the"
        echo "new suffix first."
        exit 1
        ;;
    *) CHANNEL="latest" ;;
esac

echo "Releasing $VERSION (npm dist-tag: $CHANNEL)"
echo "Tagging $TAG and pushing..."

git tag "$TAG" -m "Release $TAG"
git push origin HEAD
git push origin "$TAG"

echo
echo "Done. Release workflow triggered for $TAG."
echo "Watch it: gh run watch \$(gh run list --workflow=Publish --limit 1 --json databaseId -q '.[0].databaseId')"
echo

if [ "$CHANNEL" = "latest" ]; then
    echo "This is a stable release. publish.yml publishes it to npm with --tag latest,"
    echo "so no dist-tag work is needed."
else
    echo "This is a prerelease. publish.yml publishes it to npm with --tag $CHANNEL,"
    echo "which does NOT move 'latest'."
    echo
    echo "While no stable release exists, you may want 'latest' to track the newest"
    echo "prerelease so that a plain 'npm install $NPM_PKG' resolves to it:"
    echo
    echo "  npm dist-tag add $NPM_PKG@$VERSION latest"
    echo
    echo "Stop doing this once 1.0 ships — after that, 'latest' must stay on the newest"
    echo "stable version, and the workflow manages it for you."
fi
