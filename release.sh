#!/bin/sh
set -eu

# Resolve project directory relative to script path
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [ $# -lt 1 ]; then
	echo "Usage: $0 <major|minor|patch> [--push]"
	exit 1
fi

BUMP_TYPE=""
DO_PUSH=0

for arg in "$@"; do
	case "$arg" in
		major|minor|patch)
			BUMP_TYPE="$arg"
			;;
		--push)
			DO_PUSH=1
			;;
		*)
			echo "Error: unrecognized argument '$arg'"
			echo "Usage: $0 <major|minor|patch> [--push]"
			exit 1
			;;
	esac
done

if [ -z "$BUMP_TYPE" ]; then
	echo "Error: specify bump type: major, minor, or patch"
	exit 1
fi

# Ensure git working tree is clean
if [ -n "$(git status --porcelain)" ]; then
	echo "Error: working tree contains uncommitted changes. Commit or stash them first."
	exit 1
fi

CURRENT_VERSION="0.1.0"
if [ -f VERSION ]; then
	CURRENT_VERSION="$(tr -d 'v \t\r\n' < VERSION)"
fi

# Parse semver components
MAJOR="$(echo "$CURRENT_VERSION" | cut -d. -f1)"
MINOR="$(echo "$CURRENT_VERSION" | cut -d. -f2)"
PATCH="$(echo "$CURRENT_VERSION" | cut -d. -f3)"

case "$BUMP_TYPE" in
	major)
		MAJOR=$((MAJOR + 1))
		MINOR=0
		PATCH=0
		;;
	minor)
		MINOR=$((MINOR + 1))
		PATCH=0
		;;
	patch)
		PATCH=$((PATCH + 1))
		;;
esac

NEW_VERSION="${MAJOR}.${MINOR}.${PATCH}"
TAG="v${NEW_VERSION}"

echo "Bumping version: ${CURRENT_VERSION} -> ${NEW_VERSION} (${BUMP_TYPE})"

# Update VERSION file
echo "${NEW_VERSION}" > VERSION

# Update pkg/version/version.go
cat <<EOF > pkg/version/version.go
// Package version defines the current release version of dev-vps.
package version

// Version holds the semantic version string of the binary.
var Version = "${NEW_VERSION}"

// Current returns the current semantic version string.
func Current() string {
	return Version
}
EOF

# Run test suite to verify tests pass
echo "Running tests..."
go test ./...

# Commit and tag
git add VERSION pkg/version/version.go
git commit -m "chore(release): ${TAG}"
git tag -a "${TAG}" -m "Release ${TAG}"

echo "Created release commit and tag: ${TAG}"

if [ "${DO_PUSH}" -eq 1 ]; then
	echo "Pushing release to origin..."
	CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
	git push origin "${CURRENT_BRANCH}" --tags
	echo "Successfully pushed ${CURRENT_BRANCH} and ${TAG} to origin."
else
	echo "Tag created locally. To push to remote, run:"
	echo "  git push origin $(git rev-parse --abbrev-ref HEAD) --tags"
fi
