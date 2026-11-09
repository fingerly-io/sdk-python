#!/usr/bin/env bash
# The version gate release.yml runs. src/fingerly/_version.py is the manifest:
# hatch reads the package version from it.
#
#   version      print the manifest's version
#   consistency  fail if anything else could declare a different version
#   check        print version= and release=true|false for $GITHUB_OUTPUT
set -euo pipefail

die() {
  echo "release-version: $*" >&2
  exit 1
}

# Only a clear yes or no is an answer. An outage has to fail the job, because
# reading it as "not published" would try to release a version that exists.
lookup() {
  local out
  out=$(curl --silent --show-error --location --max-time 30 --retry 3 --retry-all-errors \
    --write-out '\n%{http_code}' "$1") || die "could not reach $1"
  status=${out##*$'\n'}
  body=${out%$'\n'*}
}

on_registry() {
  lookup "https://pypi.org/pypi/fingerly/$version/json"
  case "$status" in
    200) return 0 ;;
    404) return 1 ;;
    *) die "PyPI answered $status" ;;
  esac
}

tag_exists() {
  local rc=0
  git ls-remote --exit-code --tags origin "refs/tags/v$version" >/dev/null || rc=$?
  case "$rc" in
    0) return 0 ;;
    2) return 1 ;;
    *) die "git ls-remote failed with $rc" ;;
  esac
}

version=$(sed -n 's/^__version__ = "\([^"]*\)"$/\1/p' src/fingerly/_version.py)
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "no X.Y.Z version in the manifest: '$version'"

case "${1:-}" in
  version)
    echo "$version"
    ;;
  consistency)
    # A literal version in pyproject.toml would quietly replace the manifest.
    grep -q '^dynamic = \["version"\]$' pyproject.toml || die "pyproject.toml must keep the version dynamic"
    grep -q '^path = "src/fingerly/_version.py"$' pyproject.toml || die "hatch must read src/fingerly/_version.py"
    ;;
  check)
    echo "version=$version"
    if tag_exists; then
      echo "v$version is already tagged" >&2
      echo "release=false"
    elif on_registry; then
      echo "$version is already on PyPI" >&2
      echo "release=false"
    else
      echo "release=true"
    fi
    ;;
  *)
    die "usage: release-version.sh version|consistency|check"
    ;;
esac
