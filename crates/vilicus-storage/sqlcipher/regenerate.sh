#!/usr/bin/env bash
# Regenerates the SQLCipher amalgamation of this directory from the official release tag and
# compares it with SHA256SUMS (D143). With --write, it replaces sqlite3.c, the licence files and
# SHA256SUMS with what it generated, which is how an upgrade starts: change TAG, TAG_OBJECT and
# COMMIT below, run with --write, review the diff.
#
# Run it in the pinned build image, which has git, a C compiler and make; generation needs no
# tclsh, since SQLite's build compiles its bundled jimsh. It needs the network to clone the tag.
# Its work directory is left under the system temporary directory, so run it in a throwaway
# container (see README.md):
#
#   docker run --rm -v "$PWD:/w" -w /w <image> bash crates/vilicus-storage/sqlcipher/regenerate.sh
set -euo pipefail

TAG=v4.19.0
TAG_OBJECT=58beb4a302f0e3c37341d2312cef521f858b1273
COMMIT=c4b275a47932888216bade83aff2bbc73df0ff85
REPOSITORY=https://github.com/sqlcipher/sqlcipher
# Files taken from the tag as they are, then the generated amalgamation.
COPIED=(LICENSE.md SQLITE_LICENSE.md)
GENERATED=sqlite3.c

write=false
case "${1:-}" in
  "") ;;
  --write) write=true ;;
  *) echo "usage: $0 [--write]" >&2; exit 2 ;;
esac

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"

git clone --quiet --depth 1 --branch "$TAG" "$REPOSITORY" "$work/src" 2>/dev/null
tag_object="$(git -C "$work/src" rev-parse "refs/tags/$TAG")"
commit="$(git -C "$work/src" rev-parse HEAD)"
if [ "$tag_object" != "$TAG_OBJECT" ] || [ "$commit" != "$COMMIT" ]; then
  echo "tag $TAG is object $tag_object on commit $commit; expected $TAG_OBJECT on $COMMIT" >&2
  exit 1
fi

mkdir "$work/build" "$work/out"
(cd "$work/build" && "$work/src/configure" >"$work/configure.log" 2>&1 && make "$GENERATED" >"$work/make.log" 2>&1)
cp "$work/build/$GENERATED" "$work/out/"
for file in "${COPIED[@]}"; do
  cp "$work/src/$file" "$work/out/"
done
(cd "$work/out" && sha256sum "${COPIED[@]}" "$GENERATED" | sort -k 2 >"$work/SHA256SUMS")

if $write; then
  cp "$work/out/"* "$here/"
  cp "$work/SHA256SUMS" "$here/SHA256SUMS"
  echo "wrote $TAG ($COMMIT) into $here"
fi
if ! diff -u "$here/SHA256SUMS" "$work/SHA256SUMS"; then
  echo "the amalgamation generated from $TAG differs from SHA256SUMS" >&2
  exit 1
fi
(cd "$here" && sha256sum --check --quiet SHA256SUMS)
# Byte for byte as well, so the comparison does not rest on SHA256SUMS alone.
for file in "${COPIED[@]}" "$GENERATED"; do
  if ! cmp "$work/out/$file" "$here/$file"; then
    echo "$file generated from $TAG differs from the committed $file" >&2
    exit 1
  fi
done
echo "SQLCipher $TAG ($COMMIT) regenerates to the files of SHA256SUMS, byte for byte"
