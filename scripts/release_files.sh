#!/usr/bin/env bash
# The notes and files of a release (ADR-0085, docs/releasing.md).
#
#   bash scripts/release_files.sh <tag> <commit>
#
# <tag>     vX.Y.Z.  scripts/release.py check holds it against the version in
#           the tree and the CHANGELOG.
# <commit>  The commit main's CI built the image from: the tagged commit, or,
#           for the pull-request dry run, main's last commit whose CI passed.
#
# Finds the image main's CI published for <commit> (ghcr.io, tag sha-<commit>)
# and verifies its two attestations: SLSA provenance and SBOM, both signed by
# ci.yml on refs/heads/main for <commit>.  Then writes:
#
#   release/dist/ctiparsor-X.Y.Z.tar.gz          git archive of HEAD
#   release/dist/ctiparsor-X.Y.Z-image.cdx.json  the image's SBOM, as attested
#   release/dist/SHA256SUMS                      the two files above
#   release/notes.md                             scripts/release.py notes
#   release/image                                name@digest of the image
#   release/version                              X.Y.Z
#
# Publishes nothing: the Release workflow attests and uploads these files.
# Needs git, docker with buildx, gh (GH_TOKEN), python3, GITHUB_REPOSITORY.
set -euo pipefail

tag=${1:?usage: release_files.sh <tag> <commit>}
commit=${2:?usage: release_files.sh <tag> <commit>}
repo=${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}

version=$(python3 scripts/release.py check "$tag")
name="ghcr.io/${repo,,}"   # GHCR names are lowercase; the owner is not

digest=$(docker buildx imagetools inspect "$name:sha-$commit" --format '{{json .Manifest}}' \
  | python3 -c 'import json, sys; print(json.load(sys.stdin)["digest"])')
image="$name@$digest"
echo "Image main's CI published for $commit: $image"

# Built by this repository's ci.yml, on main, from <commit>: anything else,
# such as an image pushed by hand under that tag, fails here.
verify=(gh attestation verify "oci://$image" -R "$repo"
        --signer-workflow "$repo/.github/workflows/ci.yml"
        --source-ref refs/heads/main --source-digest "$commit")

mkdir -p release/dist
"${verify[@]}" > /dev/null
"${verify[@]}" --predicate-type https://cyclonedx.org/bom --format json > release/sbom-verified.json
python3 scripts/release.py predicate release/sbom-verified.json --type https://cyclonedx.org/bom \
  > "release/dist/ctiparsor-$version-image.cdx.json"

git archive --format=tar.gz --prefix="ctiparsor-$version/" \
  -o "release/dist/ctiparsor-$version.tar.gz" HEAD

(cd release/dist && sha256sum -- "ctiparsor-$version.tar.gz" "ctiparsor-$version-image.cdx.json" > SHA256SUMS)

python3 scripts/release.py notes "$version" --image "$image" --repo "$repo" > release/notes.md
printf '%s\n' "$image" > release/image
printf '%s\n' "$version" > release/version
echo "Wrote release/notes.md and release/dist/:"
ls -l release/dist
