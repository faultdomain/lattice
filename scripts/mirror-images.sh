#!/usr/bin/env bash
#
# Mirror all Docker Hub images used by E2E tests to GHCR.
#
# Prerequisites:
#   echo $GITHUB_TOKEN | docker login ghcr.io -u evan-hines-js --password-stdin
#
# Usage:
#   ./scripts/mirror-images.sh          # mirror all images
#   ./scripts/mirror-images.sh --dry-run # show what would be mirrored

set -euo pipefail

GHCR_PREFIX="ghcr.io/evan-hines-js"

# source → GHCR target name
# Format: "docker.io/org/image:tag  target-name:tag"
IMAGES=(
  # E2E test helpers (used by test_image() in helpers/mod.rs)
  "docker.io/nginxinc/nginx-unprivileged:alpine       nginx-unprivileged:alpine"
  "docker.io/curlimages/curl:latest                   curl:latest"
  "docker.io/library/busybox:latest                   busybox:latest"
  "docker.io/bitnami/kubectl:latest                   kubectl:latest"

  # Media server fixtures
  "docker.io/jellyfin/jellyfin:latest                 jellyfin:latest"
  "docker.io/plexinc/pms-docker:latest                pms-docker:latest"
  "docker.io/linuxserver/nzbget:latest                nzbget:latest"
  "docker.io/linuxserver/wireguard:latest             wireguard:latest"
  "docker.io/linuxserver/sonarr:latest                sonarr:latest"
)

DRY_RUN=false
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=true
fi

failed=0

for entry in "${IMAGES[@]}"; do
  src=$(echo "$entry" | awk '{print $1}')
  dst_name=$(echo "$entry" | awk '{print $2}')
  dst="${GHCR_PREFIX}/${dst_name}"

  echo "=== ${src} → ${dst} ==="

  if $DRY_RUN; then
    echo "  [dry-run] would pull, tag, push"
    continue
  fi

  if ! docker pull "$src"; then
    echo "  FAILED to pull $src"
    failed=$((failed + 1))
    continue
  fi

  docker tag "$src" "$dst"

  if ! docker push "$dst"; then
    echo "  FAILED to push $dst"
    failed=$((failed + 1))
    continue
  fi

  echo "  OK"
done

echo ""
if [ $failed -gt 0 ]; then
  echo "WARNING: $failed image(s) failed to mirror"
  exit 1
else
  echo "All images mirrored to ${GHCR_PREFIX}/"
fi
