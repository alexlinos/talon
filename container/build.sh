#!/bin/bash
# Build the NanoClaw agent container image

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

IMAGE_NAME="nanoclaw-agent"
TAG="${1:-latest}"
CONTAINER_RUNTIME="${CONTAINER_RUNTIME:-container}"

echo "Building NanoClaw agent container image..."
echo "Image: ${IMAGE_NAME}:${TAG}"

# The build context is this directory, so the repo-root copilot-mcp fork is not
# reachable by COPY. Stage it here first. It is a Talon fork of
# socfortress/copilot-mcp-server, so it cannot be pip-installed from GitHub.
VENDOR_DIR="$SCRIPT_DIR/vendor/copilot-mcp"
rm -rf "$SCRIPT_DIR/vendor"
# Clean up the staging dir even if the build fails (this script runs under set -e).
trap 'rm -rf "$SCRIPT_DIR/vendor"' EXIT
mkdir -p "$VENDOR_DIR"
for item in copilot_mcp_server pyproject.toml requirements.txt README.md LICENSE MANIFEST.in; do
    cp -R "$SCRIPT_DIR/../copilot-mcp/$item" "$VENDOR_DIR/$item"
done
find "$VENDOR_DIR" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
echo "Staged copilot-mcp fork into $VENDOR_DIR"

${CONTAINER_RUNTIME} build -t "${IMAGE_NAME}:${TAG}" .

echo ""
echo "Build complete!"
echo "Image: ${IMAGE_NAME}:${TAG}"
echo ""
echo "Test with:"
echo "  echo '{\"prompt\":\"What is 2+2?\",\"groupFolder\":\"test\",\"chatJid\":\"test@g.us\",\"isMain\":false}' | ${CONTAINER_RUNTIME} run -i ${IMAGE_NAME}:${TAG}"
