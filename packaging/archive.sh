#!/usr/bin/env bash
set -euo pipefail

: "${SECSTORE_VERSION:?SECSTORE_VERSION is required}"
: "${SECSTORE_ARCH:?SECSTORE_ARCH is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP must name a temporary staging directory}"

archive="secstore-v${SECSTORE_VERSION}-linux-${SECSTORE_ARCH}"
staging="$RUNNER_TEMP/$archive"
install -Dm755 dist/secstore "$staging/bin/secstore"
install -Dm644 packaging/systemd/secstore-hydrate.service "$staging/packaging/systemd/secstore-hydrate.service"
install -Dm644 doc/design.md "$staging/doc/design.md"
install -m644 LICENSE README.md "$staging/"
tar -czf "dist/$archive.tar.gz" -C "$RUNNER_TEMP" "$archive"
(cd dist && sha256sum -- *.tar.gz *.deb *.rpm > SHA256SUMS)
