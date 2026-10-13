# secstore

`secstore` is a small Linux secret store for Docker Compose hosts. It encrypts
secrets on disk with age and hydrates them into a protected, non-swappable
tmpfs. It ships as a single native executable; no Go or age installation is
needed to run it.

## Getting started

Use a Linux host with tmpfs `noswap` support (upstream kernel 6.4+) and root
mounting privileges.

Download the `.deb` or `.rpm` package for your architecture from
[GitHub Releases](https://github.com/Bpoe/secstore/releases), then install it:

```sh
sudo apt install ./secstore_*.deb     # Debian / Ubuntu
# or
sudo dnf install ./secstore-*.rpm     # Fedora / RHEL
```

Initialize the store, add a secret through stdin, and hydrate it:

```sh
sudo secstore init
printf '%s' "$DB_PASSWORD" | sudo secstore add --name app/db_password
sudo secstore hydrate
```

The encrypted blob is stored at `/var/lib/secstore/secrets/app/db_password.age`.
The runtime file is available at `/run/secrets-store/app/db_password`.

Remove a secret with:

```sh
sudo secstore remove --name app/db_password
```

To hydrate before Docker starts, enable the included systemd service:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now secstore-hydrate.service
```

Packages do not automatically initialize the store or enable services.
The service uses `0444` file permissions for unprivileged container users;
root-owned `0700` host directories still restrict access.

## Docker Compose

Reference the hydrated host file as a Compose secret:

```yaml
services:
  app:
    image: your-app-image
    secrets:
      - db_password

secrets:
  db_password:
    file: /run/secrets-store/app/db_password
```

Configure your application to read `/run/secrets/db_password`. After changing
a secret, hydrate again and recreate affected containers to refresh their
file bind mounts.

## Configuration and design

`secstore --help` lists the commands and environment overrides:

```sh
SECSTORE_VAULT_DIR=/var/lib/secstore
SECSTORE_RUN_DIR=/run/secrets-store
SECSTORE_RUN_SIZE=16M
SECSTORE_FILE_MODE=0400
```

Back up `identity.txt` along with the encrypted blobs and protect the backup.
Anyone possessing both can decrypt the secrets.

See [doc/design.md](doc/design.md) for storage layout, command behavior,
hydration guarantees, security boundaries, migration from the original Bash
script, systemd ordering, and troubleshooting.

## Development

Requires Go 1.26 or newer. The only direct library dependency is
[`filippo.io/age`](https://filippo.io/age); the rest uses the standard library.

```text
cmd/secstore/          Executable entrypoint
internal/secstore/     Implementation and tests
packaging/            Native package definition and systemd unit
doc/design.md         Design and operational details
```

Build and install from source:

```sh
CGO_ENABLED=0 go build -trimpath -o secstore ./cmd/secstore
sudo install -m 0755 secstore /usr/bin/secstore
sudo install -m 0644 packaging/systemd/secstore-hydrate.service /etc/systemd/system/secstore-hydrate.service
```

Run the unit tests and vet:

```sh
go test -race ./...
go vet ./...
```

Linux mount tests use a private mount namespace and only synthetic secrets:

```sh
go test -c -o secstore.test ./internal/secstore
sudo unshare --mount --propagation private \
  env SECSTORE_MOUNT_TEST=1 ./secstore.test -test.run '^TestRuntimeIntegration$'
```

Optionally verify interoperability with an installed legacy age CLI:

```sh
SECSTORE_TEST_AGE="$(command -v age)" go test -run '^TestAgeCLICompatibility$' ./internal/secstore
```

### Build native packages

[nFPM](https://nfpm.goreleaser.com/) is a build-time tool only:

```sh
go install github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.47.0
export SECSTORE_VERSION=0.0.0-dev
export SECSTORE_ARCH=amd64
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o dist/secstore ./cmd/secstore
nfpm package --config packaging/nfpm.yaml --packager deb --target dist/
nfpm package --config packaging/nfpm.yaml --packager rpm --target dist/
```

For ARM64, set both `SECSTORE_ARCH` and `GOARCH` to `arm64`. For ARMv7, use
`SECSTORE_ARCH=arm7`, `GOARCH=arm`, and `GOARM=7`. The package architecture must
match the binary you build. Set `SECSTORE_VERSION` to the intended version;
CI uses `0.0.0-dev.<run number>` for development snapshots. Release packages
use the stable tag version without its leading `v`.

`packaging/archive.sh` creates the archive and checksum list from `dist/`.
Run it from the repository root after building both native packages, with
`SECSTORE_VERSION`, `SECSTORE_ARCH`, and `RUNNER_TEMP` (a temporary staging
directory) set.

`.github/workflows/ci.yaml` checks formatting, vet, race-enabled tests, and
real noswap mounts, then uploads static binaries and `.deb`/`.rpm` packages
for amd64, arm64, and ARMv7, alongside archives and checksums. It runs for
branch pushes and pull requests, and is reused by the release workflow.
Development snapshots remain available as CI artifacts.

## Releases

The release workflow must first be merged into `main` and included in the
commit being tagged. Choose an unused stable `vX.Y.Z` version and a reviewed
commit already in `main`. For example, to tag the fetched tip of `main`:

```sh
git fetch origin
git tag -a v1.2.3 origin/main -m "secstore v1.2.3"
git push origin refs/tags/v1.2.3
```

Both annotated and lightweight tags are supported. The
[release workflow](.github/workflows/release.yaml) rejects prerelease tags,
build metadata, leading-zero version components, commits outside `main`, and
existing releases (including drafts). Tags without the `v` prefix do not
trigger releases.

Release builds use the exact tagged commit and the same checks and packaging
as ordinary CI. Tests run on the Linux runner's native architecture; ARM
packages are cross-compiled. Native ARM execution and package
installation/lifecycle tests are not part of the release gate.

Each release includes:

- `secstore-vX.Y.Z-linux-<arch>.tar.gz`, where `<arch>` is `amd64`, `arm64`,
  or `arm7` (ARMv7).
- `secstore_X.Y.Z_<arch>.deb`, using Debian architectures `amd64`, `arm64`,
  or `armhf` (ARMv7).
- `secstore-X.Y.Z-1.<arch>.rpm`, using RPM architectures `x86_64`, `aarch64`,
  or `armv7hl` (ARMv7).
- `SHA256SUMS` covering all downloadable archives and packages.

Archives have a versioned root containing `bin/secstore`, the systemd unit
under `packaging/systemd/`, the README, design document, and license. They do
not initialize a store or install/enable a service. Native packages remain the
recommended installation method.

Download `SHA256SUMS` alongside your chosen assets and verify them on Linux:

```sh
sha256sum --check --ignore-missing SHA256SUMS
```

After all checks pass, the workflow downloads the same run's build artifacts,
verifies their exact filenames and checksums, and rechecks the tag's commit.
It creates a **draft normal release**, not a prerelease. Review the assets,
source commit, and workflow results in **Releases**, then publish manually.
The workflow never creates or moves tags, overwrites releases, or publishes
automatically. It uses the built-in `GITHUB_TOKEN`; no additional secret is
required.

### Failures and retries

Build, source, API, or asset-verification failures prevent draft creation.
Inspect the failed job's logs before retrying. Re-run failed jobs while the
original artifacts remain available; use **Re-run all jobs** if artifacts
have expired or need rebuilding so the replacement payloads pass the checks.

An existing draft or published release stops the run. A partially failed
upload can leave an incomplete draft: inspect it and remove it manually only
after review before retrying the same unchanged tag. For source fixes, merge
the fix and push a new version tag. Never move an existing release tag.
