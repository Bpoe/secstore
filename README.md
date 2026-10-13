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

## Microsoft DSC

The native DSC command resource **`Secstore/secrets`** ships with the same
executable. DEB/RPM packages install its manifest at
`/usr/bin/secstore.dsc.resource.json`, beside `/usr/bin/secstore`. DSC discovers
it through PATH; if you override `DSC_RESOURCE_PATH`, include `/usr/bin` in that
resource search path. The executable must also remain on PATH. No manual
manifest copy or separate resource package is needed after package installation.

The resource is tested with **DSC 3.3.0**. Discover it and inspect its schema:

```sh
dsc resource list Secstore/secrets
dsc resource schema --resource Secstore/secrets
```

Properties:

- `name`: required slash-separated secret name, using the existing secstore
  validation rules.
- `value`: sensitive secret string, including an empty string. Required by
  Test/Set for desired presence; optional for Get or desired absence. Object
  values, including secure-value transport envelopes, are not accepted.
- `_exist`: boolean, defaulting to true. False requests absence.
- `_inDesiredState`: read-only boolean returned by Test; null in Get/Set results.

`secstore dsc get`, `test`, and `set` each accept one JSON object on stdin.
DSC input is limited to **1 MiB of UTF-8 JSON**, including syntax and whitespace.
The existing `secstore add` remains an unlimited binary stdin stream.

Get reports existence without returning the value, and authenticates any existing
encrypted blob. Get/Test never initialize, create a lock, repair permissions, mount,
or hydrate. A missing or safely empty store is absent. Missing optional nested
name directories are also absent; damaged store structure, invalid identities,
unsafe paths, permission failures, and corrupt ciphertext are errors.

Test decrypts internally, fully verifies age authentication, and compares values.
Set performs the same comparison under its writer lock and does not rewrite
unchanged ciphertext. Set initializes a new store using the existing initialization
logic, including mounting/verifying runtime tmpfs, but **never hydrates**.
Therefore automatic initialization needs root mount privileges and tmpfs `noswap`
support. All resource operations require root, just like the existing CLI.

Setting `_exist: false` uses the existing removal behavior: it removes the
encrypted blob and any corresponding runtime copy and prunes empty parent
directories. Removing an absent secret does not initialize a missing store.
Creation and updates leave hydrated copies unchanged. Hydration remains a separate
operation; DSC does not restart services or containers.

Get emits one sanitized state object. Test/Set use DSC's `stateAndDiff` contract:
a state object followed by a JSON array of property names. Missing desired-present
secrets report `_exist` and `value`; value drift reports `value`; deletion reports
`_exist`. Compliant Test and unchanged Set return an empty array.

For example, retrieving existence requires no secret input:

```sh
printf '%s\n' '{"name":"app/db_password"}' |
  sudo dsc resource get --resource Secstore/secrets --file -
```

Use this configuration as `secrets.dsc.config.yaml`:

```yaml
$schema: https://aka.ms/dsc/schemas/v3/bundled/config/document.json
parameters:
  secretValue:
    type: string
resources:
  - name: databasePassword
    type: Secstore/secrets
    properties:
      name: app/db_password
      value: "[parameters('secretValue')]"
```

Use a plain `string` parameter for now, pending upstream DSC `secureString`
parameter handling. Do not append `.secureString` to the expression. A string
parameter does not provide DSC secure-value tagging or engine-output redaction.

Supply the parameter document through stdin from your existing trusted parameter
provider, not a literal command-line argument or environment variable:

```sh
sudo dsc config --parameters-file - test --file secrets.dsc.config.yaml
sudo dsc config --parameters-file - set --file secrets.dsc.config.yaml
```

DSC expects the stdin parameter document to have a `parameters` object containing
`secretValue` as a string. Parameter resolution, Azure Key Vault access, and scheduling belong
to DSC secret extensions and/or dscd; secstore does not implement them.

### Secret output boundary

Secstore never emits `value`, decrypted data, ciphertext, hashes, or identity
material in DSC output, and sanitizes its failures. The canonical property schemas
are bundled into the manifest so DSC does not need to fetch them at runtime.

**Do not assume engine output is secret-free.** With DSC 3.3.0, integration checks
observe that `dsc resource test` includes the supplied secret in the engine's
`desiredState.value`, despite `writeOnly: true`. `dsc config test` with the string
parameter above likewise includes it in `results[].result.desiredState.value`.
Valid resource Get/Set and config Set results do not expose it in the tested
scenarios. These exposure expectations are checked against the pinned runtime.

These checks do not guarantee redaction for other versions, malformed inputs,
verbose/debug traces, extensions, dscd, or downstream logging. Treat resolved input,
DSC results, and diagnostics as potentially secret-bearing; restrict access and
avoid logging them. dscd is not exercised by this repository's tests. Secstore
cannot provide end-to-end redaction or protection against privileged processes,
process-memory inspection, or core dumps.

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
sudo install -m 0644 secstore.dsc.resource.json /usr/bin/secstore.dsc.resource.json
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

The DSC integration suite requires DSC 3.3.0 and the binary/manifest installed
together (or staged together). It uses synthetic values and a private mount
namespace. Set absolute paths for your installation:

```sh
go test -c -o secstore.test ./internal/secstore
sudo unshare --mount --propagation private env \
  SECSTORE_TEST_DSC="$(command -v dsc)" \
  SECSTORE_TEST_BINARY=/usr/bin/secstore \
  SECSTORE_TEST_MANIFEST=/usr/bin/secstore.dsc.resource.json \
  ./secstore.test -test.run '^TestDSCIntegration$' -test.v
```

### Build native packages

[nFPM](https://nfpm.goreleaser.com/) and `jq` are build-time tools only. Stage
the manifest with the same version as the native package:

```sh
go install github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.47.0
export SECSTORE_VERSION=0.0.0-dev
export SECSTORE_ARCH=amd64
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o dist/secstore ./cmd/secstore
jq --arg version "$SECSTORE_VERSION" '.version = $version' secstore.dsc.resource.json > dist/secstore.dsc.resource.json
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
The amd64 job installs both package formats into isolated package roots and runs
DSC 3.3.0 discovery, lifecycle, and string-parameter checks against the installed
files. Development snapshots remain available as CI artifacts.

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
packages are cross-compiled. Installed-package DSC checks run on amd64; native
ARM execution and systemd/package service-lifecycle checks are not part of the
release gate.

Each release includes:

- `secstore-vX.Y.Z-linux-<arch>.tar.gz`, where `<arch>` is `amd64`, `arm64`,
  or `arm7` (ARMv7).
- `secstore_X.Y.Z_<arch>.deb`, using Debian architectures `amd64`, `arm64`,
  or `armhf` (ARMv7).
- `secstore-X.Y.Z-1.<arch>.rpm`, using RPM architectures `x86_64`, `aarch64`,
  or `armv7hl` (ARMv7).
- `SHA256SUMS` covering all downloadable archives and packages.

Archives have a versioned root containing `bin/secstore` and
`bin/secstore.dsc.resource.json`, the systemd unit under `packaging/systemd/`,
the README, design document, and license. They do
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
