# secstore design

This design is based on the original
[secstore setup and usage document](https://github.com/Bpoe/homelab/blob/main/scripts/secstore.md)
and its [Bash implementation](https://github.com/Bpoe/homelab/blob/main/scripts/secstore).
The Go port preserves the command interface, environment overrides, local
X25519 identity, encrypted file layout, and advisory lock. Installation and
development instructions are in the [README](../README.md).

## Goals and scope

Secstore assigns a small local vault to each Linux node. Only secrets explicitly
added to that node are stored there; the node does not need credentials for an
upstream vault. Docker Compose and other applications consume hydrated files.

Secrets are encrypted at rest and plaintext files are written only to a
non-swappable tmpfs. Hydrated files survive service restarts but disappear on
reboot. Secret values enter through stdin, never through command-line arguments.
The interface remains independent of the underlying encryption implementation.

Secstore is not a remote vault, a secret-distribution service, or a defense
against root compromise. Listing, rotation, dehydrate, and health commands are
outside the CLI and single-secret DSC resource scope.

## Implementation

`cmd/secstore` is a thin executable entrypoint. `internal/secstore` implements
command parsing, filesystem operations, encryption, locking, and Linux support
using ordinary functions and a small store struct. There are no CLI frameworks,
factories, or dependency injection frameworks.

The standard library provides configuration, streaming I/O, rooted filesystem
access through `os.Root`, and Linux mount/flock system calls. The sole direct
library dependency is [`filippo.io/age`](https://filippo.io/age), providing
maintained encryption and compatibility with existing vaults. No external age
CLI, shell, mount utility, shared library, or language runtime is needed by
the statically built executable.

Linux must support tmpfs `noswap` (upstream 6.4+, subject to distribution
backports), expose `/proc`, and grant root mounting privileges (`CAP_SYS_ADMIN`).
Non-Linux builds can display help but cannot operate a vault.

## Command behavior

```text
secstore init
secstore add --name <name>
secstore remove --name <name>
secstore hydrate
secstore dsc get
secstore dsc test
secstore dsc set
```

`init` creates the vault, generates a local age X25519 identity if it is missing,
and mounts/verifies the runtime directory. It never rotates an existing identity;
an invalid identity is reported rather than overwritten.

`add` streams plaintext from stdin directly into age encryption and atomically
replaces the encrypted blob. It does not update an already hydrated runtime copy.
Run `hydrate` to publish updates.

```sh
printf '%s' "$DB_PASSWORD" | sudo secstore add --name kea/db_password
printf '%s' "$TSIG_KEY" | ssh node1 'sudo secstore add --name bind/ddns_tsig'
sudo secstore hydrate
```

`remove` deletes the encrypted blob and its runtime copy and prunes empty parent
directories. Removing a missing name succeeds. `hydrate` decrypts every `.age`
blob and removes stale runtime files after publishing the new files.

```sh
sudo secstore remove --name kea/db_password
```

Names consist of slash-separated components matching
`[A-Za-z0-9][A-Za-z0-9._-]*`. Absolute paths, empty components (including a
trailing slash), `.`/`..`, whitespace, control characters, and symlinks are
rejected. A name cannot be both a file and a directory: for example, `app`
and `app/password` cannot be hydrated together. Remove the conflicting name
before switching layouts.

Help is available with `secstore --help` without root privileges.
Errors and progress go to stderr; failures exit with status 1.

### DSC resource boundary

`Secstore/secrets` is a native command resource using the same executable, not
a wrapper or a separate service. Its manifest embeds the JSON Schema and maps
Get/Test/Set to the three `dsc` subcommands with JSON input on stdin. Protocol
handling is separate from the legacy CLI. The schema permits name-only Get;
Test/Set enforce a required value when `_exist` is true or omitted.

The value accepts either a normal JSON string or DSC's secureString transport
object, containing exactly one `secureString` property whose value is a string.
Both forms support empty strings and are normalized to the same internal secret
string immediately. Neither form is logged or returned, and switching forms for
the same value does not rewrite ciphertext. Extra/duplicate fields, nested
objects, null, and non-string contents are rejected. Stored bytes are the UTF-8
string contents, never the transport JSON. Legacy `add` still supports arbitrary
binary stdin.

DSC input is bounded to one MiB of encoded JSON, including whitespace. Invalid
JSON, duplicate/unknown properties, trailing documents, invalid names, wrong
types, and oversized input fail before initialization or mutation. Parser and
storage errors cross a sanitized error boundary: error classification and the
failed operation remain available without echoing input, keys, or ciphertext.

Get/Test open trusted paths without creating directories, repairing permissions,
or preparing runtime. They open an existing lock without creating or chmod/chown
operations, then validate/read under the same exclusive flock used by writers.
No identity, secret directory, or lock is created to report a missing store.
An empty vault, optionally containing a lock or empty secrets directory, is
uninitialized. Orphaned data without an identity, or an initialized vault missing
its identity, secrets root, or lock, is an error. Missing optional secret-name
directories mean absence; unsafe or unreadable paths do not.

Get authenticates the requested ciphertext to EOF without returning plaintext.
Test compares desired and actual contents using streaming, in-memory SHA-256
digests and constant-time digest comparison. Authentication must finish even if
the content differs. No plaintext temporary file, digest, or secret fingerprint
is written or emitted. Process memory is not locked or guaranteed to be erased.

Set holds the same exclusive lock continuously across pretest and mutation.
It initializes only a safely new/empty store using the existing `init`, including
runtime tmpfs mounting/verification, and never replaces an existing identity.
Initialization errors are reported before a secret is added. Matching values
leave ciphertext, inode, and modification time unchanged. Changes reuse the
existing age encryption and atomic write. Desired absence reuses `remove`,
including runtime cleanup; missing stores are not initialized for deletion.
Creation/update never hydrates, and compliance does not depend on runtime copies.

Get returns only name, existence, and null `_inDesiredState`. Test returns a
boolean `_inDesiredState`; Set returns null for that read-only property.
Test/Set emit a second JSON line containing distinct differing/changed property
names: `_exist` and `value` for creation/missing desired presence, `value` for
value drift, `_exist` for deletion, or an empty array for compliance/no change.
The manifest declares `implementsPretest`, `handlesExist`, and `stateAndDiff`.

The published canonical `_exist` and `_inDesiredState` schemas are included in
`$defs` with their canonical IDs, and properties reference those IDs. DSC 3.3
does not fetch arbitrary HTTP schema references, so bundling is necessary for
offline validation. The runtime version and published schema versions differ;
the manifest uses the published, supported v3.1.0 schema rather than an invented
v3.3.0 schema URI.

The README shows a `secureString` parameter with `[parameters('secretValue')]`.
A `string` parameter uses the same expression and is equally sensitive to the
resource. DSC supplies the secureString transport object automatically; no
`.secureString` member access is needed. Integration tests cover both parameter
types, cross-form comparisons, unchanged Set behavior, and sanitized errors.

## Storage and configuration

```text
/var/lib/secstore/              0700
  identity.txt                 0600 (unencrypted private key)
  .lock                        0600
  secrets/                     0700
    kea/db_password.age         0600
    bind/ddns_tsig.age          0600

/run/secrets-store/             0700 (tmpfs, noswap)
  kea/db_password               0400 by default
  bind/ddns_tsig                0400 by default
```

Environment variables use these defaults; empty values also select the default:

```sh
SECSTORE_VAULT_DIR=/var/lib/secstore
SECSTORE_RUN_DIR=/run/secrets-store
SECSTORE_RUN_SIZE=16M
SECSTORE_FILE_MODE=0400
```

`SECSTORE_RUN_SIZE` accepts a positive byte count with an optional K/M/G/T/P or
percentage suffix supported by tmpfs. It applies when creating a mount, not
when reusing an existing one. `SECSTORE_FILE_MODE` is an octal permission mode
from `0000` to `0777`; all managed directories remain `0700`.

Vault and runtime paths must be separate, non-overlapping directory trees with
trusted, root-controlled ancestors. The runtime directory must be dedicated to
secstore: hydration removes files that have no backing blob. Symlinked paths
and nested/stacked runtime mounts are rejected. A pre-existing runtime mount
must be writable tmpfs with `noswap`; there is no fallback to disk or swappable
tmpfs. Newly created mounts also use `nosuid,nodev,noexec`.

For overrides with sudo, set them on the privileged command:

```sh
sudo env SECSTORE_FILE_MODE=0444 secstore hydrate
```

Operations on initialized stores hold an exclusive `.lock` with a 30-second
timeout. DSC can report absent, uninitialized storage without creating a lock;
Set rechecks under its writer lock before initializing. Use the same vault path
for processes sharing a runtime directory. Do not modify either tree or its
mounts while secstore is running.

### Hydration and failure behavior

All blobs are fully decrypted and authenticated into a private staging
directory **inside the verified runtime tmpfs** before any live secret is
replaced. A decryption error leaves the existing runtime files and stale files
unchanged and removes that attempt's staged plaintext.

Publishing uses an atomic rename for each file: readers do not encounter a
missing or partially written replacement. This is **not a transaction across
the whole set**; readers may observe a mix of old and new versions while
publishing, and a publication/cleanup I/O error can leave a partial update.
The error is reported and a later successful hydration converges the store.
An abrupt process termination can leave staging files, which are removed on
the next successful hydration or on reboot.

Existing file descriptors and Docker file bind mounts retain the old inode
after replacement. Recreate affected Compose containers to pick up changed
secrets; deleting a path does not revoke copies already open or mounted.

### Migrating from the Bash script

Keep the existing vault and install the Go binary at `/usr/bin/secstore`.
Move any old `/usr/local/sbin/secstore` script aside so it cannot shadow the
new executable on `PATH`. Replace the old service unit as well; an existing
`/etc/systemd/system/secstore-hydrate.service` overrides a packaged unit in
`/usr/lib/systemd/system`.

The `age-keygen`-generated `identity.txt` (one X25519 key, with optional
comments) and binary `.age` blobs are read directly; no re-encryption is needed.
The library also writes files readable by the age CLI. Encryption remains
X25519 even though newer age releases support additional identity types.

## Security boundaries

Back up the identity together with the encrypted blobs and protect that backup.
Losing the identity makes the blobs unrecoverable. Possessing both the identity
and ciphertext permits decryption: this design does not defend against root
compromise or a complete disk/backup disclosure. Plaintext runtime *files*
cannot swap, but `noswap` does not lock process memory or prevent core dumps.

The resource never returns or logs secret values, ciphertext, hashes, or identity
material. `writeOnly` describes its input contract; it is not an engine-wide
redaction guarantee. Actual DSC 3.3 integration checks show that plain-string
`dsc resource test` input appears in the engine's `desiredState.value`. Config
Test with a string parameter also exposes the value in
`results[].result.desiredState.value`. Valid resource Get/Set and config Set
results are sanitized for both input forms in the tested cases. The tested
secureString Test results redact the desired value to `<secureValue>`. The tests
explicitly distinguish engine-originated exposure from the resource's sanitized
output; accepting a normal string never authorizes the resource to reveal it.

DSC extensions or dscd resolve and supply secrets; secstore performs no Key Vault
access or upstream retrieval. These components, DSC's diagnostics/results, and
downstream logging are separate trust boundaries. Engine validation failures,
debug traces, other versions, and dscd itself are not covered by an end-to-end
redaction guarantee. Protect resolved inputs and captured output, and avoid
logging them. Tests use synthetic values and keep resolved parameter documents
in memory, supplying them to DSC through stdin.

## Docker Compose and systemd

The included service calls `/usr/bin/secstore hydrate`. Native packages install
it in `/usr/lib/systemd/system`; a source installation can install it manually:

```sh
sudo install -m 0644 packaging/systemd/secstore-hydrate.service /etc/systemd/system/secstore-hydrate.service
sudo systemctl daemon-reload
sudo systemctl enable secstore-hydrate.service
sudo systemctl start secstore-hydrate.service
```

The unit hydrates before Docker starts and sets `SECSTORE_FILE_MODE=0444`.
Standalone Compose bind-mounts file secrets and does not implement their
`uid`, `gid`, or `mode` settings. `0444` lets unprivileged container users read
explicitly mounted secrets; the root-owned `0700` host directory tree blocks
unprivileged host users from reaching them. Use a systemd override with `0400`
if all consumers can read root-only files.

```yaml
services:
  kea:
    image: iscproject/kea:latest
    secrets:
      - kea_db_password
    environment:
      KEA_DB_PASSWORD_FILE: /run/secrets/kea_db_password

secrets:
  kea_db_password:
    file: /run/secrets-store/kea/db_password
```

The image must support the indicated file-based configuration.

`WantedBy=docker.service` pulls in hydration; `Before=docker.service` provides
ordering. Like the original unit, this is a **weak dependency**: hydration
failure does not prevent Docker from starting. If that is required, add a
Docker drop-in with `Requires=secstore-hydrate.service` in its `[Unit]` section.
Stopping the oneshot unit does not erase or unmount secrets. To hydrate again
after adding secrets, run `sudo secstore hydrate` or restart the unit.

If overriding the vault path in the unit, update `RequiresMountsFor` as well.
Do not isolate the service's mount namespace: Docker must see the host mount.

## Diagnostics

```sh
findmnt /run/secrets-store
findmnt -n -o OPTIONS --target /run/secrets-store
sudo systemctl status secstore-hydrate.service
sudo journalctl -u secstore-hydrate.service
```

If mounting with `noswap` fails, check kernel support and mounting privileges.
An existing tmpfs without `noswap` is rejected even if system swap is disabled.
Do not unmount a live store while consumers use it; arrange downtime before
recreating the mount. A full tmpfs causes hydration to fail rather than spill
plaintext onto disk; provision enough space for live files and staged
replacements together.

## Native packaging

`packaging/nfpm.yaml` builds `.deb` and `.rpm` packages from the same static
binary. Packages contain the executable, DSC manifest, systemd unit, and license.
The README and design document remain in the repository. Packages do not
include vault contents or identities and declare no runtime dependencies on
Go or age.

Both package formats install `/usr/bin/secstore.dsc.resource.json` with mode
0644 and root ownership, beside the existing executable. The staged manifest's
resource version matches `SECSTORE_VERSION`. Release archives include that same
manifest in their `bin` directory. DSC discovers the manifest through PATH or a
configured `DSC_RESOURCE_PATH` containing its directory; the executable must
remain discoverable too.

Installation does not initialize a vault, mount tmpfs, enable a service, or
restart Docker. Administrators explicitly initialize and enable hydration as
shown in the README. Before uninstalling an enabled service, disable it with
`systemctl disable --now secstore-hydrate.service`. After removal, run
`systemctl daemon-reload`. Existing vault and runtime data are not package-owned
and are never deleted by package removal.

Stable `vX.Y.Z` tags on commits already in `main` invoke the same CI checks and
package builds used for development snapshots. Release package versions omit
the tag's leading `v`; ordinary branch/PR builds retain
`0.0.0-dev.<run number>`. Linux amd64, arm64, and ARMv7 packages are built from
the exact tagged commit. ARM binaries are cross-compiled, not natively tested.

Release archives additionally contain the README and this design document,
alongside the executable, systemd unit, and license in a versioned directory.
Archives do not change package installation or service-enablement behavior.

The release workflow verifies the same run's assets and SHA-256 checksums,
rechecks the remote tag's commit, and refuses existing releases, including
drafts. Only the final draft-creation job has repository-content write access.
Successful runs create drafts for manual review and publishing; they do not
publish automatically. Native amd64 CI installs both package formats into
isolated roots and runs pinned DSC 3.3.0 discovery/lifecycle and both parameter
checks against the installed files in private mount namespaces. Native ARM
execution and systemd service-lifecycle tests are not part of
this gate. See [Releases](../README.md#releases) for tag rules, asset naming,
checksum verification, and failure/retry procedures.
