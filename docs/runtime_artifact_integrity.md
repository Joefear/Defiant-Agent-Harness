# Runtime artifact and dependency-closure integrity

v0.16 closes the gap between a configured local MCP command and the bytes that
Defiant actually starts. A command string or package version identifies an
intention; it does not prove that the executable or entrypoint on disk still
contains the reviewed content.

Production stdio MCP configurations can require a SHA-256 manifest:

```yaml
server:
  name: payments
  command:
    - C:/Program Files/Python312/python.exe
    - C:/srv/payments/server.py
  artifact_integrity:
    required: true
    artifacts:
      - role: executable
        path: C:/Program Files/Python312/python.exe
        sha256: sha256:<64 lowercase hex characters>
      - role: entrypoint
        path: C:/srv/payments/server.py
        sha256: sha256:<64 lowercase hex characters>
      - role: lockfile
        path: C:/srv/payments/requirements.lock
        sha256: sha256:<64 lowercase hex characters>
tools:
  charge:
    side_effect: spend
```

v0.23 can additionally close one or more operator-declared dependency roots:

```yaml
  artifact_integrity:
    required: true
    artifacts:
      - role: executable
        path: C:/Program Files/Python312/python.exe
        sha256: sha256:<64 lowercase hex characters>
    dependency_roots:
      - path: C:/srv/payments/runtime
        files:
          - path: payments/__init__.py
            sha256: sha256:<64 lowercase hex characters>
          - path: payments/server.py
            sha256: sha256:<64 lowercase hex characters>
          - path: plugins/approved.dll
            sha256: sha256:<64 lowercase hex characters>
```

Each `dependency_roots` entry requires exactly `path` and `files`. Each file
requires exactly a canonical relative `path` and `sha256`. Relative paths use
`/`, cannot contain `.` or `..`, and cannot be absolute. Roots and manifests
must be non-empty. Unknown fields fail loading. Relative root paths resolve
against the configuration file.

v0.35 checks artifact and dependency-root collections before constructing
paths or pin objects. Each collection, including each root's `files`, is capped
at 4,096 items, and all dependency roots together may declare at most 8,192
file pins. These loader limits apply before the separate runtime inventory and
hashing work described below.

`required` must be a boolean. Artifact entries require exactly `role`, `path`,
and `sha256`; unknown fields fail loading. Roles are unique lowercase logical
names and exactly one must be `executable`. Relative artifact paths resolve
against the configuration file. Digests use the literal `sha256:` prefix and
64 lowercase hexadecimal characters.

Manifest paths must name canonical regular files, not symlinks. If a runtime
manager exposes `python`, `node`, or another command through a symlink, resolve
that link first and pin its final target; `server.command[0]` may retain the
alias because Defiant requires it to resolve to that target and then launches
the verified absolute target path.

## Startup sequence

For required local assurance, Defiant:

1. resolves every manifest path and refuses missing files, non-files, symlinks,
   malformed digests, duplicate roles, and artifacts below the mutable harness
   state directory;
2. streams each file through SHA-256 and compares it in constant time with the
   operator-authored pin;
3. resolves `server.command[0]` and requires it to identify the exact pinned
   executable;
4. canonicalizes the manifest by role and computes one bundle hash over role,
   canonical-path hash, content hash, and file size;
5. replaces the launch token with the verified absolute executable path, so
   later `PATH` ambiguity cannot select a different program;
6. binds the assurance mode, bundle hash, count, and executable-pin posture
   into the v0.15 complete authority profile and resolves durable continuity;
7. re-hashes the bundle and compares the observation immediately before the
   upstream subprocess is created.

When dependency roots are present, each verification also walks every root
without following links, requires the complete observed regular-file set to
equal the manifest, hashes every listed file, and rejects added, missing,
changed, symlinked, reparse-point, hard-linked, or special entries. Canonical roots must be
unique, non-overlapping, and disjoint from mutable harness state. Root order
and manifest order do not affect the bundle hash. A maximum of 100,000 files
and 200,000 total entries per root bounds inventory work.

No subprocess starts before both artifact verification and authority-profile
acceptance succeed. A first pinned startup records only sanitized assurance in
`runtime_artifacts.json`, under the same state-directory authority lock. Exact
restarts refresh its last-verification time. The state file contains no paths
or individual artifact digests and must match the active profile hash.

## Planned updates

A legitimate executable or declared support-file update changes the bundle and
therefore the complete authority-profile hash. The candidate runtime fails
closed until an operator reviews and stages that exact profile with the normal
v0.15 authority-profile rotation command, including explicit identity and a
non-empty note. Signed deployments also require the configured trusted-key
attestation. Only the exact candidate activates the staged generation.

Do not “fix” a mismatch by editing `runtime_artifacts.json`. That file is a
read-only diagnostic observation, not an allowlist or authority source. Update
the external manifest pins through the authenticated deployment channel and
use the explicit profile-rotation workflow.

## Read-only diagnostics

`dah doctor`, Command Core, and Command Center report whether the runtime was
`pinned`, `closed`, `unverified`, `remote_not_applicable`, invalid, or bound to a different
active profile. They may show the canonical bundle hash, count, executable-pin
posture, dependency-root and dependency-file counts, and last-verification
time. They never expose artifact or root paths, relative filenames, or
individual digests and cannot edit pins, accept drift, rotate a profile, start
an upstream, or repair state.

Streamable HTTP upstreams are marked `remote_not_applicable`: local file pins
cannot attest server bytes on another host. Local configurations that omit the
manifest remain operational for compatibility but are explicitly `unverified`;
production deployments should require pins.

Because v0.16 adds the assurance posture to MCP authority inputs, the first
v0.16 start against a v0.15 MCP state directory intentionally reports profile
drift even when pins are not yet enabled. Review the new pinned or explicitly
unverified posture and stage the exact v0.16 candidate through the existing
authority-profile rotation workflow before starting it.

## Security limits

This is content verification, not code signing, automatic dependency discovery,
or an immutable execution environment. v0.23 closes only the roots the operator
declares. Interpreters may still load libraries, native extensions,
configuration, environment-driven plugins, or dynamic code from paths outside
those roots after launch. Operators must choose roots that cover every intended
loading surface and combine this control with restricted search paths, a locked
dependency installation, least-privilege mounts, or an immutable image.

The second verification narrows but cannot eliminate the filesystem
time-of-check/time-of-use race. A privileged host attacker can replace bytes
after verification, patch the harness, alter process memory, or replace both
state and pins. Code signing, read-only images, OS policy, trusted boot, and an
external generation/hash witness are separate deployment controls.

This release adds no DKE, Spartan, remote Command, or Command Center authority.

v0.17 complements file verification with a restricted, authority-bound process
environment and working directory. See `launch_envelope_integrity.md`.
