# Launch-envelope integrity

v0.17 closes the ambient-process gap beside v0.16 artifact verification. The
same reviewed executable bytes can load different code or behave differently
when `PYTHONPATH`, `LD_PRELOAD`, `NODE_OPTIONS`, `PATH`, a shell startup hook,
or the working directory changes.

Production stdio MCP configurations can opt into a restricted launch envelope:

```yaml
server:
  name: payments
  command: [C:/srv/runtime/python.exe, C:/srv/payments/server.py]
  cwd: C:/srv/payments
  launch_environment:
    inherit: [SystemRoot, TEMP]
    secret_env: [PAYMENTS_API_TOKEN]
    set:
      NODE_ENV: production
      TZ: UTC
    allow_unsafe: []
tools:
  charge:
    side_effect: spend
```

`launch_environment` is valid only for a local `server.command`. Its four
fields are optional but strict: `inherit`, `secret_env`, and `allow_unsafe` are
lists of variable names; `set` maps names to literal string values. Unknown
fields, nonstrings, NUL characters, duplicate or case-conflicting names, and a
name supplied by more than one source fail configuration loading.

v0.35 caps each of the four collections at 4,096 items and their supplied
entries at 4,096 in aggregate before variable validation, sorting, working-
directory resolution, or process construction. Duplicate and conflicting
names count as supplied before the existing strict validation refuses them.

The presence of this block enables restricted mode and requires an explicit
`server.cwd`. Defiant resolves that directory before authority-profile
resolution, refuses a missing, nondirectory, symlinked, or harness-state path,
passes the canonical path explicitly to the child, and checks its filesystem
identity again immediately before process creation.

## Environment sources

- `set` supplies an operator-authored literal value.
- `inherit` requires the named parent variable and copies its current value.
- `secret_env` also requires a non-empty parent value and copies it, but treats
  the value as a rotatable secret.
- Every other ambient variable is absent from the child environment.

The child environment is constructed from an empty mapping. Defiant never
merges these declarations back into the complete parent environment. This
prevents an unreviewed variable from surviving merely because a launcher,
terminal profile, CI worker, package manager, or compromised parent added it.

Nonsecret literal and inherited values are hashed in a canonical name-sorted
manifest. The resulting environment hash, variable count, secret count,
unsafe-variable count, mode, and canonical working-directory hash enter the
complete authority profile. A changed nonsecret value therefore needs the
normal explicit v0.15 profile rotation before any subprocess starts.

Secret values are copied only into the private `Popen` environment. Their names
and presence affect the canonical manifest, but their values do not enter the
environment hash, durable profile, state observation, logs, Command Core, or
Command Center. This permits credential rotation without publishing a
dictionary-attackable value hash or changing the reviewed launch policy. It
also means v0.17 does not detect substitution of one present secret value for
another; secret authenticity remains the provider's responsibility.

## Unsafe variables

Restricted mode classifies common loader, runtime, shell, and path controls as
unsafe, including `PATH`, `PYTHONPATH`, `PYTHONHOME`, `LD_PRELOAD`,
`LD_LIBRARY_PATH`, `DYLD_*`, `NODE_OPTIONS`, `NODE_PATH`, `CLASSPATH`,
Java, Ruby, Perl, and shell startup controls, proxy and TLS trust overrides, and
PowerShell module paths. Merely placing one in `inherit`, `secret_env`, or `set`
is not enough. Its exact name must also appear in `allow_unsafe`.

`allow_unsafe` is an acknowledgement, not a bypass around profile continuity.
The variable must already have one declared source, nonsecret values remain
hash-bound, and diagnostics expose the unsafe count. A safe variable cannot be
placed in the acknowledgement list to make review output noisy.

Prefer absolute child-tool paths and installed dependency closures over
allowing `PATH` or loader variables. On Windows, explicitly inherit platform
variables such as `SystemRoot` when the runtime requires them.

## Startup and recovery ordering

Defiant builds the effective environment and resolves the working directory
before constructing the harness. Their sanitized assurance is included in the
MCP server fingerprint and authority inputs. Under `authority.lock`, exact
profile continuity is resolved and `launch_envelope.json` is atomically
recorded before operational recovery. Immediately before spawn Defiant
re-verifies the v0.16 artifact bundle and the working-directory identity.

No upstream subprocess starts after a missing variable, unsafe-variable
violation, invalid directory, artifact failure, profile mismatch, state lock,
or conflicting assurance observation. A crash after profile activation but
before the observation write is conservatively recoverable by the exact same
verified candidate under the authority lock.

Because v0.17 adds launch posture to MCP authority inputs, the first v0.17
start against a v0.16 MCP state directory intentionally reports profile drift.
Review either the new restricted contract or the explicitly unrestricted
compatibility posture and stage that exact candidate through the existing
authority-profile rotation workflow.

## Read-only diagnostics and limits

`dah doctor`, Command Core, and Command Center show only mode, profile binding,
environment and working-directory hashes, counts, and last verification time.
They never expose names, values, secrets, or paths and cannot edit the
environment, acknowledge unsafe variables, rotate authority, start a process,
or repair state. Streamable HTTP upstreams are `remote_not_applicable` because
the remote server's process belongs to another host.

Configurations without `launch_environment` remain compatible and are labeled
`inherited_unrestricted`. Defiant snapshots that inherited mapping for the
child and captures an explicit canonical cwd, but does not claim value-level
environment assurance. Production local upstreams should use restricted mode.

This is process-input hardening, not an OS sandbox or complete dependency
attestation. A launched program can mutate its own environment, read config or
code from declared writable locations, invoke another process, access the
network, or load dependencies through mechanisms not controlled by environment
variables. A privileged host attacker can patch memory or replace the directory
after the final check. Use immutable deployments, least-privilege identities,
filesystem and network policy, and v0.16 artifact manifests as complementary
controls.

This release adds no DKE, Spartan, remote Command, or Command Center authority.
