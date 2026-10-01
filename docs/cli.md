# CLI reference

The `certkit` executable requires Node.js 22.15.0 or newer. Once the first beta is published, install it from npm's `beta` dist-tag with `npm install certkit@beta`.

```text
certkit [--json] [--color|--no-color] <command>

install   [--dry-run] [--json]
uninstall [--dry-run] [--json]
create <names...> [-o <existing-dir>] [--validity-days <1-825>] [--force] [--json]
status [--json] [--color|--no-color]
caroot [--json]
```

`--json` can be passed at the command level. JSON is written as one document to stdout; diagnostics and warnings go to stderr. JSON objects include `schemaVersion: 1`.
Unknown options are rejected with exit code `2` before a command runs. Put certificate names that start with `-` after `--`.

## `certkit install`

Create the CA if needed and install it in the detected supported stores for the current user. On macOS, trust is written to the current user's login keychain and macOS may show its native authentication prompt. On Linux, system store operations may need elevation; Linux browser NSS targets require `certutil`. On Windows, certkit writes only to the current user's Root store. WSL emits a warning that Windows browsers use Windows-side trust.

```sh
certkit install
certkit install --dry-run
certkit install --json
```

`--dry-run` prints planned commands and manual equivalents but does not create files, inspect by mutation, or reconcile pending writes. On a new CA directory, commands that depend on a generated CA identity are marked with symbolic paths.

JSON success shape:

```json
{"schemaVersion":1,"results":[{"store":"nss","target":"/path/to/profile","state":"trusted"}]}
```

Each store/database is reported separately. States are `trusted`, `untrusted`, `unknown`, or `not-detected`. A verified installation write may still have effective trust state `unknown`; check the `state` and `detail` fields rather than assuming command success means browser acceptance. Partial progress is retained per target and is not rolled back across stores. Rerun `certkit install` to retry unresolved work.

## `certkit uninstall`

Remove certkit's CA from detected and previously recorded trust targets, verify removal, and then remove certkit-owned CA files. The command preserves unrelated files and foreign CAs. Interrupted cleanup can be resumed by rerunning uninstall. It does not remove another tool's CA.

```sh
certkit uninstall
certkit uninstall --dry-run
certkit uninstall --json
```

A dry run prints planned removal commands. An unresolved target or failed removal retains recovery state and CA files; resolve the store problem and rerun uninstall.

## `certkit create`

Create a leaf certificate for one or more DNS names, leftmost wildcards, or IP literals. The CA is created if missing. This command does not install it.
DNS names cannot contain URL separators, percent escapes, or ASCII control characters.

```sh
certkit create localhost 127.0.0.1 ::1
certkit create '*.dev.example' -o ./certs --validity-days 30
certkit create localhost --force --json
```

`-o`/`--output` must name an existing directory. Without it, files are written to the current working directory. Default validity is 825 days; allowed values are integers from 1 through 825. Add generated PEM files to `.gitignore` before running this command.

Output names use the first name plus `+N` for additional names, for example `localhost+2.pem` and `localhost+2-key.pem`. A wildcard `*.` at the start of the first name becomes `_wildcard.`. Other filename characters are sanitized for cross-platform use.

Without `--force`, existing paths cause an error and are left unchanged. With `--force`, both destinations are checked before writing. Symbolic-link destinations are refused. If placement fails after the key file was replaced, the error identifies that partial progress. POSIX private keys are mode `0600`; Windows uses the protected CA directory and verifies ACL-preserving placement. Keep the key file private.

JSON success shape:

```json
{"schemaVersion":1,"names":["localhost","127.0.0.1"],"files":{"cert":"/work/localhost+1.pem","key":"/work/localhost+1-key.pem"}}
```

## `certkit status`

Read trust state without changing stores or creating a CA directory. It reports the CA as `null` if it has not been initialized. Each detected NSS database has its own row.

```sh
certkit status
certkit status --json
certkit status --no-color
```

Possible store states: `trusted`, `untrusted`, `unknown`, `not-detected`. `unknown` means effective trust could not be established. A pending trust write is surfaced as unknown and is not reconciled by status.

JSON shape:

```json
{"schemaVersion":1,"caDir":"/user/data/certkit","ca":null,"stores":[{"store":"windows-root","state":"not-detected"}]}
```

## `certkit caroot`

Print the resolved CA directory. This is a read-only path lookup and does not create the directory.

```sh
certkit caroot
certkit caroot --json
```

Default locations are `%LOCALAPPDATA%\\certkit` on Windows, `~/Library/Application Support/certkit` on macOS, and `${XDG_CONFIG_HOME:-~/.config}/certkit` on Linux. `$CERTKIT_HOME` overrides the platform default; library calls may also pass `caDir`.

## Exit codes and errors

| Code | Meaning |
| --- | --- |
| `0` | Command succeeded. For `status`, no detected store is `untrusted`; `unknown` and `not-detected` do not make it fail. |
| `1` | Operational failure, trust-write/removal failure, unreadable CA state, or `status` found an untrusted store. |
| `2` | Command could not run due to invalid names/options, more than 100 names, an unsupported platform/store, or an invalid output directory. |

Structured failures use `{ "schemaVersion": 1, "error": { "code", "message", "hint?" } }`. Trust commands that partially complete return per-target results and exit `1`. Key material is never included in output.
