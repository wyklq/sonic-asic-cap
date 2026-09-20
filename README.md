# sai_cap_query

`sai_cap_query` discovers what an ASIC actually exposes through SAI. It links
against `libsairedis`, so it talks to the running `syncd` over the normal SAI
Redis / ZMQ transport and asks the adapter about:

* supported object types (`SAI_SWITCH_ATTR_SUPPORTED_OBJECT_TYPE_LIST`),
* per-attribute capabilities (`sai_query_attribute_capability`),
* implemented enum values (`sai_query_attribute_enum_values_capability`),
* per-object statistics (`sai_query_stats_capability`),
* generic resource availability (`sai_object_type_get_availability`),
* live switch limits and resource counters.

## Build

The SAI **1.17.5** headers are vendored under `include/sai/` and the generated
metadata headers under `include/meta/`, so the source tree is self-contained.
Runtime libraries (`libsairedis`, `libsaimeta`, `libsaimetadata`,
`libswsscommon`, ...) are expected in `lib/`; see `build_in_mini.sh` for how
that directory is produced.

```sh
make                # build sai_cap_query
make syntax-check   # compile only, no libraries needed
make test           # pure-logic unit tests (no libraries needed)
make integration    # end-to-end tests against a fake SAI adapter
```

`make integration` needs generated SAI metadata; point `META_DIR` at a SAI
checkout containing `meta/saimetadata.c`, `meta/saimetadatautils.c` and
`meta/saiserialize.c` (see `tests/Makefile.integration`).

## Usage

```sh
# Connect to the running syncd (client mode) and dump capabilities
./sai_cap_query 0x21000000000000

# Only object types matching PORT, including rejected queries
./sai_cap_query --object PORT --include-unsupported 0x21000000000000

# Full scan, all metadata-known objects and attributes
./sai_cap_query --all 0x21000000000000

# Read-probe every known counter on a sample port/queue/IPG/switch
./sai_cap_query --probe-stats 0x21000000000000

# Falsify declared-gettable attribute claims with real GETs
./sai_cap_query --verify-attributes 0x21000000000000

# Machine-readable output (stable schema, for diffs and CI golden files)
./sai_cap_query --format json --all 0x21000000000000 > capabilities.json

# Diagnose the transport when queries fail (see Transport model below)
./sai_cap_query --debug 0x21000000000000
SAI_CAP_ENABLE_CLIENT=unset ./sai_cap_query --debug 0x21000000000000
```

### Exit codes

| code | meaning |
|------|---------|
| 0 | report produced |
| 1 | SAI initialization / transport-setup failure (including the ZMQ endpoint preflight, both roles) |
| 2 | bad command line |
| 3 | switch VID did not validate (refused to run) |

## Transport model (client vs server)

`libsairedis` serves two roles, selected by the `SAI_REDIS_ENABLE_CLIENT`
profile answer:

| role | profile answer | how operations are served |
|------|----------------|---------------------------|
| client | `SAI_REDIS_ENABLE_CLIENT=true` | requests go over the ZMQ channels (client_config.json or built-in defaults) to the sairedis server embedded in `syncd`; **requires syncd running with `-z`** (ZMQ synchronous mode) |
| server | anything else / key absent | libsairedis's default role: operations are served through the Redis channel; this is the role dozens of SONiC diagnostics used for years, and it works against a normally running (async mode) syncd |

The tool answers `true` by default (`--client`, the default) and `false` with
`--server`. If an environment only serves one of the two paths, every call on
the other path fails: a client against an async syncd fails with
`SAI_STATUS_FAILURE` on the first real operation (and
`sai_query_api_version` answers `SAI_STATUS_NOT_IMPLEMENTED`, a client-side
stub), while a server-role lookup of a switch object absent from the ASIC view
fails with `SAI_STATUS_ITEM_NOT_FOUND`. A client-mode run without
`--client-config` now preflights the built-in ZMQ endpoints before
initializing (see *Debugging the transport*), so the common mistake fails in
milliseconds instead of after the 60 s response timeout.

Builds before `--client` support existed answered **nothing** for
`SAI_REDIS_ENABLE_CLIENT`, so libsairedis always applied its own default (the
server role above). A box that only serves the Redis channel therefore worked
with those builds and refuses to report with the client default.

### Debugging the transport

* `--debug` prints, to stderr, the resolved transport, every
  `SAI_REDIS_KEY_*` answer the profile gives libsairedis, and wall-clock
  timings around `sai_api_initialize`, `sai_query_api_version` and the switch
  VID validation GET. An instant failure points at the transport, a long wait
  points at a response that never arrived.
* `SAI_CAP_ENABLE_CLIENT=true|false|unset` overrides the `ENABLE_CLIENT`
  answer for one run; `unset` (also `none`/`absent`) answers `nullptr`,
  reproducing the pre-`--client` builds exactly. This is the bisect knob for
  "which role does this box actually serve".
* Before `sai_api_initialize`, the run preflights the built-in ZMQ
  endpoints (the role decides which pair matters — see
  *Containers and namespaces* below):
  * client mode (no `--client-config`) needs a **live** sairedis server
    endpoint to connect to. It checks `ipc:///tmp/saiServer` +
    `ipc:///tmp/saiServerNtf` (the `client_config.json` defaults) and
    `ipc:///tmp/zmq_ep` + `ipc:///tmp/zmq_ntf_ep` (the
    `SAI_REDIS_COMMUNICATION_MODE_ZMQ_SYNC` defaults). A missing — or
    present-but-stale — endpoint exits 1 immediately with the fixes (run
    `syncd -z zmq_sync`, use the Redis channel via
    `SAI_CAP_ENABLE_CLIENT=false` / `--server`, or point elsewhere with
    `--client-config`) instead of hanging until the 60 s response
    timeout.
  * server mode (no `--server-config` / `--context-config`) BINDS the
    endpoint, so a missing one is the normal Redis-channel path. A file
    that already exists there does **not** stop the run: libzmq's ipc
    listener unlinks the path before `bind(2)`, so the socket file left
    behind by a process that died without cleanup (an earlier `syncd -z`,
    or an earlier run of this tool) simply disappears. The preflight only
    emits a WARNING naming who owned it. The case that does matter is an
    endpoint something is *still listening on* — a live `syncd -z` server,
    for instance, whose endpoint this run would silently steal; the
    warning then names the owning pid and points back at client mode
    (or `rm -f` on both endpoints if that server is already gone).
  * `SAI_CAP_ZMQ_PRECHECK=0` skips the preflight to observe the raw
    wait-and-fail behaviour.
* Exit code 3 (the switch VID did not validate) now prints the on-switch
  triage commands: whether the object is in the ASIC view, whether syncd
  serves ZMQ, and whether the client endpoints exist.

### Containers and namespaces (SONiC / docker)

SONiC runs every service, `syncd` and the redis database included, in its
own docker container, and **ZMQ `ipc://` endpoints are UNIX socket files in
the namespaces of the process that created them**. A tool running on the
host, or inside a different container, therefore cannot see `syncd`'s
endpoints — the same holds for `tcp://` endpoints, which live in the
network namespace. Options, in order of preference:

1. **Run the tool inside the container that owns the endpoints.** For the
   client role that is the container running `syncd -z`; for the
   Redis-channel (server) role it just needs to reach the redis database,
   i.e. the same network namespace as the database (or its published
   port):
   ```sh
   docker exec <container> /path/to/sai_cap_query --server <VID>
   ```
2. **Share the namespace instead of placing the tool in it**:
   `docker run --network container:<container> --ipc container:<container>
   ...` gives the tool both the redis socket/port and the ZMQ endpoints.
3. **Relocate the endpoint** so it lives somewhere the tool can reach:
   mount the directory holding the socket into the tool's container, or
   publish the endpoint (a `tcp://` one needs the port published) and point
   the tool at it with `--client-config` / `--server-config` /
   `--context-config`. The preflight skips the built-in defaults whenever a
   config file is supplied, precisely because the defaults then say
   nothing about the real endpoints.

Note that client mode additionally requires `syncd` to run in synchronous
ZMQ mode at all — watch the flag: **`-s` is only the deprecated alias for
`redis_sync`**, which exposes no ZMQ endpoint; the real switch is
`syncd -z zmq_sync`. A stock `syncd` (async, or `-s` redis_sync) exposes
no sairedis server, in any namespace, and the Redis-channel path
(`--server`) is the one that matches a normally running switch. A bare
`/tmp/saiServer` socket file with nothing listening is therefore not
evidence of a ZMQ server — it is a leftover from a process that died
without cleanup (possibly an earlier run of this tool).

## Machine-readable output

`--format json` emits a single JSON document on **stdout**; the human-readable
banner and warnings move to **stderr**, so `> capabilities.json` captures only
valid JSON. The document is byte-stable across runs on an unchanged system,
which makes it usable for diffs and golden-file regression tests.

Top-level keys (`schema_version` is currently `1`):

| key | contents |
|-----|----------|
| `tool`, `schema_version`, `compiled_sai_version`, `linked_metadata_version` | provenance |
| `switch_vid`, `transport`, `object_filter`, `all`, `include_unsupported`, `probe_stats`, `verify_attributes` | request echo |
| `supported_object_types` | `authoritative` flag plus each advertised type, whether it is known to the local metadata, and whether it is experimental/vendor-custom |
| `switch_attributes` | read-only switch attributes only (a GET is meaningless on create/set-only attributes, which the text report also excludes): per-attribute `result` bucket (`ok` / `skipped_by_tool` / normalized failure) and value |
| `attribute_capabilities` | per attribute: `asic_supported`, `queried`, `conditional`, `valid_only`, `deprecated`; when `queried` is true also `status` and `create/set/get_implemented`. An object type the adapter's `SUPPORTED_OBJECT_TYPE_LIST` excludes is reported from metadata only (`queried: false`, plus `verdict`), with no per-attribute capability round trip — same policy as the text scan |
| `statistics_capabilities` | per object type: `counters` with `modes`, plus nested `stream_telemetry` with `minimal_polling_interval_ns` |
| `resource_availability` | per object type: `status` and `available` |

Unlike the text report, JSON mode does **not** truncate or cap anything:
consumers are expected to filter, and silently dropping data would be worse
than a large document. `--probe-stats` and `--verify-attributes` are
line-oriented and are reported (on stderr) as excluded from JSON mode rather
than being silently omitted.

Flag interactions with JSON mode:

| combination | behavior |
|-------------|----------|
| `--list-switches --format json` | rejected as a usage error (exit 2): the switch description is a human-readable line, not a JSON document, and silently dropping the flag would produce a misleading document |
| `--include-unsupported --format json` | accepted, but inert: that flag only filters the text report, while the JSON sweeps already report every attribute of every scanned type with its status. It is echoed in the options section and a note is printed on stderr |
| `--probe-stats` / `--verify-attributes --format json` | accepted and ignored: their line-oriented output would corrupt the single-document-on-stdout contract, so a stderr warning says so |

JSON mode follows the text report's cost model: without `--all` or
`--object`, the object-type sweeps (`statistics_capabilities`,
`resource_availability`) are restricted to the same focused type lists the
text report uses, and `attribute_capabilities` skips object types the
authoritative supported list excludes.

## P1 coverage

P1 extends what the tool can actually observe and verify:

* **Stream-telemetry statistics** — queries `sai_query_stats_st_capability`
  and reports the minimal polling interval per counter. `NOT_IMPLEMENTED` is a
  normal answer for adapters that do not expose this API.
* **Discriminator-based availability** — `sai_object_type_get_availability` is
  now also queried with resource-type attributes (for example
  `SAI_NEXT_HOP_ATTR_TYPE`, `SAI_ACL_TABLE_ATTR_STAGE`), which the plain
  `attr_count = 0` query cannot reach. Each documented enum value is probed.
* **Counter cross-validation** — `--probe-stats` no longer just reads counters;
  it compares each read against the `stat_modes` the adapter *declared*. A
  counter declared `READ`-capable that fails to read is reported as a
  **CONTRADICTION**, turning the capability report from a claim into a test.
* **stat_modes validation** — port counters are re-read through
  `get_port_stats_ext` under the declared mode, so an inflated `stat_modes`
  bitmask is falsifiable. Only `READ` is exercised by default because the other
  modes mutate counters; `--allow-clear` opts into `READ_AND_CLEAR`.
* **Switch-level counters** — the live probe now also covers
  `SAI_OBJECT_TYPE_SWITCH`, not just port/queue/IPG.
* **Attribute capability verification** — `--verify-attributes` performs a
  real GET for every attribute the adapter declared `get_implemented`, on a
  live switch and port, and reports any claim it cannot substantiate as a
  **CONTRADICTION**. Output is capped at 50 lines per object type while counts
  stay exact. Only SWITCH and PORT can be sampled; other object types are
  reported as not verified rather than silently assumed to be fine.
* **Condition evaluation** — conditional and valid-only attributes are no
  longer written off as unverifiable. The tool reads the attributes their
  conditions depend on and evaluates them with the SAI metadata condition
  evaluator (`sai_metadata_is_condition_met` / `sai_metadata_is_validonly_met`),
  so an attribute whose condition is actually **met** becomes a real
  contradiction when it fails to read. The result is deliberately
  conservative:
  - `condition_met` → a failed GET is a CONTRADICTION;
  - `condition_not_met` → the attribute is legitimately absent, UNVERIFIABLE;
  - `condition_unknown` (a referenced attribute could not be read, or uses a
    value type the evaluator cannot compare) → UNVERIFIABLE.

  An unevaluated condition is never promoted to a contradiction. The report
  prints the met/not-met/unknown counts plus that policy.

### APIs that cannot be used over libsairedis

`libsairedis`' `stub.pl` explicitly returns `NOT_IMPLEMENTED` for
`sai_get_object_count`, `sai_get_object_key`,
`sai_get_maximum_attribute_count`, `sai_bulk_get_attribute`,
`sai_bulk_object_get_stats` and `sai_query_object_stage`, and `syncd`'s
`VendorSai` registers the first three as `nullptr`. They are therefore **not**
queried by this tool: calling them would report a transport limitation as if it
were an ASIC capability.

## P0 hardening

Earlier revisions could produce convincing but wrong reports. The current
version addresses the highest-risk problems:

1. **Client mode by default.** libsairedis decides client vs. server from the
   `SAI_REDIS_ENABLE_CLIENT` profile key. The old tool always returned
   `nullptr`, so it became a *server* and tried to `zmq_bind` the endpoint
   `syncd` already owned — which throws. `--server` now opts in explicitly and
   is only appropriate when `syncd` is stopped.

2. **No unhandled exceptions.** libsairedis throws on malformed or unexpected
   responses. Every SAI call is now wrapped in `try`/`catch`.

3. **Switch VID validation.** A wrong, expired, or wrong-context VID makes every
   sairedis query fail with `INVALID_OBJECT_ID`; the old tool then printed a
   full report that read as "the ASIC supports nothing". The VID is now
   validated against the live switch before any capability query, and the tool
   exits with code 3 if it does not validate.

4. **Skip vs. failure separation.** Attributes whose value types cannot be
   probed generically are counted as `skipped_by_tool`, never as adapter
   failures.

5. **Status-code normalization.** Vendors return
   `SAI_STATUS_ATTR_NOT_SUPPORTED_0 + index` and similar range codes. These are
   now collapsed into one bucket per range (see the note below), so the summary
   is meaningful instead of containing thousands of distinct keys.

6. **Authoritative object-type filter.** When the adapter publishes
   `SAI_SWITCH_ATTR_SUPPORTED_OBJECT_TYPE_LIST`, object types absent from it are
   reported as `asic_unsupported` and are not probed further. Without the list,
   verdicts are reported as `unknown` rather than silently implying support.

### A caveat about the SAI status macros

On non-Windows builds `SAI_STATUS_CODE(x)` is `(-x)`, so every failure status is
a small negative `int`. The SAI `SAI_STATUS_IS_*` range macros compare
`(x & ~0xFFFF)`, which is `0xFFFF0000` for all of `-1 .. -0xFFFF`. This makes
`SAI_STATUS_IS_INVALID_ATTRIBUTE()` return true for unrelated codes such as
`SAI_STATUS_NOT_SUPPORTED` or `SAI_STATUS_BUFFER_OVERFLOW`. `cap_logic.h`
therefore does **not** use those macros; it matches plain statuses first and
classifies range codes by the high 16 bits of the raw value.

## Scope and limitations

* Metadata is compiled into the tool from the vendored SAI 1.17.5 headers.
  Vendor-private attributes/enums/stats that are not in those headers cannot
  appear in the report; this is reported explicitly in the output.
* `sai_query_attribute_capability` answers are treated as *declarations*, not
  proof. Many vendors answer without touching hardware.
* `--probe-stats` samples one object per type and never uses
  `READ_AND_CLEAR`.
* `sai_object_type_get_availability` is queried with `attr_count = 0`, so
  resource variants that need a discriminator (for example ACL stage) can
  report `NOT_SUPPORTED` even when supported. This is called out in the output.

## Tests

* `tests/test_cap_logic.cpp` — unit tests for status normalization, enum/stat
  classification, value-type predicates, and skip/failure separation.
* `tests/test_integration.cpp` + `tests/fake_sai.cpp` — end-to-end tests that
  run the real tool against an adversarial fake adapter to verify VID
  validation, status normalization, and the supported-object-type verdict.

## Vendored header provenance

`include/sai/` and `include/meta/` come from the Open Compute Project SAI
repository, tag **v1.17.5**. The metadata sources in `include/meta/` were
generated with:

```sh
cd SAI/meta
doxygen Doxyfile
./attrversion.sh
perl -I. parse.pl -A     # -A disables the optional aspell pass
```

Only the generated headers are vendored; `saimetadata.c` is expected from the
SAI checkout at test time (`META_DIR`).
