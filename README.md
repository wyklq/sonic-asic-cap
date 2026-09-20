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
```

### Exit codes

| code | meaning |
|------|---------|
| 0 | report produced |
| 1 | SAI initialization / query-setup failure |
| 2 | bad command line |
| 3 | switch VID did not validate (refused to run) |

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
| `attribute_capabilities` | per attribute: `asic_supported`, `create/set/get_implemented`, `conditional`, `valid_only`, `deprecated` |
| `statistics_capabilities` | per object type: `counters` with `modes`, plus nested `stream_telemetry` with `minimal_polling_interval_ns` |
| `resource_availability` | per object type: `status` and `available` |

Unlike the text report, JSON mode does **not** truncate or cap anything:
consumers are expected to filter, and silently dropping data would be worse
than a large document. `--probe-stats` and `--verify-attributes` are
line-oriented and are reported (on stderr) as excluded from JSON mode rather
than being silently omitted.

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
