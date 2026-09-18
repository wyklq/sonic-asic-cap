/*
 * Unit tests for cap_logic.h.
 *
 * These tests exercise the pure classification/formatting helpers used by
 * sai_cap_query. They need no ASIC, redis, libsairedis, or test framework.
 *
 * Build/run:
 *     make -C tests test
 */

#include "../include/cap_logic.h"

#include <cstdio>
#include <string>

namespace {

int g_failures = 0;
int g_checks = 0;

void
expect_eq(const std::string &actual, const std::string &expected, const char *what)
{
    ++g_checks;
    if (actual != expected) {
        ++g_failures;
        std::printf(
            "FAIL %-52s expected='%s' actual='%s'\n",
            what,
            expected.c_str(),
            actual.c_str());
    } else {
        std::printf("ok   %-52s -> %s\n", what, actual.c_str());
    }
}

void
expect_true(bool value, const char *what)
{
    ++g_checks;
    if (!value) {
        ++g_failures;
        std::printf("FAIL %-52s expected=true\n", what);
    } else {
        std::printf("ok   %-52s -> true\n", what);
    }
}

void
expect_false(bool value, const char *what)
{
    ++g_checks;
    if (value) {
        ++g_failures;
        std::printf("FAIL %-52s expected=false\n", what);
    } else {
        std::printf("ok   %-52s -> false\n", what);
    }
}

void
expect_eq_int(long actual, long expected, const char *what)
{
    ++g_checks;
    if (actual != expected) {
        ++g_failures;
        std::printf(
            "FAIL %-52s expected=%ld actual=%ld\n",
            what,
            expected,
            actual);
    } else {
        std::printf("ok   %-52s -> %ld\n", what, actual);
    }
}

/* ------------------------------------------------------------------ */
/* status normalization                                                */
/* ------------------------------------------------------------------ */

void
test_status_classification()
{
    expect_eq(cap::classify_status(SAI_STATUS_SUCCESS), "SUCCESS",
        "success maps to SUCCESS");
    expect_eq(cap::classify_status(SAI_STATUS_NOT_SUPPORTED), "NOT_SUPPORTED",
        "plain NOT_SUPPORTED");
    expect_eq(cap::classify_status(SAI_STATUS_NOT_IMPLEMENTED), "NOT_IMPLEMENTED",
        "plain NOT_IMPLEMENTED");
    expect_eq(cap::classify_status(SAI_STATUS_INVALID_OBJECT_ID),
        "INVALID_OBJECT_ID", "invalid object id");

    /*
     * The whole point of classify_status: a vendor returning the range code
     * with an attribute index must collapse to one semantic bucket. The test
     * composes the index the same way a vendor does: by OR-ing it into the
     * low bits of the code, not by arithmetic on the (negative) value.
     */
    expect_eq(
        cap::classify_status(SAI_STATUS_ATTR_NOT_SUPPORTED_0),
        "ATTR_NOT_SUPPORTED",
        "ATTR_NOT_SUPPORTED_0 collapses");
    expect_eq(
        cap::classify_status((sai_status_t)(
            cap::status_raw_code(SAI_STATUS_ATTR_NOT_SUPPORTED_0) | 1234u)),
        "ATTR_NOT_SUPPORTED",
        "ATTR_NOT_SUPPORTED_0 | attr index collapses");
    expect_eq(
        cap::classify_status((sai_status_t)(
            cap::status_raw_code(SAI_STATUS_ATTR_NOT_IMPLEMENTED_0) | 7u)),
        "ATTR_NOT_IMPLEMENTED",
        "ATTR_NOT_IMPLEMENTED_0 | attr index collapses");
    expect_eq(
        cap::classify_status((sai_status_t)(
            cap::status_raw_code(SAI_STATUS_INVALID_ATTR_VALUE_0) | 3u)),
        "INVALID_ATTR_VALUE",
        "INVALID_ATTR_VALUE_0 | attr index collapses");
    expect_eq(
        cap::classify_status((sai_status_t)(
            cap::status_raw_code(SAI_STATUS_INVALID_ATTRIBUTE_0) | 9u)),
        "INVALID_ATTRIBUTE",
        "INVALID_ATTRIBUTE_0 | attr index collapses");
    expect_eq(
        cap::classify_status(SAI_STATUS_UNKNOWN_ATTRIBUTE_0),
        "UNKNOWN_ATTRIBUTE",
        "UNKNOWN_ATTRIBUTE_0 has its own bucket");

    /*
     * The same range bases under the positive (Windows) encoding must map to
     * the same buckets, so the classifier is not POSIX-specific.
     */
    expect_eq(cap::classify_status(SAI_STATUS_CODE(0x00050000L)),
        "ATTR_NOT_SUPPORTED", "positive ATTR_NOT_SUPPORTED base");
    expect_eq(cap::classify_status(SAI_STATUS_CODE(0x00040000L)),
        "UNKNOWN_ATTRIBUTE", "positive UNKNOWN_ATTRIBUTE base");
    expect_eq(cap::classify_status(SAI_STATUS_CODE(0x00030000L)),
        "ATTR_NOT_IMPLEMENTED", "positive ATTR_NOT_IMPLEMENTED base");
    expect_eq(cap::classify_status(SAI_STATUS_CODE(0x00020000L)),
        "INVALID_ATTR_VALUE", "positive INVALID_ATTR_VALUE base");
    expect_eq(cap::classify_status(SAI_STATUS_CODE(0x00010000L)),
        "INVALID_ATTRIBUTE", "positive INVALID_ATTRIBUTE base");

    /* BUFFER_OVERFLOW must remain visible, not be folded into a range. */
    expect_eq(cap::classify_status(SAI_STATUS_BUFFER_OVERFLOW),
        "BUFFER_OVERFLOW", "buffer overflow preserved");

    /* An unrecognized code must not be mislabelled as a known bucket. */
    expect_eq(cap::classify_status(SAI_STATUS_FAILURE), "FAILURE",
        "generic failure");
    expect_eq(cap::classify_status(SAI_STATUS_CODE(0x7fffffff)), "OTHER",
        "unknown status -> OTHER");
}

/* ------------------------------------------------------------------ */
/* enum value classification                                           */
/* ------------------------------------------------------------------ */

void
test_unknown_value_classification()
{
    expect_eq(cap::classify_unknown_value(0x00000001), "UNKNOWN_VALUE",
        "small value is UNKNOWN_VALUE");
    expect_eq(cap::classify_unknown_value(0x10000000), "UNKNOWN_CUSTOM_RANGE",
        "custom range start");
    expect_eq(cap::classify_unknown_value(0x1fffffff), "UNKNOWN_CUSTOM_RANGE",
        "custom range end");
    expect_eq(cap::classify_unknown_value(0x20000000), "UNKNOWN_EXTENSION_RANGE",
        "extension range start");
    expect_eq(cap::classify_unknown_value(0x2fffffff), "UNKNOWN_EXTENSION_RANGE",
        "extension range end");
    expect_eq(cap::classify_unknown_value(0x30000000), "UNKNOWN_VALUE",
        "above extension range is UNKNOWN_VALUE");
    /* -1 must be treated as an unsigned high value, not a small one. */
    expect_eq(cap::classify_unknown_value(-1), "UNKNOWN_VALUE",
        "negative value does not alias a range");
}

/* ------------------------------------------------------------------ */
/* stats modes                                                         */
/* ------------------------------------------------------------------ */

void
test_stats_modes()
{
    expect_eq(cap::format_stats_modes(SAI_STATS_MODE_READ), "READ",
        "READ only");
    expect_eq(
        cap::format_stats_modes(SAI_STATS_MODE_READ_AND_CLEAR),
        "READ_AND_CLEAR", "READ_AND_CLEAR only");
    expect_eq(
        cap::format_stats_modes(
            SAI_STATS_MODE_READ | SAI_STATS_MODE_BULK_READ),
        "READ|BULK_READ",
        "READ plus BULK_READ");

    /* Zero means "not reported", never "no modes". */
    expect_eq(cap::format_stats_modes(0), "UNREPORTED(0x0)",
        "zero modes reported as UNREPORTED");

    /* Unknown high bits must be surfaced rather than silently dropped. */
    expect_true(
        cap::format_stats_modes(SAI_STATS_MODE_READ | 0x100).find(
            "UNKNOWN(0x100)") != std::string::npos,
        "unknown mode bit is reported");
}

/* ------------------------------------------------------------------ */
/* version formatting                                                  */
/* ------------------------------------------------------------------ */

void
test_api_version()
{
    expect_eq(cap::format_api_version(SAI_VERSION(1, 17, 5)),
        "1.17.5 (11705)", "1.17.5 formatting");
    expect_eq(cap::format_api_version(SAI_VERSION(1, 7, 0)),
        "1.7.0 (10700)", "minor < 10 formatting");
    expect_eq(cap::format_api_version(SAI_VERSION(10, 2, 3)),
        "10.2.3 (100203)", "major > 9 formatting");
}

/* ------------------------------------------------------------------ */
/* object filter                                                       */
/* ------------------------------------------------------------------ */

void
test_object_filter()
{
    expect_true(cap::object_name_matches("SAI_OBJECT_TYPE_PORT", ""),
        "empty filter matches anything");
    expect_true(cap::object_name_matches("SAI_OBJECT_TYPE_PORT", "PORT"),
        "exact-ish substring matches");
    expect_true(cap::object_name_matches("SAI_OBJECT_TYPE_PORT", "port"),
        "filter is case-insensitive");
    expect_true(
        cap::object_name_matches("SAI_OBJECT_TYPE_PORT", "object_type_p"),
        "lowercase substring matches");
    expect_false(cap::object_name_matches("SAI_OBJECT_TYPE_PORT", "QUEUE"),
        "non-matching filter");
    expect_false(cap::object_name_matches(nullptr, "PORT"),
        "null object name does not crash");
}

/* ------------------------------------------------------------------ */
/* stat markers                                                        */
/* ------------------------------------------------------------------ */

void
test_stat_markers()
{
    expect_true(
        cap::is_stat_marker_name("SAI_PORT_STAT_CUSTOM_RANGE_BASE"),
        "custom range base is a marker");
    expect_true(
        cap::is_stat_marker_name("SAI_PORT_STAT_EXTENSIONS_RANGE_BASE"),
        "extension range base is a marker");
    /*
     * This was a real false-positive in the original tool: the PRBS lane range
     * base is a marker but lacks the _CUSTOM_RANGE_ / _EXTENSIONS_RANGE_ text.
     */
    expect_true(
        cap::is_stat_marker_name(
            "SAI_PORT_STAT_PRBS_ERROR_COUNT_LANE_RANGE_BASE"),
        "generic _RANGE_BASE is a marker");
    expect_true(
        cap::is_stat_marker_name("SAI_PORT_STAT_IN_DROP_REASON_RANGE_END"),
        "generic _RANGE_END is a marker");
    expect_true(cap::is_stat_marker_name("FOO_START"),
        "_START suffix is a marker");
    expect_true(cap::is_stat_marker_name("BAR_END"),
        "_END suffix is a marker");

    expect_false(
        cap::is_stat_marker_name("SAI_PORT_STAT_IN_OCTETS"),
        "a real counter is not a marker");
    expect_false(
        cap::is_stat_marker_name("SAI_PORT_STAT_IF_IN_ERRORS"),
        "another real counter is not a marker");
    /*
     * "RANGE" appearing inside a normal word must not trip the marker check.
     */
    expect_false(
        cap::is_stat_marker_name("SAI_PORT_STAT_ORANGE_PACKETS"),
        "substring 'RANGE' inside a word is not a marker");
}

/* ------------------------------------------------------------------ */
/* value type predicates                                               */
/* ------------------------------------------------------------------ */

void
test_value_type_predicates()
{
    /* List types must be fetchable via the count/overflow dance. */
    expect_true(
        cap::is_buffered_value_type(SAI_ATTR_VALUE_TYPE_OBJECT_LIST),
        "object list is buffered");
    expect_true(
        cap::is_buffered_value_type(SAI_ATTR_VALUE_TYPE_UINT16_LIST),
        "uint16 list is buffered (regression: was skipped)");
    expect_true(
        cap::is_buffered_value_type(SAI_ATTR_VALUE_TYPE_MAP_LIST),
        "map list is buffered (regression: was skipped)");
    expect_true(
        cap::is_buffered_value_type(SAI_ATTR_VALUE_TYPE_TLV_LIST),
        "tlv list is buffered (regression: was skipped)");
    expect_true(
        cap::is_buffered_value_type(SAI_ATTR_VALUE_TYPE_SEGMENT_LIST),
        "segment list is buffered (regression: was skipped)");
    expect_false(
        cap::is_buffered_value_type(SAI_ATTR_VALUE_TYPE_BOOL),
        "bool is not buffered");
    expect_false(
        cap::is_buffered_value_type(SAI_ATTR_VALUE_TYPE_UINT32),
        "uint32 is not buffered");

    /* Pointer and opaque per-lane lists must be reported as skipped. */
    expect_false(
        cap::can_fetch_value_type(SAI_ATTR_VALUE_TYPE_POINTER),
        "pointer cannot be fetched");
    expect_false(
        cap::can_fetch_value_type(SAI_ATTR_VALUE_TYPE_PORT_EYE_VALUES_LIST),
        "port eye values cannot be fetched");
    expect_true(
        cap::can_fetch_value_type(SAI_ATTR_VALUE_TYPE_BOOL),
        "bool can be fetched");
    expect_true(
        cap::can_fetch_value_type(SAI_ATTR_VALUE_TYPE_UINT16_LIST),
        "uint16 list can be fetched");
    expect_true(
        cap::can_fetch_value_type(SAI_ATTR_VALUE_TYPE_MAP_LIST),
        "map list can be fetched");
}

/* ------------------------------------------------------------------ */
/* skip vs failure separation                                          */
/* ------------------------------------------------------------------ */

void
test_summary_bucket()
{
    /*
     * The core P0 guarantee: "we did not ask" and "the adapter said no" must
     * never share a bucket.
     */
    expect_eq(
        cap::summary_bucket(cap::FetchKind::Skipped, SAI_STATUS_NOT_SUPPORTED),
        "skipped_by_tool",
        "tool skip is not an adapter failure");
    expect_eq(
        cap::summary_bucket(cap::FetchKind::Ok, SAI_STATUS_SUCCESS),
        "ok", "ok outcome");
    expect_eq(
        cap::summary_bucket(
            cap::FetchKind::Failure,
            SAI_STATUS_ATTR_NOT_SUPPORTED_0),
        "ATTR_NOT_SUPPORTED",
        "adapter failure is normalized");
    expect_true(
        cap::summary_bucket(
            cap::FetchKind::Skipped, SAI_STATUS_SUCCESS) !=
            cap::summary_bucket(
                cap::FetchKind::Failure, SAI_STATUS_SUCCESS),
        "skip and failure buckets differ");
}

/* ------------------------------------------------------------------ */
/* stats mode selection                                                */
/* ------------------------------------------------------------------ */

void
test_select_stats_mode()
{
    /* READ is always preferred: it does not mutate counters. */
    expect_eq_int(
        static_cast<long>(cap::select_read_only_stats_mode(
            SAI_STATS_MODE_READ | SAI_STATS_MODE_READ_AND_CLEAR,
            true)),
        SAI_STATS_MODE_READ,
        "READ preferred over READ_AND_CLEAR");

    /* Without READ, READ_AND_CLEAR is only used when explicitly allowed. */
    expect_eq_int(
        static_cast<long>(cap::select_read_only_stats_mode(
            SAI_STATS_MODE_READ_AND_CLEAR,
            false)),
        0,
        "no mode selected when clear is disallowed");
    expect_eq_int(
        static_cast<long>(cap::select_read_only_stats_mode(
            SAI_STATS_MODE_READ_AND_CLEAR,
            true)),
        SAI_STATS_MODE_READ_AND_CLEAR,
        "read_and_clear selected only when allowed");

    /* Bulk modes are never selected as a single-object read mode. */
    expect_eq_int(
        static_cast<long>(cap::select_read_only_stats_mode(
            SAI_STATS_MODE_BULK_READ,
            true)),
        0,
        "bulk_read is not a single-object read mode");
    expect_eq_int(
        static_cast<long>(cap::select_read_only_stats_mode(0, true)),
        0,
        "zero declared modes selects nothing");
}

/* ------------------------------------------------------------------ */
/* claim vs probe agreement                                            */
/* ------------------------------------------------------------------ */

void
test_capability_agreement()
{
    expect_eq(
        std::string(cap::agreement_name(
            cap::compare_capability_with_probe(true, true))),
        "AGREE",
        "claimed and readable agree");
    expect_eq(
        std::string(cap::agreement_name(
            cap::compare_capability_with_probe(false, false))),
        "AGREE",
        "not claimed and not readable agree");
    /* The only case that falsifies a vendor claim. */
    expect_eq(
        std::string(cap::agreement_name(
            cap::compare_capability_with_probe(true, false))),
        "CONTRADICTION",
        "claimed but unreadable is a contradiction");
    /* Claimed unsupported but actually works is not a lie about support. */
    expect_eq(
        std::string(cap::agreement_name(
            cap::compare_capability_with_probe(false, true))),
        "UNVERIFIABLE",
        "unclaimed but readable is unverifiable");
}

/* ------------------------------------------------------------------ */
/* attribute claim vs live GET                                         */
/* ------------------------------------------------------------------ */

void
test_attribute_capability_agreement()
{
    /* Claimed gettable and the GET worked. */
    expect_eq(
        std::string(cap::agreement_name(
            cap::compare_attribute_capability_with_probe(
                true, true, false))),
        "AGREE",
        "gettable claim confirmed by GET");
    expect_eq(
        std::string(cap::agreement_name(
            cap::compare_attribute_capability_with_probe(
                false, false, false))),
        "AGREE",
        "non-gettable claim matches failed GET");

    /* Claimed gettable but the GET failed on an unconditional attribute. */
    expect_eq(
        std::string(cap::agreement_name(
            cap::compare_attribute_capability_with_probe(
                true, false, false))),
        "CONTRADICTION",
        "gettable claim falsified by GET");

    /*
     * The critical false-positive guard: a conditionally-valid attribute may
     * legitimately reject a GET when its condition is unmet, so it must not be
     * reported as a contradiction.
     */
    expect_eq(
        std::string(cap::agreement_name(
            cap::compare_attribute_capability_with_probe(
                true, false, true))),
        "UNVERIFIABLE",
        "conditional attribute failure is not a contradiction");
    expect_true(
        cap::compare_attribute_capability_with_probe(true, false, true) !=
            cap::compare_attribute_capability_with_probe(true, false, false),
        "conditional and unconditional failures differ");

    /* Claimed non-gettable but GET worked: not a false claim of support. */
    expect_eq(
        std::string(cap::agreement_name(
            cap::compare_attribute_capability_with_probe(
                false, true, false))),
        "UNVERIFIABLE",
        "non-gettable but readable is unverifiable");
}

} // namespace

int
main()
{
    std::printf("cap_logic unit tests\n");
    std::printf("--------------------\n");

    test_status_classification();
    test_unknown_value_classification();
    test_stats_modes();
    test_api_version();
    test_object_filter();
    test_stat_markers();
    test_value_type_predicates();
    test_summary_bucket();
    test_select_stats_mode();
    test_capability_agreement();
    test_attribute_capability_agreement();

    std::printf("--------------------\n");
    std::printf(
        "%d checks, %d failure(s)\n",
        g_checks,
        g_failures);

    return g_failures == 0 ? 0 : 1;
}
